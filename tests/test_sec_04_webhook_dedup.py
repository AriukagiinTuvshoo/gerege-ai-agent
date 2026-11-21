"""
Stage D — SEC-04: Meta webhook deduplication was per-process.

`main.py` kept `_PROCESSED_MIDS: List[str]`. Production runs `--workers 2` plus a separate
worker process, so a Meta retry that landed on another process was processed **twice** and
the customer received a duplicate reply. The list also dropped its oldest 500 entries once
it passed 2 000, so a delayed retry could be re-processed.

The fix claims a row in `notification_locks` — an atomic INSERT against a primary key,
which is shared by every process and survives a restart.

These tests exercise the real HTTP endpoint and, for the cross-process case, real
subprocesses: an in-process test could not have caught the original bug, because the bug
only appears when the handler runs in a different interpreter.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _webhook_body(mid, page_id="PAGE1", sender="u1", text="hi"):
    return json.dumps(
        {
            "object": "page",
            "entry": [
                {
                    "id": page_id,
                    "messaging": [
                        {
                            "sender": {"id": sender},
                            "recipient": {"id": page_id},
                            "message": {"mid": mid, "text": text},
                        }
                    ],
                }
            ],
        }
    ).encode()


def _sign(body):
    secret = os.getenv("META_APP_SECRET", "")
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _client():
    from fastapi.testclient import TestClient

    import main

    return TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture()
def app_db(tmp_path, monkeypatch):
    """A migrated SQLite database with one registered tenant."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db_path = tmp_path / "webhook.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setattr(database, "DB_PATH", str(db_path))
    database.init_db()
    database.save_page(page_id="PAGE1", name="Tenant One", category="general")
    return db_path


def test_the_in_process_mid_list_is_gone():
    """The process-local list was the defect; it must not come back."""
    import ast

    source = open(os.path.join(REPO_ROOT, "main.py"), encoding="utf-8").read()
    tree = ast.parse(source)
    names = {
        t.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for t in node.targets
        if isinstance(t, ast.Name)
    }
    assert "_PROCESSED_MIDS" not in names


def test_dedup_uses_the_shared_database(app_db):
    """The claim must be visible in `notification_locks`, not in Python memory."""
    body = _webhook_body("MID-SHARED")
    response = _client().post("/webhook", content=body, headers={"X-Hub-Signature-256": _sign(body)})
    assert response.status_code == 200

    conn = sqlite3.connect(app_db)
    try:
        rows = conn.execute(
            "SELECT idempotency_key FROM notification_locks WHERE idempotency_key = ?",
            ("meta_mid:MID-SHARED",),
        ).fetchall()
    finally:
        conn.close()
    assert rows == [("meta_mid:MID-SHARED",)]


def test_duplicate_delivery_is_ignored_in_the_same_process(app_db):
    body = _webhook_body("MID-SAME-PROC")
    client = _client()
    first = client.post("/webhook", content=body, headers={"X-Hub-Signature-256": _sign(body)})
    second = client.post("/webhook", content=body, headers={"X-Hub-Signature-256": _sign(body)})
    assert first.status_code == 200 and second.status_code == 200

    conn = sqlite3.connect(app_db)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM notification_locks WHERE idempotency_key = ?",
            ("meta_mid:MID-SAME-PROC",),
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1, "a duplicate delivery must not create a second lock"


def test_duplicate_delivery_is_ignored_across_processes(app_db):
    """
    The actual production failure: two workers, two interpreters.

    Each subprocess imports the app fresh, so a process-local list cannot dedup between
    them. Only a shared store can, which is the entire point of SEC-04.
    """
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {REPO_ROOT!r})
        import os
        os.environ["DB_PATH"] = {str(app_db)!r}
        os.environ.pop("DATABASE_URL", None)
        os.environ.setdefault("ADMIN_PASSWORD", "Sec04-Test-Pw-2026")
        import database
        from fastapi.testclient import TestClient
        import main
        from tests.test_sec_04_webhook_dedup import _webhook_body, _sign
        body = _webhook_body("MID-CROSS-PROC")
        c = TestClient(main.app, raise_server_exceptions=False)
        r = c.post("/webhook", content=body, headers={{"X-Hub-Signature-256": _sign(body)}})
        print(r.status_code)
        """
    )
    results = []
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            timeout=180,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        results.append(proc.stdout.strip().splitlines()[-1])

    assert results == ["200", "200"], results

    conn = sqlite3.connect(app_db)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM notification_locks WHERE idempotency_key = ?",
            ("meta_mid:MID-CROSS-PROC",),
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1, (
        f"expected exactly one coordinating lock across 2 processes, found {count} — "
        "deduplication is not shared across workers"
    )


def test_unregistered_page_does_not_500_or_create_a_tenant(app_db):
    """
    With foreign keys in place (P1-06), writing a message for a page that does not exist
    would fail the whole webhook. It must be dropped, not 500, and must not implicitly
    create the tenant — an unverified sender must not be able to conjure a page row.
    """
    body = _webhook_body("MID-UNKNOWN-PAGE", page_id="GHOSTPAGE")
    response = _client().post("/webhook", content=body, headers={"X-Hub-Signature-256": _sign(body)})
    assert response.status_code == 200

    conn = sqlite3.connect(app_db)
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM pages WHERE page_id='GHOSTPAGE'"
        ).fetchone()[0] == 0, "an unregistered page must not be created implicitly"
    finally:
        conn.close()


def test_expired_lock_allows_replay(app_db):
    """A lock older than its TTL must not block a legitimate later delivery forever."""
    conn = sqlite3.connect(app_db)
    try:
        conn.execute(
            "INSERT INTO notification_locks (idempotency_key, channel, expires_at)"
            " VALUES ('meta_mid:OLD', 'meta_webhook', '2020-01-01 00:00:00')"
        )
        conn.commit()
    finally:
        conn.close()
    assert database.claim_notification_lock("meta_mid:OLD", ttl_seconds=60) is True, (
        "an expired lock must be reclaimable"
    )
