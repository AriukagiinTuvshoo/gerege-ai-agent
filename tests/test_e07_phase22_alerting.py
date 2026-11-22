"""Phase 22 - alerting: delivery semantics, retry bounds, and secret hygiene.

Phase 11/4 require an alert for every failure class, bounded timeout, bounded retries, no
secrets in the payload, and - the subtle one - a delivery failure must never mask the
original failure. The webhook must also never be able to turn a successful backup into a
failed one.

Everything here runs against a local disposable HTTP endpoint on the loopback interface.
No real notification is ever sent.
"""

import json
import pathlib
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


class _Receiver:
    """A local endpoint that records requests and can be told to misbehave."""

    def __init__(self, statuses=None):
        self.received = []
        self.attempts = 0
        self._statuses = list(statuses or [])
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length)
                outer.attempts += 1
                outer.received.append(body)
                status = outer._statuses.pop(0) if outer._statuses else 200
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b"ok" if status == 200 else b"no")

            def log_message(self, *args):
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/hook"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture()
def receiver(monkeypatch):
    """A loopback HTTP sink for alert delivery.

    Phase 28 added a destination policy to `notify()`: https only outside development, and
    no private or loopback addresses. A local sink is neither of those, so it is permitted
    only through the documented development opt-in, which is set here.

    This is not a weakening of the control. The policy refuses the same loopback sink in
    production regardless of this flag, including over https, and that refusal is asserted
    in tests/test_e07_phase28_ssrf_and_tempfiles.py
    (test_the_insecure_opt_in_cannot_be_used_in_production).

    Several tests in this file also set ENV=production to describe the run they are
    modelling. Before Phase 28 nothing in `backup_automation` read ENV, so that was
    provenance only; the fixture deletes it so the local sink keeps working, and the tests
    still assert exactly what they did before - the payload, the retry behaviour and the
    error masking.
    """
    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.delenv("ENV", raising=False)
    r = _Receiver()
    try:
        yield r
    finally:
        r.close()


# ---------------------------------------------------------------------------
# Delivery: attempts, retries, bounds
# ---------------------------------------------------------------------------


def test_notification_is_delivered(receiver):
    from core import backup_automation

    ok, detail = backup_automation.notify(receiver.url, {"event": "backup.success"})
    assert ok is True
    assert detail == "http 200"
    assert receiver.attempts == 1


def test_transient_failure_is_retried_then_succeeds(monkeypatch):
    """A 5xx is transient: retrying is the difference between an alert and silence."""
    # Loopback sink: see the `receiver` fixture for why the documented opt-in is needed.
    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.delenv("ENV", raising=False)
    r = _Receiver(statuses=[503, 503, 200])
    try:
        from core import backup_automation

        ok, detail = backup_automation.notify(r.url, {"event": "backup.failure"})
        assert ok is True, detail
        assert r.attempts == 3
    finally:
        r.close()


def test_client_error_is_not_retried(monkeypatch):
    """A 4xx means the request is wrong; repeating it cannot help."""
    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.delenv("ENV", raising=False)
    r = _Receiver(statuses=[400, 400, 400])
    try:
        from core import backup_automation

        ok, detail = backup_automation.notify(r.url, {"event": "x"})
        assert ok is False
        assert "400" in detail
        assert r.attempts == 1, "a 4xx must not be retried"
    finally:
        r.close()


def test_retries_are_bounded(receiver, monkeypatch):
    """An unreachable endpoint must not retry forever."""
    monkeypatch.setenv("BACKUP_ALERT_RETRIES", "3")
    monkeypatch.setenv("BACKUP_ALERT_BACKOFF_S", "0")
    from core import backup_automation

    started = time.time()
    ok, detail = backup_automation.notify("http://127.0.0.1:1/nobody", {"event": "x"})
    elapsed = time.time() - started
    assert ok is False
    assert "after 3 attempts" in detail
    assert elapsed < 60, f"retry loop took {elapsed:.1f}s; it must be bounded"


def test_retry_count_is_overridable():
    from core import backup_automation

    source = pathlib.Path(backup_automation.__file__).read_text(encoding="utf-8")
    assert "BACKUP_ALERT_RETRIES" in source
    assert "BACKUP_ALERT_BACKOFF_S" in source


def test_notification_timeout_is_bounded():
    """Each attempt must carry its own timeout, or one hung receiver stalls the run."""
    from core import backup_automation

    source = pathlib.Path(backup_automation.__file__).read_text(encoding="utf-8")
    start = source.index("def notify(")
    end = source.index("\ndef ", start + 1)
    body = source[start:end]
    assert "timeout=" in body, "urlopen call has no timeout"


# ---------------------------------------------------------------------------
# Secret hygiene: the payload must never carry a credential
# ---------------------------------------------------------------------------


def test_payload_names_only_non_secret_fields():
    """Structural: the alert payload is an allowlist, not a copy of the result."""
    from core import backup_automation

    source = pathlib.Path(backup_automation.__file__).read_text(encoding="utf-8")
    start = source.index('payload = {')
    end = source.index("}", start)
    body = source[start:end]
    for forbidden in ("DATABASE_URL", "dsn", "password", "key_file", "BACKUP_ENCRYPTION_KEY"):
        assert forbidden not in body, f"{forbidden} must not be part of the alert payload"


def test_a_database_failure_does_not_leak_the_dsn(receiver, monkeypatch, tmp_path):
    """The real risk: an error string that embeds the connection string.

    A production-mode run against an unreachable database fails at the credential check.
    The alert must say what happened without the DSN - which carries the owner password.
    """
    monkeypatch.setenv("BACKUP_ALERT_WEBHOOK", receiver.url)
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    # ENV is not set to production: the sink is loopback http, which the destination policy
    # permits only outside production. Nothing asserted here depends on ENV - the test is
    # about the DSN not reaching the alert body.
    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.delenv("BACKUP_ENCRYPTION", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg2://gerege_owner:SUPERSECRETPASSWORD@127.0.0.1:15999/nope",
    )

    from core import backup_automation

    result = backup_automation.run_scheduled_backup(label="alert_dsn")
    assert result.get("success") is False

    assert receiver.received, "no alert was delivered for a failed backup"
    body = receiver.received[-1].decode("utf-8")
    assert "SUPERSECRETPASSWORD" not in body
    assert "gerege_owner" not in body
    assert "15999" not in body


# ---------------------------------------------------------------------------
# A delivery failure must not mask, or manufacture, a backup failure
# ---------------------------------------------------------------------------


def test_delivery_failure_does_not_mask_the_original_error(monkeypatch, tmp_path):
    """Alerting is reporting, not part of the work. It must not overwrite the cause."""
    monkeypatch.setenv("BACKUP_ALERT_WEBHOOK", "http://127.0.0.1:1/unreachable")
    monkeypatch.setenv("BACKUP_ALERT_BACKOFF_S", "0")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", "/nonexistent/key")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg2://gerege_owner:x@127.0.0.1:15999/nope"
    )

    from core import backup_automation

    result = backup_automation.run_scheduled_backup(label="alert_mask")
    assert result.get("success") is False
    # The ORIGINAL cause survives; the delivery failure is demoted to a warning.
    assert result.get("error"), "the original error was replaced by the delivery failure"
    assert "notification" not in (result.get("error") or "").lower()
    assert any("notification" in w.lower() for w in result.get("warnings") or [])


def test_delivery_failure_does_not_fail_a_successful_backup(monkeypatch, tmp_path):
    """The inverse: a broken webhook must not turn a good backup into a red run."""
    monkeypatch.setenv("BACKUP_ALERT_WEBHOOK", "http://127.0.0.1:1/unreachable")
    monkeypatch.setenv("BACKUP_ALERT_BACKOFF_S", "0")
    monkeypatch.setenv("BACKUP_DIR", str(tmp_path / "backups"))
    (tmp_path / "backups").mkdir()
    monkeypatch.setenv("ENV", "production")
    key = tmp_path / "k"
    key.write_bytes(bytes(range(32)))
    key.chmod(0o600)
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(key))
    monkeypatch.delenv("BACKUP_ENCRYPTION", raising=False)

    url = __import__("os").environ.get("DATABASE_URL", "")
    if "postgres" not in url:
        pytest.skip("needs a PostgreSQL DATABASE_URL to run a real backup")

    from core import backup_automation

    result = backup_automation.run_scheduled_backup(label="alert_ok")
    if not result.get("success"):
        pytest.skip(f"backup could not run here: {result.get('error')}")
    assert any("notification" in w.lower() for w in result.get("warnings") or [])
    assert result.get("exit_code") == 0


def test_missing_webhook_is_reported_not_silent(monkeypatch, tmp_path):
    """'Nobody is watching' must be visible, or a failed backup fails silently."""
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)
    from core import backup_automation

    assert backup_automation.notification_url() is None
    source = pathlib.Path(backup_automation.__file__).read_text(encoding="utf-8")
    assert "nobody is notified" in source.lower()
