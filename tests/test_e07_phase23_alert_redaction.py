"""Phase 23 - pin what the alerting path actually guarantees about secrets.

Phase 22's alerting work established that the payload is an allowlist (event, label,
filename, encrypted, offsite, exit_code, error, warnings, finished_at) rather than a dump of
the result dict, and that `notify()` never raises. That is the real protection, and it is
worth a test - but the claim must be stated for what it is.

What is NOT claimed: that the `error` string is scrubbed. There is no redactor. The checks
below establish which risk this actually is, so nobody later "fixes" a non-issue or assumes
protection that does not exist.
"""

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def _payload_keys() -> set:
    """The exact allowlist `_finish()` builds, read from the source."""
    source = (REPO_ROOT / "core" / "backup_automation.py").read_text(encoding="utf-8")
    start = source.index("payload = {")
    end = source.index("}", start)
    block = source[start:end]
    keys = set()
    for line in block.split("\n"):
        line = line.strip()
        if line.startswith('"') and '":' in line:
            keys.add(line.split('"')[1])
    return keys


def test_alert_payload_is_an_allowlist_not_a_result_dump():
    """A result dict carries the DSN and key path; the payload must not."""
    keys = _payload_keys()
    assert keys == {
        "event", "label", "filename", "encrypted", "offsite",
        "exit_code", "error", "warnings", "finished_at",
    }, f"the allowlist changed: {sorted(keys)}"


def test_payload_cannot_carry_a_dsn_or_key_path():
    """None of the allowlisted fields is a place a connection string lives."""
    forbidden = {"database_url", "dsn", "url", "key_file", "backup_encryption_key_file", "password"}
    assert not (forbidden & _payload_keys())


def test_libpq_and_sqlalchemy_redact_credentials_in_connection_errors():
    """The `error` field is unscrubbed, so the risk depends on drivers not echoing DSNs.

    Verified for the two drivers this project uses: a failed connection reports host and
    port, never the password. If a future driver regresses, this test says so.
    """
    from sqlalchemy import create_engine

    marker = "LEAKPW999"
    for url in (
        f"postgresql+psycopg2://u:{marker}@127.0.0.1:59999/nope",
        f"postgresql+psycopg2://u:{marker}@nonexistent.invalid/db",
    ):
        try:
            engine = create_engine(url, connect_args={"connect_timeout": 3})
            with engine.connect():
                pass
            raise AssertionError("expected the connection to fail")
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001 - any driver error is the point
            message = f"{type(exc).__name__}: {exc}"
            assert marker not in message, (
                "the driver echoed the password into the error string, which the alert "
                f"payload forwards verbatim: {message[:120]}"
            )


def test_notify_is_fail_safe_and_bounded():
    """An unreachable webhook must return, not raise, and must not hang."""
    from core import backup_automation

    ok, detail = backup_automation.notify(
        "http://127.0.0.1:59998/unreachable", {"event": "backup.failure"}
    )
    assert ok is False
    assert "notification failed" in detail


def test_no_destination_is_configured_in_this_repository():
    """Nothing here should point alerting at a real place."""
    import os

    assert not os.getenv("BACKUP_ALERT_WEBHOOK"), (
        "this environment has a real alert destination configured; the audit must not "
        "send notifications"
    )
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "BACKUP_ALERT_WEBHOOK:" not in ci, "CI must not configure a real alert destination"
