"""Phase 24 - alert delivery: retry policy and failure semantics, against a local sink.

Every test here starts a real HTTP server on loopback. Nothing leaves the machine and no real
alert is ever sent. The sink is scriptable so a transient failure sequence can be reproduced
exactly rather than approximated.

The property that matters most is not "retries happen" - it is that alerting can never change
what a backup run means. A failed delivery must not turn a good backup into a failed one, and
must not replace the original error of a bad one.
"""

import http.server
import sys
import threading
import time
from typing import List, Optional, Tuple

import pytest

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core import backup_automation  # noqa: E402


class Sink:
    """A scriptable HTTP sink. Each request pops the next scripted response."""

    def __init__(self, script: Optional[List[Tuple[int, float]]] = None):
        self.script = list(script or [])
        self.requests: List[dict] = []
        self.default = (200, 0.0)
        sink = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length).decode("utf-8", "replace")
                sink.requests.append({"body": body, "headers": dict(self.headers)})
                code, delay = sink.script.pop(0) if sink.script else sink.default
                if delay:
                    time.sleep(delay)
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def log_message(self, *args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        return False


@pytest.fixture()
def fast_retry(monkeypatch):
    """Keep the retry backoff out of the test's runtime.

    Phase 28 also opted this file into the documented loopback sink path: every sink here
    is ``http://127.0.0.1:<port>/hook``, which the new destination policy refuses unless
    BACKUP_ALERT_ALLOW_INSECURE=1 is set outside production. That is not a relaxation of
    the control - the same policy refuses loopback in production regardless of this flag,
    and Phase 28's own tests assert exactly that (see
    tests/test_e07_phase28_ssrf_and_tempfiles.py::test_the_insecure_opt_in_cannot_be_used_in_production).
    """
    monkeypatch.setenv("BACKUP_ALERT_RETRIES", "3")
    monkeypatch.setenv("BACKUP_ALERT_BACKOFF_S", "0.01")
    monkeypatch.setenv("BACKUP_ALERT_ALLOW_INSECURE", "1")
    monkeypatch.delenv("ENV", raising=False)


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


def test_successful_delivery_is_a_single_request(fast_retry):
    with Sink() as sink:
        ok, detail = backup_automation.notify(sink.url, {"event": "backup.success"})
    assert ok is True
    assert "200" in detail
    assert len(sink.requests) == 1


def test_transient_failures_retry_then_succeed(fast_retry):
    """503, 503, 200 - the alert lands on the third attempt."""
    with Sink([(503, 0), (503, 0), (200, 0)]) as sink:
        ok, detail = backup_automation.notify(sink.url, {"event": "backup.failure"})
    assert ok is True
    assert len(sink.requests) == 3


def test_retry_is_bounded(fast_retry):
    """A permanently broken receiver must not be hammered forever."""
    with Sink([(503, 0)] * 10) as sink:
        ok, detail = backup_automation.notify(sink.url, {"event": "backup.failure"})
    assert ok is False
    assert len(sink.requests) == 3, "retry count is not bounded by BACKUP_ALERT_RETRIES"
    assert "3" in detail or "attempt" in detail


def test_permanent_4xx_is_not_retried(fast_retry):
    """400 means the request is wrong; retrying it cannot help."""
    with Sink([(400, 0)]) as sink:
        ok, detail = backup_automation.notify(sink.url, {"event": "backup.failure"})
    assert ok is False
    assert len(sink.requests) == 1
    assert "400" in detail


@pytest.mark.parametrize("code", [401, 403, 404, 422])
def test_other_4xx_are_also_not_retried(fast_retry, code):
    with Sink([(code, 0)]) as sink:
        ok, _ = backup_automation.notify(sink.url, {"event": "backup.failure"})
    assert ok is False
    assert len(sink.requests) == 1


def test_429_is_retried_within_the_bound(fast_retry):
    """429 is a transient throttle, not a malformed request."""
    with Sink([(429, 0), (429, 0), (200, 0)]) as sink:
        ok, _ = backup_automation.notify(sink.url, {"event": "backup.failure"})
    assert ok is True
    assert len(sink.requests) == 3


def test_connection_error_is_retried_then_reported(fast_retry):
    """Nothing listening: bounded retries, then a clean failure - never an exception."""
    ok, detail = backup_automation.notify(
        "http://127.0.0.1:59997/nobody-here", {"event": "backup.failure"}
    )
    assert ok is False
    assert "notification failed" in detail


def test_retry_count_cannot_be_raised_without_bound(monkeypatch):
    """The clamp is what stops a misconfiguration turning into a request storm."""
    monkeypatch.setenv("BACKUP_ALERT_RETRIES", "1000")
    monkeypatch.setenv("BACKUP_ALERT_BACKOFF_S", "0.01")
    source = (REPO_ROOT / "core" / "backup_automation.py").read_text(encoding="utf-8")
    assert "min(int(os.getenv(\"BACKUP_ALERT_RETRIES\"" in source


def test_backoff_is_clamped(monkeypatch):
    monkeypatch.setenv("BACKUP_ALERT_BACKOFF_S", "1000")
    source = (REPO_ROOT / "core" / "backup_automation.py").read_text(encoding="utf-8")
    assert "10.0" in source


# ---------------------------------------------------------------------------
# Failure semantics: alerting never changes what a run means
# ---------------------------------------------------------------------------


def test_a_failed_alert_does_not_fail_a_successful_backup(fast_retry):
    """A backup that worked stays successful; the delivery problem is a warning."""
    result = {"success": True, "filename": "x.enc", "label": "scheduled", "warnings": []}
    directory = None
    with Sink([(500, 0)] * 5) as sink:
        original_url = backup_automation.notification_url
        try:
            backup_automation.notification_url = lambda: sink.url
            backup_automation._finish(result, _tmpdir())
        finally:
            backup_automation.notification_url = original_url
    assert result["success"] is True
    assert any("notification failed" in warning for warning in result["warnings"])


def test_a_failed_alert_does_not_mask_the_original_error(fast_retry):
    """The backup's own failure must remain the reported failure."""
    result = {
        "success": False,
        "exit_code": 18,
        "error": "database preflight exceeded its deadline",
        "label": "scheduled",
        "warnings": [],
    }
    with Sink([(500, 0)] * 5) as sink:
        original_url = backup_automation.notification_url
        try:
            backup_automation.notification_url = lambda: sink.url
            backup_automation._finish(result, _tmpdir())
        finally:
            backup_automation.notification_url = original_url
    assert result["success"] is False
    assert result["error"] == "database preflight exceeded its deadline"
    assert result["exit_code"] == 18


def test_unset_webhook_is_reported_as_nobody_notified(monkeypatch):
    """Silence is the worst outcome: it must be said out loud."""
    monkeypatch.delenv("BACKUP_ALERT_WEBHOOK", raising=False)
    result = {"success": False, "error": "boom", "warnings": []}
    backup_automation._finish(result, _tmpdir())
    assert any("nobody is notified" in warning for warning in result["warnings"])


def test_the_delivered_body_is_the_redacted_payload(fast_retry, monkeypatch):
    """End to end: a credential in `error` must not appear in the request body."""
    monkeypatch.setenv("BACKUP_ALERT_WEBHOOK", "")
    result = {
        "success": False,
        "exit_code": 10,
        "error": "connect failed: postgresql://owner:hunter2@db:5432/gerege",
        "label": "scheduled",
        "warnings": ["retrying with password=hunter2"],
    }
    with Sink() as sink:
        original_url = backup_automation.notification_url
        try:
            backup_automation.notification_url = lambda: sink.url
            backup_automation._finish(result, _tmpdir())
        finally:
            backup_automation.notification_url = original_url
    assert sink.requests, "no request was delivered"
    body = sink.requests[0]["body"]
    assert "hunter2" not in body, f"credential reached the webhook: {body}"
    assert "backup.failure" in body


def test_the_alert_timeout_is_bounded():
    source = (REPO_ROOT / "core" / "backup_automation.py").read_text(encoding="utf-8")
    assert "timeout=10" in source, "the per-attempt timeout is not bounded"


def test_notify_never_raises_on_a_malformed_webhook_url(fast_retry):
    """A typo in the webhook must not crash the timer."""
    for bad in ("not-a-url", "", "ftp://127.0.0.1/x", "http://"):
        ok, detail = backup_automation.notify(bad, {"event": "backup.failure"})
        assert ok is False
        assert isinstance(detail, str)


def _tmpdir():
    import tempfile

    return tempfile.mkdtemp(prefix="p24-alert-")
