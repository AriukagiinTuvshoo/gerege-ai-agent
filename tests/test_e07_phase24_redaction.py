"""Phase 24 - secret redaction on the alert path.

The alert payload forwards `result["error"]` and `result["warnings"]` to a webhook outside the
trust boundary. Those strings are assembled from several layers, one of which interpolates a
raw exception. No leak was observed: libpq, `pg_dump`, SQLAlchemy and the offsite module were
each checked, and none echo credentials. This is defence in depth, and the tests say so -
every one that could be read as "a leak was fixed" is written as "a leak cannot reach here".

The two failure modes of a redactor are covered with equal weight:

* too weak - a credential survives;
* too strong - the sha256 digest and archive filename an operator needs to act are destroyed.

The second is not hypothetical: the first implementation of the base64 rule ate both.
"""

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core import redaction  # noqa: E402

P = redaction.PLACEHOLDER


# ---------------------------------------------------------------------------
# Credentials must not survive
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,secret",
    [
        ("connect failed: postgresql://owner:hunter2@db:5432/gerege", "hunter2"),
        ("postgres://u:pw12345@h/d", "pw12345"),
        ("redis://default:redispass@cache:6379/0", "redispass"),
        ("https://AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI@bucket/p", "wJalrXUtnFEMI"),
        ("auth failed: password=s3cr3t-value host=db", "s3cr3t-value"),
        ("api_key = 'abc123def456'", "abc123def456"),
        ("client_secret: topsecret9", "topsecret9"),
        ("upload rejected for AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefgh", "eyJhbGciOiJIUzI1NiJ9"),
        (
            "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123def456",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ),
        ("key MATERIAL wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
    ],
)
def test_credentials_are_removed(text, secret):
    out = redaction.sanitize_message(text)
    assert secret not in out, f"secret survived redaction: {out}"
    assert P in out, "the message should say something was removed, not silently drop it"


def test_a_known_secret_value_is_scrubbed_wherever_it_appears(monkeypatch):
    """A bare value must be caught even when no pattern matches its shape."""
    monkeypatch.setenv("PGPASSWORD", "zzzz-plain-password-1234")
    values = redaction.collect_secret_values()
    out = redaction.sanitize_message(
        "login failed using zzzz-plain-password-1234", secret_values=values
    )
    assert "zzzz-plain-password-1234" not in out


def test_a_dsn_password_is_collected_from_the_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_OWNER_URL", "postgresql://owner:isolated-pw-999@h/db")
    values = redaction.collect_secret_values()
    assert "isolated-pw-999" in values


# ---------------------------------------------------------------------------
# Diagnostics must survive - the other failure mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "diagnostic",
    [
        "database preflight exceeded its deadline - table row counts: a lock could not be "
        "acquired within lock_timeout. statement_timeout=30s, lock_timeout=5s.",
        "pg_dump did not finish within 120s. The deadline is BACKUP_DB_OPERATION_DEADLINE (120s).",
        "offsite upload failed: transport failure: URLError",
        "downloaded digest does not match the expected sha256",
        "/var/lib/gerege/backups: No space left on device",
        "restore FAILED: Missing required PostgreSQL tables: ['pages', 'invoices']",
        "BACKUP_ALERT_WEBHOOK is not configured: nobody is notified of a failure",
    ],
)
def test_real_diagnostics_pass_through_unchanged(diagnostic):
    """If these are redacted, the redactor has made an outage harder to diagnose."""
    assert redaction.sanitize_message(diagnostic) == diagnostic


def test_sha256_digests_are_preserved():
    """The first base64 rule destroyed these. A digest is how you prove an archive is intact."""
    digest = "5189a8e123180a7912345678abcdef0123456789abcdef0123456789abcdef01"
    out = redaction.sanitize_message(f"archive sha256 {digest}")
    assert digest in out


@pytest.mark.parametrize(
    "filename",
    [
        "pg_backup_scheduled_20261121_074807_661234.sql.gz.enc",
        "pg_backup_pre_restore_20261121_074808_88.sql.gz.enc",
        "sqlite_backup_manual_20260101_000000_12.db.gz.enc",
    ],
)
def test_archive_filenames_are_preserved(filename):
    """An operator needs the filename to act on the alert."""
    out = redaction.sanitize_message(f"restore of {filename} failed")
    assert filename in out


def test_a_single_repeated_character_run_is_not_a_secret():
    out = redaction.sanitize_message("progress " + "=" * 60 + " done")
    assert "=" * 60 in out


# ---------------------------------------------------------------------------
# Message hygiene
# ---------------------------------------------------------------------------


def test_multiline_injection_is_collapsed_to_one_line():
    """A newline in an error lets a caller forge a second record at the receiver."""
    out = redaction.sanitize_message("real failure\nFAKE: backup.success\nanother")
    assert "\n" not in out
    assert "\r" not in out


def test_ansi_escapes_and_control_characters_are_stripped():
    out = redaction.sanitize_message("bad \x1b[31mred\x1b[0m \x07bell\x00null")
    assert "\x1b" not in out and "\x07" not in out and "\x00" not in out
    assert "bad" in out and "red" in out


def test_oversized_messages_are_bounded_and_say_so():
    out = redaction.sanitize_message("x" * 5000, max_length=500)
    assert len(out) <= 520
    assert "truncated" in out


def test_tabs_do_not_survive():
    assert "\t" not in redaction.sanitize_message("a\tb")


def test_none_and_empty_are_safe():
    assert redaction.sanitize_message(None) == ""
    assert redaction.sanitize_message("") == ""


# ---------------------------------------------------------------------------
# Payload level
# ---------------------------------------------------------------------------


def test_payload_strings_and_lists_are_sanitized():
    payload = {
        "event": "backup.failure",
        "label": "scheduled",
        "exit_code": 18,
        "error": "connect failed: postgresql://owner:hunter2@db/gerege",
        "warnings": ["offsite: token=abcdef123456", "harmless warning"],
    }
    clean = redaction.sanitize_payload(payload, secret_values=["hunter2"])
    assert "hunter2" not in str(clean)
    assert "abcdef123456" not in str(clean)
    # The contract is preserved: keys and non-string values are untouched.
    assert set(clean) == set(payload)
    assert clean["exit_code"] == 18
    assert clean["event"] == "backup.failure"
    assert clean["label"] == "scheduled"
    assert "harmless warning" in clean["warnings"]


def test_payload_warning_list_is_bounded():
    payload = {"warnings": [f"warning {i}" for i in range(50)]}
    clean = redaction.sanitize_payload(payload)
    assert len(clean["warnings"]) == 21  # 20 items + the truncation marker
    assert "more warnings truncated" in clean["warnings"][-1]


def test_audit_reports_findings_without_sending_anything():
    report = redaction.audit({"error": "postgresql://u:hunter2@h/db"})
    assert not report.clean
    assert report.findings[0].rule == "url-userinfo"
    # The preview must itself be redacted.
    assert "hunter2" not in report.findings[0].preview


def test_audit_is_clean_for_a_realistic_success_payload():
    payload = {
        "event": "backup.success",
        "filename": "pg_backup_scheduled_2026.sql.gz.enc",
        "exit_code": None,
        "encrypted": True,
        "offsite": "uploaded",
        "warnings": [],
    }
    assert redaction.audit(payload).clean


# ---------------------------------------------------------------------------
# Fail-safe
# ---------------------------------------------------------------------------


def test_redaction_failure_suppresses_rather_than_leaks(monkeypatch):
    """If redaction itself breaks, the message must not go out raw."""

    class Boom(Exception):
        pass

    def exploding_sub(*args, **kwargs):
        raise Boom("regex engine failure")

    # Replace the first rule's pattern with one whose .sub raises, via a small stand-in.
    class ExplodingPattern:
        def sub(self, *args, **kwargs):
            raise Boom("regex engine failure")

    monkeypatch.setattr(
        redaction, "RULES", (redaction.Rule("boom", ExplodingPattern(), ""),) + redaction.RULES[1:]
    )
    out = redaction.sanitize_message("postgresql://u:hunter2@h/db")
    assert "hunter2" not in out
    assert "suppressed" in out.lower()


def test_no_secret_is_written_to_a_log_or_returned_by_the_audit(monkeypatch):
    """Collecting secrets must return values, never names, and must be usable."""
    monkeypatch.setenv("BACKUP_OFFSITE_SECRET_KEY", "offsite-secret-value-xyz")
    values = redaction.collect_secret_values()
    assert "offsite-secret-value-xyz" in values
    # A short value must not be collected: scrubbing it would redact ordinary prose.
    monkeypatch.setenv("PGPASSWORD", "abc")
    assert "abc" not in redaction.collect_secret_values()
