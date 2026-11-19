"""
Shared pytest configuration.

Rate-limit isolation (SEC-07)
-----------------------------
`core.rate_limit` counts per client identity in a **shared** store when `REDIS_URL` is
set. Under pytest every request originates from the same address (`testclient`), so
without a reset the first suite to log in a few times exhausts the `auth_login` budget and
*every later test that logs in* receives a 429 instead of a session.

That is a real property of a shared limiter, not a bug, and the fix belongs in the test
setup rather than in the limiter: each test starts with an empty counter, exactly as a
freshly deployed instance would.
"""
import os
import sys

import pytest

# conftest is imported before any test module, so it cannot rely on a test module having
# put the repository root on `sys.path`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import rate_limit  # noqa: E402


#: Test-only secret for the E-02 Phase 4 account-throttle keys.
#:
#: Account-level throttling is disabled when `E02_ACCOUNT_KEY_SECRET` is unset (there is no
#: unkeyed fallback by design — see `core/account_keys`). Tests that exercise login must
#: therefore run with it set, exactly as a deployed instance would. This value is obviously
#: not a secret; production supplies its own through the environment.
TEST_ACCOUNT_KEY_SECRET = "e02-test-only-account-key-secret-not-for-production"


@pytest.fixture()
def _no_e02_secret_fixture():
    """
    Opt out of the automatic account-key secret for one test.

    Tests that assert on secret *absence* (production refusing to start, no unkeyed fallback)
    must control the variable themselves; without this the autouse fixture below would set it
    and the assertion would be untestable.
    """
    return None


@pytest.fixture(autouse=True)
def _e02_account_key_secret(monkeypatch, request):
    """
    Configure the account-key secret for every test.

    `autouse` so no login test silently runs against a disabled account throttle and then
    asserts something weaker than it thinks. A test that specifically needs the secret
    *absent* (to prove fail-closed behaviour) overrides this with
    `monkeypatch.delenv(..., raising=False)` plus `rate_limit.refresh_account_key_secret()`.
    """
    if "_no_e02_secret_fixture" in request.fixturenames:
        yield
        return
    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_ACCOUNT_KEY_SECRET)
    rate_limit.refresh_account_key_secret()
    yield


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Give every test a clean rate-limit window."""
    try:
        rate_limit.get_limiter().reset()
    except Exception:
        # A limiter outage must never fail the suite; the limiter itself fails open.
        pass
    yield
    try:
        rate_limit.get_limiter().reset()
    except Exception:
        pass


# ===========================================================================
# Audit-trail append-only guard: the ONLY sanctioned test reset
# ===========================================================================
# Phase 13 (finding F-D) made `audit_logs` append-only at the database level. Several
# suites legitimately clear that table between cases to make audit counts attributable
# to the test that produced them, and those fixtures now hit the guard — correctly.
#
# The alternative to this helper would be to weaken the assertions, or to skip the
# guard in production, and both are worse. So the bypass lives *here*, in test
# infrastructure, and nowhere else:
#
#   * it is not imported by any application module, and no production code path can
#     reach it — `tests/test_e02_phase13_audit_append_only.py` asserts that by
#     scanning the tree for callers outside `tests/`;
#   * restoration runs in a `finally` and is *verified*: if the guard is not correctly
#     back in place afterwards, the helper raises rather than leaving an unprotected
#     table for the next test.
#
# Prefer a fresh database per test where practical; use this only where a suite needs
# to clear history inside an existing one.
def clear_audit_logs_for_test(conn=None):
    """Delete every audit row with the guard temporarily lifted, then restore it.

    Test infrastructure only. Do not call from application code.
    """
    from core import audit_integrity
    import database as _database

    own = conn is None
    if own:
        conn = _database.get_connection()
    try:
        with audit_integrity.temporarily_unguarded(conn):
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM audit_logs")
            finally:
                try:
                    cursor.close()
                except Exception:
                    pass
            conn.commit()
    finally:
        if own:
            conn.close()


# ---------------------------------------------------------------------------
# Backup encryption test configuration (Phase 20)
# ---------------------------------------------------------------------------
#: Test-only AES-256 key. Obviously not a secret; production supplies its own through
#: ``BACKUP_ENCRYPTION_KEY_FILE``.
#:
#: Phase 20 makes ``create_backup()`` enforce ``BACKUP_ENCRYPTION`` internally instead of
#: leaving the policy to whichever CLI happened to call it. That is the fix for the Phase
#: 19 plaintext-publication finding, and it means a test that creates a backup without a
#: key now fails closed — which is the correct product behaviour.
#:
#: The suite therefore runs the way a deployed instance runs: encryption on, with a real
#: key. This *strengthens* the backup tests. Before, they exercised the plaintext path
#: that production never uses and did not touch the AEAD container at all. A test that
#: needs to prove fail-closed behaviour deletes the variable itself with
#: ``monkeypatch.delenv``/``setenv``.
TEST_BACKUP_KEY = os.urandom(32)


@pytest.fixture(autouse=True)
def _backup_encryption_key(tmp_path_factory, monkeypatch):
    """Give every test a real encryption key and a private backup directory."""
    key_file = tmp_path_factory.getbasetemp() / "pytest-backup.key"
    if not key_file.exists():
        key_file.write_bytes(TEST_BACKUP_KEY)
        key_file.chmod(0o600)
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(key_file))
    monkeypatch.delenv("BACKUP_ENCRYPTION", raising=False)
