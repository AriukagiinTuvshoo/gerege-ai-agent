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
# Copying a live SQLite database (Phase 22, CI step 17 root cause)
# ---------------------------------------------------------------------------
# `shutil.copy2(database.DB_PATH, dest)` is **not** a faithful copy of a live database.
# The application opens SQLite in WAL mode, so committed data can still live in the
# `-wal` sidecar; copying only the main file yields a database that may be missing entire
# tables. That is not a rare race - it depends on when SQLite last checkpointed, which
# differs between machines.
#
# Reproduced: a WAL-mode database with an open connection, one committed `CREATE TABLE`
# plus rows, copied with `shutil.copy2`, produced a copy with **no tables at all**, and the
# caller's next statement failed with `sqlite3.OperationalError: no such table: pages`.
# That is exactly how CI step 17 failed while passing locally 151/151: the same test
# copies `database.DB_PATH`, and CI's checkpoint timing left the schema in the WAL.
#
# `sqlite3.Connection.backup()` is the API for this: it reads through the WAL. The product
# already uses it in `scripts/migrate_sqlite_to_postgres.create_sqlite_snapshot`; these
# helpers give tests the same guarantee instead of relying on checkpoint luck.
def copy_sqlite_database(source_path: str, dest_path: str) -> str:
    """Copy a live SQLite database consistently, including anything still in the WAL.

    Returns ``dest_path``. Raises if the source does not exist, so a caller never gets a
    silently empty database.
    """
    import sqlite3

    if not os.path.exists(source_path):
        raise FileNotFoundError(f"SQLite database not found: {source_path}")
    src = sqlite3.connect(source_path)
    dst = sqlite3.connect(dest_path)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    return dest_path


@pytest.fixture()
def sqlite_db_copy(tmp_path):
    """Factory returning consistent copies of the live database.

    Usage: ``copy = sqlite_db_copy("src.db")``. Prefer this over `shutil.copy2` in any test
    that reads the database through a second connection.
    """
    import database as _database

    def _make(name: str) -> str:
        return copy_sqlite_database(_database.DB_PATH, str(tmp_path / name))

    return _make


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


#: Phase 45 (F-44-F): the secrets a production startup requires.
#:
#: `core.secret_guard` refuses to start a production process whose required secrets are
#: missing, default or too short. Suites that set `ENV=production` in order to exercise the
#: real startup path therefore need a valid set, exactly as a real deployment does - without
#: them they fail on the secret sweep instead of on the behaviour they are testing.
#:
#: The values are generated per run and are obviously not secrets. A test that needs to prove
#: the *refusal* behaviour deletes or blanks one itself with `monkeypatch.delenv`/`setenv`;
#: `test_e45_final_hardening.py` does exactly that.
_TEST_SECRET = os.urandom(24).hex()


@pytest.fixture(autouse=True)
def _production_secrets_present(monkeypatch):
    """Supply valid production secrets for the whole suite.

    Autouse and non-destructive: it uses `setenv`, so `monkeypatch` restores the previous
    values after every test, and any test that deletes or overrides one still sees its own
    change because its `monkeypatch` calls run after this fixture.
    """
    # Which variables, and why not the others.
    #
    # META_VERIFY_TOKEN and E02_ACCOUNT_KEY_SECRET are set because production startup
    # refuses without them and no suite reads them to make a decision in development.
    #
    # META_APP_SECRET is NOT set. Setting it turns on `X-Hub-Signature-256` enforcement for
    # every webhook test in the suite, and the existing ones post unsigned bodies by design -
    # they exercise routing and SSRF containment, not signatures. Measured: setting it turned
    # `test_meta_webhook_image_url_cannot_reach_loopback` from skipped into a 403 failure.
    # The signature path has its own tests and is unchanged by this phase.
    #
    # ADMIN_PASSWORD is NOT set, and is not checked by `core.secret_guard` at all: it is
    # enforced at the point of use by `database._verify_admin_password`, which is the stronger
    # guarantee and is already covered by its own suite.
    # Only E02_ACCOUNT_KEY_SECRET. It is required by production startup and no suite reads it
    # to make a routing decision.
    #
    # META_VERIFY_TOKEN is deliberately NOT set. Setting it makes META_APP_SECRET conditionally
    # required (the pair means "the Meta integration is configured"), and setting *that*
    # switches on `X-Hub-Signature-256` enforcement for every webhook test - measured to turn
    # `test_meta_webhook_image_url_cannot_reach_loopback` from a skip into a 403. Suites that
    # enter a production startup and need the handshake configured set the pair themselves;
    # `test_e45_final_hardening.py` does exactly that.
    for name in ("E02_ACCOUNT_KEY_SECRET",):
        monkeypatch.setenv(name, _TEST_SECRET)


