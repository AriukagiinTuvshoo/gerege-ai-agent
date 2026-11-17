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


@pytest.fixture(autouse=True)
def _e02_account_key_secret(monkeypatch):
    """
    Configure the account-key secret for every test.

    `autouse` so no login test silently runs against a disabled account throttle and then
    asserts something weaker than it thinks. A test that specifically needs the secret
    *absent* (to prove fail-closed behaviour) overrides this with
    `monkeypatch.delenv(..., raising=False)` plus `rate_limit.refresh_account_key_secret()`.
    """
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
