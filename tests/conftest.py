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
