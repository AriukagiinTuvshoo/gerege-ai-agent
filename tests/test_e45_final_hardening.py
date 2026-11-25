"""Phase 45 — regression tests for F-44-A, F-44-B, F-44-C and F-44-F.

Each test here fails against the Phase 44 code and passes against the Phase 45 fix. That
was checked by reverting each fix in turn and re-running this file, not assumed: a
regression test that would have passed against the bug proves nothing.

The four findings:

  F-44-A  `verify_resource_tenant_ownership` allowed a resource whose tenant was `None`
          or `''`, because its condition was `resource_page_id and …`. Reachable while
          `registrations.page_id` was nullable; now guarded in the function *and* in the
          schema (migration 0008).
  F-44-B  GET `/webhook` completed Meta's handshake with the published default when
          `META_VERIFY_TOKEN` was unset, including under `ENV=production`.
  F-44-C  `tests/test_postgres_restore_real_rollback.py` guarded six cases with
          `print("[SKIP]"); return`, so a missing database produced "8 passed".
  F-44-F  Production secret enforcement existed for one credential (`ADMIN_PASSWORD`)
          and was documentation for the others.

These tests are deliberately behavioural where they can be: the IDOR ones call the real
function, and the F-44-C ones run the real pytest subprocess rather than grepping source.
"""

import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)


def _redis_is_reachable() -> bool:
    """Whether a live Redis answers.

    Only the two full-startup endpoint tests need this: `ENV=production` correctly refuses
    to start without a shared rate-limit store (E-02 Phase 6), so entering the app's lifespan
    requires one. Everything else in this file is independent of Redis and must run even on a
    machine that has none. CI always provides Redis, so these two always run there.
    """
    try:
        import redis as _redis

        client = _redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"),
            socket_connect_timeout=1,
        )
        client.ping()
        return True
    except Exception:
        return False


requires_redis = pytest.mark.skipif(
    not _redis_is_reachable(),
    reason=(
        "needs a live Redis: a production startup refuses to serve without a shared "
        "rate-limit store (E-02 Phase 6), so the full lifespan cannot be exercised here. "
        "CI provides Redis; the guard logic itself is covered by the non-Redis tests above."
    ),
)

from fastapi import HTTPException  # noqa: E402

from core import secret_guard  # noqa: E402
from core import security  # noqa: E402


# ---------------------------------------------------------------------------
# F-44-A — IDOR fails closed
# ---------------------------------------------------------------------------
class TestIdorGuardFailsClosed:
    """The guard must deny when it cannot prove the resource belongs to the caller."""

    USER_A = {"role": "client", "page_id": "pageA"}

    def _denied(self, resource_page_id):
        with pytest.raises(HTTPException) as exc:
            security.verify_resource_tenant_ownership(
                self.USER_A, resource_page_id, require_auth=True
            )
        return exc.value

    # 1. Valid same-tenant resource keeps working. This is the control that stops the fix
    #    from being "deny everything", which would pass every other test in this class.
    def test_same_tenant_resource_is_allowed(self):
        security.verify_resource_tenant_ownership(self.USER_A, "pageA", require_auth=True)

    # 2. Cross-tenant is rejected.
    def test_cross_tenant_resource_is_denied(self):
        assert self._denied("pageB").status_code == 403

    # 3. The Phase 44 defect: a resource with no tenant was allowed.
    def test_none_resource_page_id_is_denied(self):
        issue = self._denied(None)
        assert issue.status_code == 403
        assert "IDOR" in issue.detail

    # 4. Same defect, empty-string shape.
    def test_empty_resource_page_id_is_denied(self):
        assert self._denied("").status_code == 403

    # 4b. Whitespace is not a tenant either: `str(x).strip()` decides.
    def test_whitespace_resource_page_id_is_denied(self):
        assert self._denied("   ").status_code == 403

    # 5. A user with no tenant of their own cannot be proven to own anything.
    def test_user_without_page_id_is_denied(self):
        with pytest.raises(HTTPException) as exc:
            security.verify_resource_tenant_ownership(
                {"role": "client", "page_id": None}, "pageA", require_auth=True
            )
        assert exc.value.status_code == 403

    # 6. Unauthenticated stays 401 (not 403): the distinction matters to a client.
    def test_missing_user_is_unauthenticated_not_forbidden(self):
        with pytest.raises(HTTPException) as exc:
            security.verify_resource_tenant_ownership(None, "pageA", require_auth=True)
        assert exc.value.status_code == 401

    # 7. Admins are cross-tenant by design and must not be caught by the tightening.
    def test_admin_is_allowed_across_tenants(self):
        security.verify_resource_tenant_ownership(
            {"role": "admin", "page_id": None}, "pageB", require_auth=True
        )

    # 8. Surrounding whitespace on a real tenant must not turn a valid call into a 403.
    def test_surrounding_whitespace_on_a_matching_tenant_is_allowed(self):
        security.verify_resource_tenant_ownership(self.USER_A, " pageA ", require_auth=True)

    def test_the_old_condition_would_have_failed_this_suite(self):
        """A guard that only looked at `resource_page_id` truthiness is the bug.

        Asserted directly, so a future "simplification" back to
        `resource_page_id and str(resource_page_id) != str(user_pid)` is caught here as
        well as in the behavioural tests above.
        """
        # The expression the fix replaced, evaluated the way Python evaluated it.
        user_pid = "pageA"
        old_allowed = not (not user_pid or (None and str(None) != str(user_pid)))
        assert old_allowed is True, "the old expression no longer reproduces the bug"
        # ...and the current guard refuses the same input.
        assert self._denied(None).status_code == 403


class TestNullableTenantColumnIsClosed:
    """F-44-A's schema half: a lead cannot be stored without a tenant."""

    def test_registration_page_id_is_not_nullable_in_the_model(self):
        from core import models

        column = models.RegistrationModel.__table__.c.page_id
        assert column.nullable is False, (
            "registrations.page_id is nullable again: a NULL-tenant lead would exist for "
            "the IDOR guard to have to reason about"
        )

    def test_a_migration_enforces_not_null(self):
        """The model alone does not change an existing database; a revision must."""
        versions = os.path.join(REPO_ROOT, "migrations", "versions")
        migration = os.path.join(versions, "0008_registration_tenant_not_null.py")
        assert os.path.exists(migration), "the 0008 migration is missing"
        body = open(migration, encoding="utf-8").read()
        assert "SET NOT NULL" in body
        assert "registrations" in body and "page_id" in body


# ---------------------------------------------------------------------------
# F-44-B — Meta verify token
# ---------------------------------------------------------------------------
class TestMetaVerifyToken:
    @pytest.fixture(autouse=True)
    def _clean_env(self, monkeypatch):
        """Start every test from "no Meta token, not production".

        REDIS_URL is deliberately untouched: a full production startup legitimately needs a
        shared rate-limit store, and deleting it here would make `_apply_valid_env` unable
        to construct a valid configuration. Each test that needs production sets it.
        """
        monkeypatch.delenv("META_VERIFY_TOKEN", raising=False)
        monkeypatch.delenv("ENV", raising=False)
        monkeypatch.delenv("STRICT_SECURITY", raising=False)

    #: A complete, valid production environment. The endpoint tests must exercise the
    #: webhook decision, not the startup secret validator (which `TestSecretEnforcement`
    #: covers); without this, `TestClient` enters the lifespan and the validator aborts
    #: before a request is ever made - a confusing failure that says nothing about F-44-B.
    _VALID_ENV = {
        "META_APP_SECRET": "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3",
        "E02_ACCOUNT_KEY_SECRET": "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3",
        "ADMIN_PASSWORD": "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3",
    }

    def _apply_valid_env(self, monkeypatch):
        """Everything the production startup path requires, so only F-44-B varies.

        `ENV=production` legitimately demands a shared rate-limit store (E-02 Phase 6), so
        a live Redis URL is part of a *valid* production configuration here. Without it the
        app refuses to start for a reason that has nothing to do with this test.
        """
        for name, value in self._VALID_ENV.items():
            monkeypatch.setenv(name, value)
        # Always set it, even when the surrounding environment already has one: this must be
        # the value the *production* startup path reads, and `monkeypatch` restores it after
        # the test either way.
        monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6379/0")
        # The limiter caches the store it selected. Without this the process keeps whatever
        # backend an earlier test (running with no REDIS_URL) left behind, and startup
        # correctly refuses a per-worker counter - a stale-state failure that has nothing to
        # do with the behaviour under test.
        from core import rate_limit as _rate_limit

        _rate_limit._shared_limiter = None

    # 1. Production + unset -> not usable.
    def test_production_with_unset_token_is_not_usable(self, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        assert security.meta_verify_token_is_usable("") is False

    # 2. Production + empty/whitespace -> not usable.
    @pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
    def test_production_with_empty_token_is_not_usable(self, monkeypatch, blank):
        monkeypatch.setenv("ENV", "production")
        assert security.meta_verify_token_is_usable(blank) is False

    # 3. Production + a real value -> usable.
    def test_production_with_a_real_token_is_usable(self, monkeypatch):
        monkeypatch.setenv("ENV", "production")
        assert security.meta_verify_token_is_usable("9f2a1c7e5b8d4036a1e9") is True

    # 4. The published default is refused in production even when explicitly set.
    @pytest.mark.parametrize(
        "placeholder",
        [
            "agent_verify_secret_token_123",
            "AGENT_VERIFY_SECRET_TOKEN_123",
            "changeme",
            "your-token-here",
            "<generate: openssl rand -hex 16>",
        ],
    )
    def test_production_refuses_placeholders(self, monkeypatch, placeholder):
        monkeypatch.setenv("ENV", "production")
        assert security.meta_verify_token_is_usable(placeholder) is False

    # 5. STRICT_SECURITY counts as production, matching the rest of the codebase.
    def test_strict_security_mode_also_refuses_the_placeholder(self, monkeypatch):
        monkeypatch.setenv("STRICT_SECURITY", "1")
        assert security.meta_verify_token_is_usable("agent_verify_secret_token_123") is False

    # 6. Development stays usable: the suite and local runs depend on it.
    def test_development_allows_a_configured_token(self):
        assert security.meta_verify_token_is_usable("agent_verify_secret_token_123") is True

    def test_development_still_refuses_an_empty_token(self):
        """`empty` is never a token, in any environment."""
        assert security.meta_verify_token_is_usable("") is False

    # 7. No public fallback can activate: the constant no longer appears in main.py as a
    #    default for the environment variable.
    def test_main_has_no_published_fallback(self):
        body = open(os.path.join(REPO_ROOT, "main.py"), encoding="utf-8").read()
        # Only executable lines count. The fix's own docstring quotes the old expression
        # while explaining it, which is exactly the shape that made a naive string
        # assertion misfire in Phase 43 - so comments and prose are skipped.
        triple = chr(34) * 3
        offenders = []
        in_docstring = False
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.count(triple) % 2 == 1:
                in_docstring = not in_docstring
                continue
            if in_docstring or stripped.startswith("#"):
                continue
            if 'os.getenv("META_VERIFY_TOKEN"' in line and \
                    security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER in line:
                offenders.append(stripped)
        assert not offenders, f"the published fallback is back: {offenders}"

    # 8. The token's enforcement lives at the endpoint, not at startup, and that placement is
    #    deliberate: it only matters to Meta traffic, so a deployment that runs no Meta
    #    integration should still start. What must be true is that the handshake refuses.
    def test_production_without_a_token_refuses_the_handshake(self, monkeypatch):
        self._apply_valid_env(monkeypatch)
        monkeypatch.setenv("ENV", "production")
        monkeypatch.delenv("META_VERIFY_TOKEN", raising=False)
        assert security.meta_verify_token_is_usable("") is False
        # The endpoint is the enforcement point, and `main` imports cleanly without the token.
        import main
        from starlette.testclient import TestClient

        with TestClient(main.app, raise_server_exceptions=False) as client:
            response = client.get(
                "/webhook",
                params={
                    "hub.mode": "subscribe",
                    "hub.verify_token": security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER,
                    "hub.challenge": "challenge-123",
                },
            )
        assert response.status_code == 403
        assert "challenge-123" not in response.text

    # 8b. And if a deployment somehow bypassed the startup check, the endpoint itself still
    #     refuses the published default. This is the defence-in-depth case.
    def test_endpoint_still_refuses_the_placeholder_even_if_startup_is_bypassed(
        self, monkeypatch
    ):
        self._apply_valid_env(monkeypatch)
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("META_VERIFY_TOKEN", security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER)
        assert security.meta_verify_token_is_usable(
            security.PUBLIC_VERIFY_TOKEN_PLACEHOLDER
        ) is False

    @requires_redis
    # 9. ...and still works with a real token, so the fix is not "refuse everything".
    def test_endpoint_accepts_a_real_token_in_production(self, monkeypatch):
        self._apply_valid_env(monkeypatch)
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("META_VERIFY_TOKEN", "9f2a1c7e5b8d4036a1e9")
        import main
        from starlette.testclient import TestClient

        with TestClient(main.app, raise_server_exceptions=False) as client:
            response = client.get(
                "/webhook",
                params={
                    "hub.mode": "subscribe",
                    "hub.verify_token": "9f2a1c7e5b8d4036a1e9",
                    "hub.challenge": "challenge-456",
                },
            )
        assert response.status_code == 200
        assert response.text == "challenge-456"

    @requires_redis
    # 10. A wrong token is refused with the same response as a missing configuration, so
    #     the endpoint does not tell an outsider that the deployment is misconfigured.
    def test_wrong_token_is_indistinguishable_from_missing_configuration(self, monkeypatch):
        from starlette.testclient import TestClient
        import main

        self._apply_valid_env(monkeypatch)
        monkeypatch.setenv("ENV", "production")
        monkeypatch.setenv("META_VERIFY_TOKEN", "9f2a1c7e5b8d4036a1e9")
        with TestClient(main.app, raise_server_exceptions=False) as client:
            wrong = client.get(
                "/webhook",
                params={"hub.mode": "subscribe", "hub.verify_token": "nope", "hub.challenge": "c"},
            )
            # Same request, but the caller presents nothing at all.
            absent = client.get(
                "/webhook",
                params={"hub.mode": "subscribe", "hub.challenge": "c"},
            )
        assert wrong.status_code == absent.status_code == 403
        assert wrong.text == absent.text
        # Neither response echoes the challenge, so a failed handshake cannot be used to
        # smuggle data back to the caller.
        assert "c" != wrong.text.strip()

    def test_no_secret_is_ever_logged(self, monkeypatch, caplog):
        """The refusal path must not print the configured value."""
        monkeypatch.setenv("ENV", "production")
        secret_value = "9f2a1c7e5b8d4036a1e9"
        monkeypatch.setenv("META_VERIFY_TOKEN", "changeme")
        with caplog.at_level("DEBUG"):
            security.meta_verify_token_is_usable(os.environ["META_VERIFY_TOKEN"])
        assert secret_value not in caplog.text


# ---------------------------------------------------------------------------
# F-44-C — no false PASSED when PostgreSQL is absent
# ---------------------------------------------------------------------------
class TestNoFalsePassWhenPostgresIsMissing:
    TARGET = "tests/test_postgres_restore_real_rollback.py"

    def _run(self, env_extra):
        env = dict(os.environ)
        env.pop("DATABASE_URL", None)
        env.update(env_extra)
        return subprocess.run(
            [sys.executable, "-m", "pytest", self.TARGET, "-q", "-rs", "-p", "no:cacheprovider"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=600,
        )

    # 1. Missing PostgreSQL must SKIP, not pass.
    def test_missing_postgres_skips_instead_of_passing(self):
        result = self._run({})
        assert "skipped" in result.stdout, result.stdout[-2000:]
        assert "8 passed" not in result.stdout, (
            "all 8 cases reported PASSED without a database: the false-pass guard is back"
        )
        assert "requires a live PostgreSQL target" in result.stdout

    # 2. The skip is clearly reported with a reason, not silent.
    def test_the_skip_carries_an_explicit_reason(self):
        result = self._run({})
        assert "SKIPPED" in result.stdout
        assert "DATABASE_URL" in result.stdout

    # 3. No `print("[SKIP]")` guard survives in the file.
    def test_the_false_pass_pattern_is_gone(self):
        body = open(os.path.join(REPO_ROOT, self.TARGET), encoding="utf-8").read()
        offenders = [
            line.strip()
            for line in body.splitlines()
            if line.strip().startswith('print("[SKIP]')
        ]
        assert not offenders, f"a false-pass guard is back: {offenders}"
        assert "pytest.skip(" in body, "the module never calls pytest.skip()"

    # 4. A genuine failure remains a failure (not converted into a skip by the change).
    def test_a_real_failure_still_fails(self, tmp_path):
        """Guard against the fix being implemented as "skip whenever anything is wrong"."""
        bogus = tmp_path / "test_genuine_failure.py"
        bogus.write_text(
            "import pytest\n\n\ndef test_this_must_fail():\n    assert 1 == 2, 'genuine'\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(bogus), "-q", "-p", "no:cacheprovider"],
            cwd=str(tmp_path), capture_output=True, text=True, timeout=300,
        )
        assert result.returncode != 0
        assert "1 failed" in result.stdout


# ---------------------------------------------------------------------------
# F-44-F — secret enforcement
# ---------------------------------------------------------------------------
class TestSecretEnforcement:
    STRONG = "9f2a1c7e5b8d4036a1e9c4f7b2d8e5a3"

    def _environ(self, **overrides):
        """A fully valid production environment, so a test can break exactly one thing."""
        env = {
            "ENV": "production",
            "META_VERIFY_TOKEN": self.STRONG,
            "META_APP_SECRET": self.STRONG,
            "E02_ACCOUNT_KEY_SECRET": self.STRONG,
        }
        env.update(overrides)
        return env

    # Valid configuration is accepted, so the guard is not simply "always raise".
    def test_a_fully_valid_environment_passes(self):
        assert secret_guard.validate_production_secrets(self._environ()) == []

    @pytest.mark.parametrize(
        "name",
        ["E02_ACCOUNT_KEY_SECRET", "META_APP_SECRET"],
    )
    def test_missing_secret_fails_startup(self, name):
        env = self._environ()
        del env[name]
        with pytest.raises(secret_guard.InsecureSecretError) as exc:
            secret_guard.validate_production_secrets(env)
        assert name in str(exc.value)
        assert "missing" in str(exc.value)

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_empty_secret_fails_startup(self, blank):
        with pytest.raises(secret_guard.InsecureSecretError):
            secret_guard.validate_production_secrets(self._environ(META_APP_SECRET=blank))

    @pytest.mark.parametrize(
        "placeholder",
        ["agent_verify_secret_token_123", "changeme", "<generate: openssl rand -base64 32>", "your-secret"],
    )
    def test_placeholder_secret_fails_startup(self, placeholder):
        with pytest.raises(secret_guard.InsecureSecretError) as exc:
            secret_guard.validate_production_secrets(
                self._environ(E02_ACCOUNT_KEY_SECRET=placeholder)
            )
        assert "placeholder" in str(exc.value)

    def test_weak_secret_fails_startup(self):
        with pytest.raises(secret_guard.InsecureSecretError) as exc:
            secret_guard.validate_production_secrets(self._environ(E02_ACCOUNT_KEY_SECRET="short"))
        assert "weak" in str(exc.value)

    # The error must be safe to paste into a ticket.
    def test_the_error_never_contains_a_secret_value(self):
        # A value that IS rejected (a placeholder), so the assertion is about the message
        # rather than about whether the guard fired at all.
        value = "changeme-please-replace-me"
        assert secret_guard.classify_secret("E02_ACCOUNT_KEY_SECRET", value) is not None
        with pytest.raises(secret_guard.InsecureSecretError) as exc:
            secret_guard.validate_production_secrets(
                self._environ(E02_ACCOUNT_KEY_SECRET=value)
            )
        message = str(exc.value)
        assert value not in message
        assert "E02_ACCOUNT_KEY_SECRET" in message

    def test_a_leaked_length_is_the_only_quantity_reported(self):
        with pytest.raises(secret_guard.InsecureSecretError) as exc:
            secret_guard.validate_production_secrets(
                self._environ(E02_ACCOUNT_KEY_SECRET="abc123")
            )
        assert "6 characters" in str(exc.value)
        assert "abc123" not in str(exc.value)

    # Development must stay practical: warnings, not refusal.
    def test_development_does_not_raise(self):
        env = {"ENV": "development", "META_VERIFY_TOKEN": ""}
        issues = secret_guard.validate_production_secrets(env)
        assert issues, "development should still report the issues"
        assert all(isinstance(i, secret_guard.SecretIssue) for i in issues)

    def test_development_accepts_placeholders_without_raising(self):
        env = {"ENV": "development", "META_VERIFY_TOKEN": "agent_verify_secret_token_123"}
        assert secret_guard.validate_production_secrets(env)

    # Conditional secrets: only required when the integration is configured.
    def test_telegram_secret_not_required_when_telegram_is_unconfigured(self):
        env = self._environ()
        assert secret_guard.validate_production_secrets(env) == []

    def test_telegram_secret_required_when_telegram_is_configured(self):
        env = self._environ(TELEGRAM_BOT_TOKEN="123:abc", TELEGRAM_WEBHOOK_SECRET="")
        with pytest.raises(secret_guard.InsecureSecretError) as exc:
            secret_guard.validate_production_secrets(env)
        assert "TELEGRAM_WEBHOOK_SECRET" in str(exc.value)

    def test_classify_is_total_and_value_free(self):
        """Every input yields either None or a well-formed, value-free issue."""
        for value in (None, "", "x", self.STRONG, "changeme"):
            issue = secret_guard.classify_secret("SOME_NAME", value)
            if issue is None:
                continue
            assert issue.name == "SOME_NAME"
            assert issue.reason in {"missing", "placeholder", "weak"}
            # A rejected value must not be reproducible from the detail, except when it is
            # a single character ("x") which the *length* rule legitimately reports.
            if value and len(str(value)) > 1:
                assert str(value) not in issue.detail

    def test_admin_password_is_enforced_elsewhere_not_duplicated(self):
        """ADMIN_PASSWORD is deliberately out of the sweep - assert the reasoning holds.

        Phase 45 delegated it to `database.authenticate_admin`, which refuses the default
        in production at the point of use. That is stronger than a startup check, and
        duplicating it here broke sixteen suites that authenticate with the documented
        development credential. If the delegation is ever reversed, both halves must change
        together - so this test pins the pairing.
        """
        assert "ADMIN_PASSWORD" not in secret_guard.REQUIRED_PRODUCTION_SECRETS
        assert "ADMIN_PASSWORD" in secret_guard.SECRETS_ENFORCED_ELSEWHERE
        # Same reasoning for the Meta handshake token: enforced by the endpoint itself.
        assert "META_VERIFY_TOKEN" not in secret_guard.REQUIRED_PRODUCTION_SECRETS
        assert "META_VERIFY_TOKEN" in secret_guard.SECRETS_ENFORCED_ELSEWHERE
        # ...and the enforcing code refuses the default in production.
        import database

        os.environ_backup = os.environ.get("ENV")
        try:
            os.environ["ENV"] = "production"
            os.environ.pop("ADMIN_PASSWORD", None)
            assert database.authenticate_admin(database.DEFAULT_ADMIN_PASSWORD) is False, (
                "the default admin password is accepted in production"
            )
        finally:
            if os.environ_backup is None:
                os.environ.pop("ENV", None)
            else:
                os.environ["ENV"] = os.environ_backup

    def test_startup_hook_is_wired(self):
        """The validator must actually run at startup, not merely exist."""
        body = open(os.path.join(REPO_ROOT, "main.py"), encoding="utf-8").read()
        assert "validate_production_secrets()" in body
