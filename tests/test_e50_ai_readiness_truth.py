"""Phase 50 — F-50-1: a *configured* AI key is not a *verified* one.

The finding, measured live on 2026-11-26 with a real key written to `.env`:

    /api/health -> {"gemini_ready": true, ...}
    /api/chat   -> 200 {"model": "fallback"}      # every generation attempt failed
    log         -> ERROR:agent:Gemini API алдаа: TLS/SSL connection has been closed (EOF)

`agent.is_gemini_ready()` is `bool(agent.default_client)`, and building that client
(`genai.Client(api_key=...)`) performs no network I/O. So `/api/health` — an unauthenticated
endpoint an operator reads during an incident — reported the AI as ready while every reply
was coming from the deterministic fallback, for a key that was wrong, revoked, over quota or
merely unreachable. It also sat next to two honestly named neighbours,
`meta_token_configured` and `telegram_configured`, which claim only configuration.

This file pins the fixed behaviour:

* the observed verdict of real generation calls is recorded, classified into a closed enum,
  and published beside the historical field — which keeps its historical value, so nothing
  that already reads `gemini_ready` changes behaviour;
* "never attempted" is `null`, not `false`: a fresh process is not a broken key;
* a tenant's own key cannot verify (or condemn) the platform key, and vice versa;
* rotating the key discards a verdict that was about a different credential;
* nothing secret reaches the log or the unauthenticated payload — no exception text at all
  leaves `health_fields()`, and the excerpt kept for logs is redacted, single-line, bounded;
* the diagnostic can never be the reason a request or a health endpoint fails.

F-50-2 is pinned here too: the three AI error paths in `agent.py` used to log (and, for
receipt analysis, *return to an API caller*) the raw exception text. An SDK message can quote
the request it was building, so all three now go through `ai_readiness.redacted()`.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from core import ai_readiness

# --------------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------------

#: The exact failure observed on the live instance: no route to Google from the sandbox.
LIVE_NETWORK_ERROR = "TLS/SSL connection has been closed (EOF) (_ssl.c:992)"

#: Obviously fake. Never a real credential, and shaped so a leak is unmistakable.
FAKE_KEY = "e50-fake-gemini-key-4a7c9e2b"

#: A distinctive marker used to prove exception text does not reach an unauthenticated payload.
MARKER = "e50-distinctive-diagnostic-marker-7731"


@pytest.fixture(autouse=True)
def _clean_observation():
    """The observation is process-global; every test starts and ends from a known state."""
    ai_readiness.reset()
    yield
    ai_readiness.reset()


@pytest.fixture()
def client():
    import main

    with TestClient(main.app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture()
def configured_agent(monkeypatch):
    """An agent whose default key is configured, with `.env` kept out of the way.

    `agent._init_default_gemini()` calls `load_dotenv(override=True)`, which would let a
    developer's `.env` override the value a test just set (F-48A-2). Stubbing it makes the
    test mean the same thing on a workstation and in CI.
    """
    import agent as agent_module

    monkeypatch.setattr(agent_module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
    monkeypatch.setenv("GEMINI_MODEL", "e50-test-model")
    agent_module._init_default_gemini()
    yield agent_module
    ai_readiness.reset()


class _RecordingHandler(logging.Handler):
    """Collect log records from one named logger.

    `caplog` proved unreliable in this repository when the schema is created inside the
    session (see tests/test_e49_page_secret_hygiene.py): a negative assertion on an empty
    capture passes for free. Attaching a handler to the specific logger cannot miss.

    It must be a real `logging.Handler`: `Logger.callHandlers` reads `hdlr.level` and calls
    `hdlr.handle(record)`, so a duck-typed object raises inside the logging call — and
    `record_failure` swallows that by design, which would make these tests pass while
    asserting nothing. (That is exactly how the first version of this fixture failed.)
    """

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        try:
            self.records.append(record.getMessage())
        except Exception:  # noqa: BLE001
            self.records.append("<unformatable>")

    @property
    def text(self):
        return "\n".join(self.records)


@pytest.fixture()
def readiness_log():
    handler = _RecordingHandler()
    logger = logging.getLogger("core.ai_readiness")
    previous_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)


# --------------------------------------------------------------------------------------------
# 1. Classification — a closed enum, coarse enough to act on, fine enough to be useful
# --------------------------------------------------------------------------------------------


class TestErrorClassification:
    """Each class must map to an operator action, and the mapping must be predictable."""

    @pytest.mark.parametrize(
        "message,wanted",
        [
            # The error the live instance actually produced.
            (LIVE_NETWORK_ERROR, "network"),
            ("[Errno -3] Temporary failure in name resolution", "network"),
            ("[Errno 111] Connection refused", "network"),
            ("[Errno 11001] getaddrinfo failed", "network"),
            ("httpx.ReadTimeout: timed out", "network"),
            ("ConnectError: All connection attempts failed", "network"),
            ("RemoteDisconnected('Remote end closed connection without response')", "network"),
            # The operator action for all three of these is "rotate / re-issue the key",
            # whichever status the provider wrapped it in.
            (
                "400 BAD_REQUEST. {'error': {'code': 400, 'message': "
                "'API key not valid. Please pass a valid API key.'}}",
                "auth",
            ),
            ("ClientError: 403 Permission denied. API key does not have access", "auth"),
            ("401 UNAUTHENTICATED. Request had invalid authentication credentials", "auth"),
            ("429 RESOURCE_EXHAUSTED. You exceeded your current quota.", "quota"),
            ("Too Many Requests", "quota"),
            ("404 models/gemini-3.5-flash-lite is not found for project", "model"),
            ("503 Service Unavailable", "server"),
            ("500 Internal error encountered.", "server"),
            ("400 Invalid JSON payload received. Invalid argument at contents", "bad_request"),
            ("ValueError: contents must not be empty", "other"),
        ],
    )
    def test_provider_errors_are_filed_by_the_action_they_need(self, message, wanted):
        assert ai_readiness.classify_error(RuntimeError(message)) == wanted

    def test_every_class_is_in_the_published_enum(self):
        """The enum is published to an unauthenticated endpoint, so it is the contract."""
        for name, _needles in ai_readiness._CLASSIFIERS:
            assert name in ai_readiness.ERROR_CLASSES

    def test_classification_never_returns_anything_outside_the_enum(self):
        for value in (
            RuntimeError(LIVE_NETWORK_ERROR),
            ValueError(""),
            Exception("402 payment required"),
            KeyError("weird"),
            None,
            "a bare string",
            42,
        ):
            assert ai_readiness.classify_error(value) in ai_readiness.ERROR_CLASSES

    def test_a_status_code_attribute_wins_over_the_text(self):
        """SDK exceptions carry the real status; the message is prose."""

        class ClientError(Exception):
            status_code = 401

        assert ai_readiness.classify_error(ClientError("conflicting prose about a quota")) == "auth"

    def test_a_string_status_code_attribute_is_understood(self):
        class Weird(Exception):
            code = "429"

        assert ai_readiness.classify_error(Weird("no keywords here")) == "quota"

    def test_an_out_of_range_status_is_ignored(self):
        class Weird(Exception):
            status_code = 999

        # 999 is not an HTTP status, so the text decides — and this text says network.
        assert ai_readiness.classify_error(Weird(LIVE_NETWORK_ERROR)) == "network"

    def test_an_ssl_source_location_does_not_become_a_status_code(self):
        """Python reports TLS failures as `... (_ssl.c:NNN)`, and NNN is a line number.

        Both of these contain a digit run that could be mistaken for an HTTP status; the
        reason phrase must win, so a TLS failure is never filed as a provider-side 500.
        """
        assert ai_readiness.classify_error(RuntimeError(LIVE_NETWORK_ERROR)) == "network"
        assert ai_readiness.classify_error(
            RuntimeError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:500)")
        ) == "network"

    def test_a_number_in_prose_is_not_invented_into_a_status(self):
        """Only a code a provider demonstrably sent is read as one."""
        assert ai_readiness.classify_error(RuntimeError("the report was 429 pages long")) == "other"
        assert ai_readiness.classify_error(RuntimeError("exceeded 500 tokens")) == "other"

    @pytest.mark.parametrize(
        "message,wanted",
        [
            ("<HttpError 403 when requesting https://generativelanguage.googleapis.com/>", "auth"),
            ("Error code: 429 - {'error': {'message': 'slow down'}}", "quota"),
            ("status_code=503", "server"),
            ("upstream said code: 404", "model"),
        ],
    )
    def test_a_status_in_the_wrappers_providers_actually_emit(self, message, wanted):
        assert ai_readiness.classify_error(RuntimeError(message)) == wanted

    def test_classification_is_case_insensitive(self):
        assert ai_readiness.classify_error(RuntimeError("API_KEY_INVALID")) == "auth"
        assert ai_readiness.classify_error(RuntimeError("api_key_invalid")) == "auth"

    def test_a_filesystem_permission_error_is_not_an_authentication_failure(self):
        """`Permission denied` on a path is not a credential problem.

        This is why the auth needles name the provider's own vocabulary
        (`PERMISSION_DENIED`, `403`, `api key`) rather than the English phrase.
        """
        assert ai_readiness.classify_error(
            RuntimeError("[Errno 13] Permission denied: '/var/lib/app/cache.db'")
        ) == "other"

    def test_a_hostile_exception_cannot_break_classification(self):
        class Hostile(Exception):
            def __str__(self):
                raise RuntimeError("cannot even describe myself")

        assert ai_readiness.classify_error(Hostile()) in ai_readiness.ERROR_CLASSES


# --------------------------------------------------------------------------------------------
# 2. The finding itself: configured is not verified
# --------------------------------------------------------------------------------------------


class TestConfiguredIsNotVerified:
    def test_a_client_that_was_never_used_is_not_a_verdict(self):
        fields = ai_readiness.health_fields(configured=True)
        assert fields["gemini_configured"] is True
        assert fields["gemini_verified"] is None, (
            "nothing was attempted, so nothing is known — this must not read as verified"
        )

    def test_untried_is_not_reported_as_broken_either(self):
        assert ai_readiness.health_fields(configured=True)["gemini_verified"] is not False

    def test_the_historical_field_keeps_its_historical_meaning(self):
        """/api/health has published `gemini_ready` since Phase 5; consumers must not break."""
        assert ai_readiness.health_fields(configured=True)["gemini_ready"] is True
        assert ai_readiness.health_fields(configured=False)["gemini_ready"] is False

    def test_ready_and_configured_always_agree(self):
        for configured in (True, False):
            fields = ai_readiness.health_fields(configured=configured)
            assert fields["gemini_ready"] == fields["gemini_configured"]

    def test_the_note_says_the_key_is_not_proven(self):
        note = ai_readiness.note(configured=True)
        assert "NOT proven" in note
        assert "no network call" in note, "the note must explain *why* configured is not verified"

    def test_the_note_tells_an_operator_what_to_do_when_no_key_is_set(self):
        note = ai_readiness.note(configured=False)
        assert "GEMINI_API_KEY" in note
        assert "fallback" in note

    def test_no_error_class_is_invented_before_anything_happened(self):
        fields = ai_readiness.health_fields(configured=True)
        assert fields["gemini_error_class"] is None
        assert fields["gemini_attempts"] == 0


# --------------------------------------------------------------------------------------------
# 3. The observed verdict
# --------------------------------------------------------------------------------------------


class TestObservedVerdict:
    def test_a_failed_call_is_recorded_with_its_class(self):
        klass = ai_readiness.record_failure(RuntimeError(LIVE_NETWORK_ERROR), model="m")
        assert klass == "network"
        fields = ai_readiness.health_fields(configured=True)
        assert fields["gemini_verified"] is False
        assert fields["gemini_error_class"] == "network"

    def test_the_error_observed_on_the_live_instance_classifies_as_network(self):
        """This is the exact string from the sandbox run, kept as a regression pin."""
        assert ai_readiness.classify_error(Exception(LIVE_NETWORK_ERROR)) == "network"

    def test_a_successful_call_clears_the_previous_error(self):
        ai_readiness.record_failure(RuntimeError("403 PERMISSION_DENIED"), model="m")
        ai_readiness.record_success(model="m")
        fields = ai_readiness.health_fields(configured=True)
        assert fields["gemini_verified"] is True
        assert fields["gemini_error_class"] is None

    def test_the_verdict_follows_the_most_recent_call(self):
        ai_readiness.record_success(model="m")
        assert ai_readiness.health_fields(True)["gemini_verified"] is True
        ai_readiness.record_failure(RuntimeError("429 quota"), model="m")
        assert ai_readiness.health_fields(True)["gemini_verified"] is False
        ai_readiness.record_success(model="m")
        assert ai_readiness.health_fields(True)["gemini_verified"] is True

    def test_counters_count_calls_not_conversations(self):
        """A retry is a second call, and saying so is more useful than hiding it."""
        ai_readiness.record_failure(RuntimeError("tls eof"), model="m")
        ai_readiness.record_failure(RuntimeError("tls eof"), model="m")
        ai_readiness.record_success(model="m")
        state = ai_readiness.snapshot()
        assert (state["attempts"], state["failures"], state["successes"]) == (3, 2, 1)
        assert ai_readiness.health_fields(True)["gemini_attempts"] == 3

    def test_the_timestamp_is_utc_and_iso8601(self):
        ai_readiness.record_success(model="m")
        stamp = ai_readiness.snapshot()["last_attempt_at"]
        parsed = datetime.fromisoformat(stamp)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timezone.utc.utcoffset(None)
        assert abs((datetime.now(timezone.utc) - parsed).total_seconds()) < 120

    def test_the_model_that_was_actually_called_is_remembered(self):
        ai_readiness.record_success(model="gemini-test-a")
        assert ai_readiness.snapshot()["last_model"] == "gemini-test-a"

    def test_a_failed_note_names_the_class_so_it_can_be_acted_on(self):
        ai_readiness.record_failure(RuntimeError("API key not valid"), model="m")
        note = ai_readiness.note(configured=True)
        assert "FAILED" in note
        assert "auth" in note
        assert "not a working key" in note

    def test_a_succeeded_note_does_not_overclaim(self):
        ai_readiness.record_success(model="m")
        note = ai_readiness.note(configured=True)
        assert "succeeded" in note
        assert "most recent" in note, "one success is not a promise about the next call"


# --------------------------------------------------------------------------------------------
# 4. Scope: a tenant's key is not the platform's key
# --------------------------------------------------------------------------------------------


class TestScopeIsolation:
    def test_a_working_tenant_key_does_not_verify_the_platform_key(self):
        """The failure mode this prevents: one tenant paying for their own key makes the
        platform's broken key look healthy."""
        ai_readiness.record_success(scope="page", model="m")
        assert ai_readiness.snapshot("page")["verified"] is True
        assert ai_readiness.snapshot("default")["verified"] is None
        assert ai_readiness.health_fields(configured=True)["gemini_verified"] is None

    def test_a_broken_platform_key_does_not_condemn_a_tenant_key(self):
        ai_readiness.record_failure(RuntimeError("tls eof"), scope="default", model="m")
        ai_readiness.record_success(scope="page", model="m")
        assert ai_readiness.snapshot("default")["verified"] is False
        assert ai_readiness.snapshot("page")["verified"] is True

    def test_an_unknown_scope_is_filed_against_the_default(self):
        """A new call site must not be able to create an unpublished bucket silently."""
        ai_readiness.record_success(scope="nonsense", model="m")
        assert ai_readiness.snapshot("default")["verified"] is True
        assert set(ai_readiness._STATE) == set(ai_readiness.SCOPES)

    def test_both_scopes_are_reset_together(self):
        ai_readiness.record_success(scope="page", model="m")
        ai_readiness.record_success(scope="default", model="m")
        ai_readiness.reset()
        assert ai_readiness.snapshot("page")["attempts"] == 0
        assert ai_readiness.snapshot("default")["attempts"] == 0


# --------------------------------------------------------------------------------------------
# 5. Rotation: a verdict belongs to the credential it was observed with
# --------------------------------------------------------------------------------------------


class TestKeyRotation:
    def test_rotating_the_key_discards_the_old_verdict(self, configured_agent, monkeypatch):
        configured_agent.ai_readiness.record_success(model="m")
        assert configured_agent.gemini_status()["gemini_verified"] is True

        monkeypatch.setenv("GEMINI_API_KEY", "e50-a-different-fake-key-1111")
        configured_agent._init_default_gemini()

        assert configured_agent.gemini_status()["gemini_verified"] is None, (
            "the previous success was about the old key; reporting it for the new one "
            "would be exactly the lie this phase removes"
        )

    def test_reinitialising_with_the_same_key_keeps_the_verdict(self, configured_agent):
        """`get_client_for_page()` re-runs `_init_default_gemini()` on every request path;
        a verdict must survive that, or it would be forgotten constantly."""
        configured_agent.ai_readiness.record_failure(RuntimeError("tls eof"), model="m")
        configured_agent._init_default_gemini()
        configured_agent._init_default_gemini()
        assert configured_agent.gemini_status()["gemini_verified"] is False
        assert configured_agent.gemini_status()["gemini_error_class"] == "network"

    def test_clearing_the_key_discards_the_verdict(self, configured_agent, monkeypatch):
        configured_agent.ai_readiness.record_success(model="m")
        monkeypatch.setenv("GEMINI_API_KEY", "")
        configured_agent._init_default_gemini()
        assert configured_agent.is_gemini_configured() is False
        assert configured_agent.gemini_status()["gemini_verified"] is None

    def test_only_a_fingerprint_of_the_key_is_kept(self, configured_agent):
        """The rotation check needs to notice a change without storing the credential."""
        fingerprint = configured_agent.agent._ai_key_fingerprint
        assert fingerprint
        assert FAKE_KEY not in fingerprint
        assert len(fingerprint) == 16

    def test_clearing_the_key_actually_drops_the_client(self, configured_agent, monkeypatch):
        """F-50-3: an operator who removes a key must stop using it.

        Before this, the `else` branch left the previously built client in place, so the app
        kept calling (and billing) a credential that had just been removed, while
        `/api/health` still reported it as configured.
        """
        assert configured_agent.is_gemini_configured() is True
        monkeypatch.setenv("GEMINI_API_KEY", "")
        configured_agent._init_default_gemini()
        assert configured_agent.agent.default_client is None
        assert configured_agent.is_gemini_ready() is False
        assert configured_agent.gemini_status()["gemini_note"].startswith("no API key")

    def test_the_fingerprint_is_a_truncated_hash_not_the_key(self, configured_agent):
        """What the rotation check stores must not be usable as the credential."""
        import hashlib

        fingerprint = configured_agent.agent._ai_key_fingerprint
        assert fingerprint == hashlib.sha256(FAKE_KEY.encode("utf-8")).hexdigest()[:16]
        assert FAKE_KEY not in fingerprint
        assert len(fingerprint) < len(FAKE_KEY)


# --------------------------------------------------------------------------------------------
# 6. What the unauthenticated endpoint may publish
# --------------------------------------------------------------------------------------------


class TestHealthPayload:
    NEW_FIELDS = (
        "gemini_ready",
        "gemini_configured",
        "gemini_verified",
        "gemini_error_class",
        "gemini_attempts",
        "gemini_note",
    )

    def test_health_publishes_the_observed_state(self, client):
        body = client.get("/api/health").json()
        for field in self.NEW_FIELDS:
            assert field in body, f"{field} missing from /api/health"

    def test_health_types_are_what_a_monitor_can_rely_on(self, client):
        body = client.get("/api/health").json()
        assert isinstance(body["gemini_ready"], bool)
        assert isinstance(body["gemini_configured"], bool)
        assert body["gemini_verified"] in (True, False, None)
        assert body["gemini_error_class"] is None or body["gemini_error_class"] in (
            ai_readiness.ERROR_CLASSES
        )
        assert isinstance(body["gemini_attempts"], int)
        assert isinstance(body["gemini_note"], str)

    def test_health_reports_a_failure_that_already_happened(self, client):
        ai_readiness.record_failure(RuntimeError("429 RESOURCE_EXHAUSTED"), model="m")
        body = client.get("/api/health").json()
        assert body["gemini_verified"] is False
        assert body["gemini_error_class"] == "quota"

    def test_health_carries_no_exception_text(self, client):
        """/api/ready states the rule in its own comment: an unauthenticated endpoint
        publishes a backend *kind*, never a URL and never exception text. A provider error
        can contain a key, a project id or an internal URL."""
        ai_readiness.record_failure(
            RuntimeError(f"{MARKER} https://internal.example/v1?key={FAKE_KEY}"), model="m"
        )
        text = client.get("/api/health").text
        assert MARKER not in text
        assert "internal.example" not in text

    def test_health_never_carries_the_api_key(self, client, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
        ai_readiness.record_failure(RuntimeError(f"request used key={FAKE_KEY} {MARKER}"), model="m")
        text = client.get("/api/health").text
        assert FAKE_KEY not in text
        assert MARKER not in text

    def test_the_note_cannot_smuggle_the_error_in(self, client):
        ai_readiness.record_failure(RuntimeError(MARKER), model="m")
        note = client.get("/api/health").json()["gemini_note"]
        assert MARKER not in note
        assert note.startswith("the most recent generation call FAILED")

    def test_health_still_reports_its_neighbours_unchanged(self, client):
        body = client.get("/api/health").json()
        for field in (
            "status",
            "model",
            "rate_limit_backend",
            "rate_limits_shared_across_workers",
            "meta_token_configured",
            "telegram_configured",
            "total_pages",
            "total_leads",
            "active_sessions",
            "summary_available",
        ):
            assert field in body, f"{field} disappeared from /api/health"
        assert body["status"] == "healthy"

    def test_health_is_still_200_if_the_diagnostic_dies(self, client, monkeypatch):
        """A diagnostic that can break the endpoint it is reported through is worse than no
        diagnostic at all."""
        import agent as agent_module

        def explode(*args, **kwargs):
            raise RuntimeError("diagnostic is down")

        monkeypatch.setattr(agent_module.ai_readiness, "health_fields", explode)
        response = client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["gemini_verified"] is None
        assert "could not be observed" in body["gemini_note"]
        assert body["status"] == "healthy"

    def test_health_does_not_get_slower_because_of_the_diagnostic(self, client):
        """/api/health is O(1) extra work: read a dict under a lock. No I/O, no query."""
        ai_readiness.record_success(model="m")
        body = client.get("/api/health").json()
        assert body["gemini_attempts"] == 1
        source_fields = ai_readiness.health_fields(configured=True)
        assert set(source_fields) == set(self.NEW_FIELDS)


# --------------------------------------------------------------------------------------------
# 7. F-50-2: nothing secret reaches a log or an API response
# --------------------------------------------------------------------------------------------


class TestNothingSecretIsLogged:
    def test_the_recorded_excerpt_is_redacted(self, monkeypatch):
        # Redaction learns the literal value from the environment, which is exactly where a
        # real key lives; without that it can only apply its shape rules.
        monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
        ai_readiness.record_failure(
            RuntimeError(f"GET https://x/v1/models?key={FAKE_KEY} failed"), model="m"
        )
        excerpt = ai_readiness.snapshot()["last_error_excerpt"]
        assert FAKE_KEY not in excerpt
        assert "[REDACTED]" in excerpt

    def test_the_logged_line_is_redacted(self, readiness_log, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
        ai_readiness.record_failure(
            RuntimeError(f"provider rejected key={FAKE_KEY} with {MARKER}"), model="m"
        )
        assert readiness_log.records, "a failure must be logged once, at the recorder"
        assert FAKE_KEY not in readiness_log.text
        assert MARKER in readiness_log.text, "the diagnostic itself must survive redaction"

    def test_the_logged_line_is_one_line_and_bounded(self, readiness_log, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
        ai_readiness.record_failure(
            RuntimeError(f"first\n{MARKER}\n" + "x" * 5000 + f"\nlast {FAKE_KEY}"), model="m"
        )
        line = next(r for r in readiness_log.records if MARKER in r)
        assert "\n" not in line, "a newline lets a caller forge a second log record"
        assert len(line) < 400
        assert FAKE_KEY not in line

    def test_the_excerpt_kept_in_state_is_bounded(self):
        ai_readiness.record_failure(RuntimeError("y" * 9000), model="m")
        assert len(ai_readiness.snapshot()["last_error_excerpt"]) <= (
            ai_readiness.MAX_EXCERPT_LENGTH + 40
        )

    def test_redaction_failure_falls_back_to_the_class_name(self, monkeypatch):
        from core import redaction

        def explode(*args, **kwargs):
            raise RuntimeError("redactor is down")

        monkeypatch.setattr(redaction, "sanitize_message", explode)
        assert ai_readiness.redacted(ValueError(f"secret {FAKE_KEY}")) == "ValueError"

    def test_an_exception_that_cannot_be_described_is_still_reportable(self):
        class Hostile(Exception):
            def __str__(self):
                raise RuntimeError("no")

        text = ai_readiness.redacted(Hostile())
        assert text == "Hostile"

    def test_redaction_alone_never_leaks_a_configured_secret(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
        assert FAKE_KEY not in ai_readiness.redacted(
            RuntimeError(f"the request carried {FAKE_KEY} in a header")
        )


# --------------------------------------------------------------------------------------------
# 8. The diagnostic must never be the reason something else fails
# --------------------------------------------------------------------------------------------


class TestRecordingIsSafe:
    def test_recording_never_raises(self):
        class Hostile(Exception):
            def __str__(self):
                raise RuntimeError("no")

        ai_readiness.record_failure(Hostile(), model="m")
        ai_readiness.record_success(model="m")
        ai_readiness.reset()
        ai_readiness.reset(scope="page")
        ai_readiness.snapshot()
        ai_readiness.health_fields(configured=True)
        ai_readiness.note(configured=True)

    def test_recording_survives_a_broken_redactor(self, monkeypatch):
        from core import redaction

        def explode(*args, **kwargs):
            raise RuntimeError("redactor is down")

        monkeypatch.setattr(redaction, "sanitize_message", explode)
        klass = ai_readiness.record_failure(RuntimeError(f"boom {FAKE_KEY}"), model="m")
        assert klass == "other"
        assert ai_readiness.health_fields(True)["gemini_verified"] is False
        assert FAKE_KEY not in ai_readiness.snapshot()["last_error_excerpt"]

    def test_the_snapshot_is_a_copy(self):
        ai_readiness.record_success(model="m")
        state = ai_readiness.snapshot()
        state["attempts"] = 9999
        state["verified"] = False
        assert ai_readiness.snapshot()["attempts"] == 1
        assert ai_readiness.snapshot()["verified"] is True

    def test_concurrent_recording_loses_nothing(self):
        """Requests are handled on several threads; a lost update would under-report."""
        threads = []
        for _ in range(8):
            def work():
                for _ in range(50):
                    ai_readiness.record_success(model="m")

            thread = threading.Thread(target=work)
            threads.append(thread)
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert ai_readiness.snapshot()["attempts"] == 400
        assert ai_readiness.snapshot()["successes"] == 400

    def test_reset_returns_to_the_untried_state(self):
        ai_readiness.record_failure(RuntimeError("tls eof"), model="m")
        ai_readiness.reset()
        state = ai_readiness.snapshot()
        assert state["verified"] is None
        assert state["attempts"] == 0
        assert state["last_error_class"] is None
        assert state["last_error_excerpt"] == ""
        assert state["last_attempt_at"] is None


# --------------------------------------------------------------------------------------------
# 9. The agent's public surface
# --------------------------------------------------------------------------------------------


class TestAgentAccessors:
    def test_the_accessors_agree_about_configuration(self, configured_agent):
        assert configured_agent.is_gemini_ready() is True
        assert configured_agent.is_gemini_configured() is True
        assert configured_agent.gemini_status()["gemini_configured"] is True

    def test_status_and_observation_disagree_about_the_excerpt_on_purpose(
        self, configured_agent
    ):
        """`snapshot()` is for logs and admin surfaces; `health_fields()` is for the
        unauthenticated endpoint and must not carry free text."""
        configured_agent.ai_readiness.record_failure(RuntimeError(MARKER), model="m")
        assert MARKER in configured_agent.gemini_observation()["last_error_excerpt"]
        assert MARKER not in str(configured_agent.gemini_status())

    def test_is_gemini_ready_documents_that_it_only_means_configured(self):
        import agent as agent_module

        doc = agent_module.is_gemini_ready.__doc__ or ""
        assert "configured" in doc
        assert "no network I/O" in doc

    def test_an_unconfigured_agent_reports_no_key(self, monkeypatch):
        import agent as agent_module

        monkeypatch.setattr(agent_module, "load_dotenv", lambda *a, **k: None)
        monkeypatch.setenv("GEMINI_API_KEY", "")
        agent_module._init_default_gemini()
        status = agent_module.gemini_status()
        assert status["gemini_configured"] is False
        assert status["gemini_ready"] is False
        assert "GEMINI_API_KEY" in status["gemini_note"]


# --------------------------------------------------------------------------------------------
# 10. Source contract — the wiring itself, so it cannot silently come undone
# --------------------------------------------------------------------------------------------


class TestSourceContract:
    @staticmethod
    def _source(module):
        return open(module.__file__, encoding="utf-8").read()

    def test_health_publishes_the_observed_status_not_the_bare_flag(self):
        import main as main_module

        source = self._source(main_module)
        start = source.index("async def health_check")
        end = source.index("@app.", start)
        body = "\n".join(
            line
            for line in source[start:end].splitlines()
            if not line.lstrip().startswith("#")
        )
        assert "agent.gemini_status()" in body
        assert '"gemini_ready": agent.is_gemini_ready()' not in body, (
            "the bare flag must not come back: it is the misleading signal this phase removes"
        )

    def test_both_generation_call_sites_record_their_outcome(self):
        import agent as agent_module

        source = self._source(agent_module)
        assert source.count("_send_generation(") == 3, (
            "one definition plus the two send_message call sites"
        )
        assert "def _send_generation(chat_obj):" in source
        # One failure + one success recorder per generation path: _send_generation (chat,
        # both attempts) and analyze_receipt_image (vision).
        assert source.count("ai_readiness.record_failure(") == 2
        assert source.count("ai_readiness.record_success(") == 2

    def test_the_raw_exception_is_no_longer_logged_on_the_ai_paths(self):
        """F-50-2. An SDK message can quote the request it was building."""
        import agent as agent_module

        source = self._source(agent_module)
        for banned in (
            'f"Gemini API алдаа: {e}"',
            'f"Chat session send_message error, refreshing session: {send_err}"',
            'f"Зураг шинжлэхэд алдаа гарлаа: {e}"',
            'f"Alternative AI provider fallback error: {alt_err}"',
            'f"Gemini Client холболтын алдаа: {e}"',
        ):
            assert banned not in source, f"unredacted AI error logging came back: {banned}"
        assert '"details": safe_details' in source, (
            "receipt analysis returns its error text to an API caller; it must be redacted"
        )

    def test_the_receipt_path_does_not_return_raw_exception_text(self):
        import agent as agent_module

        source = self._source(agent_module)
        assert '{"is_receipt": False, "details": str(e)}' not in source

    def test_the_image_path_records_only_around_the_generation_call(self):
        """`Image.open()` failing is bad input, not a broken key, and must not be filed as
        one — otherwise a user uploading a corrupt JPEG would mark the platform AI as down."""
        import agent as agent_module

        source = self._source(agent_module)
        start = source.index("def analyze_receipt_image")
        end = source.index("def process_message", start)
        body = source[start:end]
        assert "ai_readiness.record_failure(gen_err" in body
        assert "ai_readiness.record_success(scope=ai_scope" in body
        assert body.index("img = Image.open(") < body.index("ai_readiness.record_failure(")
        assert "except Exception as gen_err:" in body

    def test_the_readiness_module_does_not_import_the_agent(self):
        """It is imported *by* agent.py; importing back would be a cycle."""
        from core import ai_readiness as module

        source = self._source(module)
        assert "import agent" not in source
        assert "import database" not in source
        assert "import main" not in source

    def test_the_published_enum_has_not_grown_without_a_decision(self):
        assert ai_readiness.ERROR_CLASSES == (
            "auth",
            "quota",
            "model",
            "network",
            "bad_request",
            "server",
            "other",
        )
        assert ai_readiness.SCOPES == ("default", "page")
