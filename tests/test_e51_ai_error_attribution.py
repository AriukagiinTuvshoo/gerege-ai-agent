"""Phase 51 — F-51-4: a database error used to announce itself as an AI outage.

`AIAgent.process_message` wraps one `try:` block around ~260 lines that do three unrelated
kinds of work:

    if client:
        try:
            from google.genai import types        # <- context: tool definitions, database
            ...                                    #    and memory reads, sheet lookup
            response = _send_generation(chat)      # <- generation: the provider call
            ...
            eval_res = ai_router.evaluate_ai_response(reply_text, page_id=page_id)
            ...                                    # <- post-processing: payment order, token
            database.increment_page_tokens(...)    #    accounting, registration, message log
            return {...}
        except Exception as e:
            logger.error("Gemini API алдаа: %s", ai_readiness.redacted(e))

So every failure in that block was reported as a Gemini failure. An operator chasing an AI
outage was handed database errors, and a database error announced itself as an AI outage — in
a system where `/api/chat` degrades to a deterministic reply, "the AI is down" is the first
thing anybody concludes. Phase 50 made this line redacted (F-50-2) and gave the AI a truthful
readiness signal (F-50-1), but left the label, deliberately, to keep the change small; this
closes it.

The fix tracks a `phase` and keeps the historical string for the phase it belongs to:

    phase = "context"                     # before the try, so the handler cannot see it unbound
    ...
    phase = "generation"                  # session creation and the generation call
    ...
    phase = "post-processing"             # the reply exists; everything below is local work
    ...
    if phase == "generation":
        logger.error("Gemini API алдаа: %s", detail)
    else:
        logger.error("Chat алдаа — шат: %s (Gemini API биш): %s", phase, detail)

Control flow is unchanged: every phase still falls through to the alternative providers and
then to the deterministic reply. What changed is the attribution, and one property that
matters more than the wording — a post-processing failure must not touch the AI readiness
verdict, because the generation call genuinely succeeded (`record_success` already ran).
Before this, the two were reported by the same log line and were indistinguishable.

These tests drive the real `process_message` with a fake provider client and stubbed
database calls, so they need no API key, no network and no database.
"""

import io
import logging
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import agent as agent_module  # noqa: E402
import database  # noqa: E402
import sheets_service  # noqa: E402
from core import ai_readiness, ai_router  # noqa: E402

#: A distinctive marker so an assertion can tell "the failure was logged" from "some other
#: error happened to be logged".
MARKER = "e51-distinctive-failure-marker-8842"

#: A synthetic credential. `core/redaction.collect_secret_values()` learns literals from the
#: environment, so the redaction test below sets GEMINI_API_KEY to this value.
FAKE_KEY = "e51-fake-gemini-key-6b2d94f1"

BENIGN_TEXT = "Сайн байна уу? Танай бүтээгдэхүүний талаар мэдээлэл өгнө үү."


class _FakeResponse:
    def __init__(self, text):
        self.text = text
        self.usage_metadata = None


class _FakeChat:
    """Stands in for `google.genai`'s chat object."""

    def __init__(self, mode):
        self.mode = mode
        self.sent = []

    def send_message(self, payload):
        self.sent.append(payload)
        if self.mode == "raise":
            raise RuntimeError(f"simulated provider failure {MARKER}")
        if self.mode == "raise-with-key":
            raise RuntimeError(f"400 API key not valid: {FAKE_KEY} {MARKER}")
        return _FakeResponse("Сайн байна уу! Танд юугаар туслах вэ?")


class _FakeChats:
    def __init__(self, mode):
        self.mode = mode
        self.created = 0

    def create(self, model=None, config=None):
        self.created += 1
        return _FakeChat(self.mode)


class _FakeClient:
    def __init__(self, mode="ok"):
        self.mode = mode
        self.chats = _FakeChats(mode)


PAGE = {
    "page_id": "p51-attribution",
    "name": "Атрибуцийн тест",
    "category": "general",
    "monthly_token_limit": 100000,
    "tokens_used": 0,
    "gemini_api_key": "",
    "verify_token": "e51-not-the-published-one",
    "is_active": 1,
}


@pytest.fixture(autouse=True)
def _clean_readiness():
    """The observed AI state is process-global; leave it as this test found it."""
    ai_readiness.reset()
    ai_readiness.reset(scope="page")
    yield
    ai_readiness.reset()
    ai_readiness.reset(scope="page")


@pytest.fixture()
def chat_env(monkeypatch):
    """Drive the AI branch of `process_message` with no provider, network or database."""
    calls = []

    def _record(name):
        def _stub(*args, **kwargs):
            calls.append(name)
            return None

        return _stub

    monkeypatch.setattr(database, "get_page", lambda _page_id: dict(PAGE))
    monkeypatch.setattr(database, "log_message", _record("log_message"))
    monkeypatch.setattr(database, "is_session_human_takeover", lambda *a, **k: False)
    monkeypatch.setattr(database, "get_user_memory", lambda *a, **k: None)
    monkeypatch.setattr(database, "increment_page_tokens", _record("increment_page_tokens"))
    monkeypatch.setattr(database, "save_registration", lambda **k: 1)
    monkeypatch.setattr(database, "upsert_user_memory", _record("upsert_user_memory"))
    monkeypatch.setattr(database, "record_audit_log", _record("record_audit_log"))
    monkeypatch.setattr(sheets_service, "get_page_sheets_lookup_context", lambda *a, **k: "")
    monkeypatch.setattr(ai_router, "format_persistent_conversation_context", lambda *a, **k: "")
    # One attempt, no retry, no circuit breaker: the breaker is shared process state and a
    # test that trips it would decide the outcome of every later test that calls a provider.
    monkeypatch.setattr(ai_router, "execute_with_retry", lambda func, **kwargs: func())
    monkeypatch.setattr(ai_router, "call_openai_compatible_fallback", lambda *a, **k: None)
    monkeypatch.setattr(ai_router, "call_anthropic_fallback", lambda *a, **k: None)
    monkeypatch.setattr(agent_module, "build_system_instruction_for_page", lambda *a, **k: "SYS")
    monkeypatch.setattr(agent_module.agent, "chat_sessions", {})

    state = {"client": _FakeClient("ok"), "calls": calls}
    monkeypatch.setattr(
        agent_module.agent,
        "get_client_for_page",
        lambda page_data: (state["client"], False),
    )
    return state


def _process():
    return agent_module.process_message(
        text=BENIGN_TEXT,
        sender_id="e51_attribution_user",
        channel="web",
        page_id=PAGE["page_id"],
    )


def _errors(caplog):
    return "\n".join(r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)


# --------------------------------------------------------------------------------------
# 1. The label follows the phase that actually failed
# --------------------------------------------------------------------------------------


class TestTheLabelNamesThePhaseThatFailed:
    def test_a_provider_failure_is_still_labelled_a_gemini_error(self, chat_env, caplog):
        """The historical string stays for the case it always described, so log greps hold."""
        chat_env["client"] = _FakeClient("raise")
        with caplog.at_level(logging.ERROR):
            result = _process()
        logged = _errors(caplog)
        assert "Gemini API алдаа" in logged
        assert MARKER in logged, "the diagnostic itself must survive"
        assert "шат:" not in logged, "a generation failure must not be reported as a phase"
        assert isinstance(result, dict) and result.get("reply") is not None, (
            "control flow is unchanged: the caller still gets a reply"
        )

    def test_a_database_failure_after_the_reply_is_not_a_gemini_error(
        self, chat_env, monkeypatch, caplog
    ):
        """The reply existed. Token accounting is a local write, not a provider call."""
        def _boom(*args, **kwargs):
            raise RuntimeError(f"simulated database failure {MARKER}")

        chat_env["client"] = _FakeClient("ok")
        monkeypatch.setattr(database, "increment_page_tokens", _boom)
        with caplog.at_level(logging.ERROR):
            _process()
        logged = _errors(caplog)
        assert "Gemini API алдаа" not in logged, (
            "a database write failure was reported as an AI outage — that is F-51-4"
        )
        assert "post-processing" in logged
        assert MARKER in logged

    def test_a_context_failure_is_labelled_context(self, chat_env, monkeypatch, caplog):
        """A read that happens before the provider is ever called."""
        def _boom(*args, **kwargs):
            raise RuntimeError(f"simulated context failure {MARKER}")

        monkeypatch.setattr(database, "get_user_memory", _boom)
        with caplog.at_level(logging.ERROR):
            _process()
        logged = _errors(caplog)
        assert "Gemini API алдаа" not in logged
        assert "context" in logged
        assert MARKER in logged

    def test_a_provider_failure_is_not_labelled_as_something_else(self, chat_env, caplog):
        """The converse of the two above: the phases must not blur into each other."""
        chat_env["client"] = _FakeClient("raise")
        with caplog.at_level(logging.ERROR):
            _process()
        logged = _errors(caplog)
        assert "post-processing" not in logged
        assert "Chat алдаа — шат: context" not in logged


# --------------------------------------------------------------------------------------
# 2. The property that matters more than the wording
# --------------------------------------------------------------------------------------


class TestTheReadinessVerdictFollowsTheGenerationCallOnly:
    def test_a_generation_failure_is_recorded(self, chat_env):
        chat_env["client"] = _FakeClient("raise")
        _process()
        snapshot = ai_readiness.snapshot()
        assert snapshot["failures"] >= 1
        assert snapshot["successes"] == 0
        assert snapshot["last_error_class"] is not None

    def test_a_post_processing_failure_does_not_condemn_the_ai(self, chat_env, monkeypatch):
        """The generation call succeeded, so the key is proven to work. A database error
        must not turn that into `gemini_verified: false` — that is the F-50-1 signal an
        operator reads, and it would send them to their AI billing instead of their disk.

        `verified` is the field `/api/health` publishes as `gemini_verified`; the assertion
        is on the observation, not on `is_gemini_ready()`, which reports *configuration* and
        is False in a test run that configured no key at all.
        """
        def _boom(*args, **kwargs):
            raise RuntimeError(f"simulated database failure {MARKER}")

        chat_env["client"] = _FakeClient("ok")
        monkeypatch.setattr(database, "increment_page_tokens", _boom)
        _process()

        snapshot = ai_readiness.snapshot()
        assert snapshot["successes"] == 1, "the generation call did succeed"
        assert snapshot["failures"] == 0
        assert snapshot["last_error_class"] is None
        assert snapshot["verified"] is True, "the AI must stay verified despite the DB error"
        assert agent_module.gemini_status()["gemini_verified"] is True

    def test_a_context_failure_does_not_condemn_the_ai_either(self, chat_env, monkeypatch):
        def _boom(*args, **kwargs):
            raise RuntimeError(f"simulated context failure {MARKER}")

        monkeypatch.setattr(database, "get_user_memory", _boom)
        _process()

        snapshot = ai_readiness.snapshot()
        assert snapshot["attempts"] == 0, "no generation call was ever made"
        assert snapshot["verified"] is None, "never attempted is not 'broken'"
        assert snapshot["last_error_class"] is None


# --------------------------------------------------------------------------------------
# 3. Redaction still applies at this site (F-50-2 regression)
# --------------------------------------------------------------------------------------


class TestTheLabelNeverCarriesASecret:
    def test_a_credential_in_the_provider_error_is_scrubbed(self, chat_env, monkeypatch, caplog):
        monkeypatch.setenv("GEMINI_API_KEY", FAKE_KEY)
        chat_env["client"] = _FakeClient("raise-with-key")
        with caplog.at_level(logging.ERROR):
            _process()
        logged = _errors(caplog)
        assert MARKER in logged, "the diagnosis must survive the scrubbing"
        assert FAKE_KEY not in logged
        assert "[REDACTED]" in logged

    def test_the_label_is_one_line(self, chat_env, caplog):
        """A multi-line exception must not become a multi-line log record."""
        chat_env["client"] = _FakeClient("raise")
        with caplog.at_level(logging.ERROR):
            _process()
        for record in caplog.records:
            if "Gemini API алдаа" in record.getMessage():
                assert "\n" not in record.getMessage()


# --------------------------------------------------------------------------------------
# 4. Source contract
# --------------------------------------------------------------------------------------


class TestTheSourceContract:
    def _code(self):
        body = io.open(os.path.join(REPO_ROOT, "agent.py"), encoding="utf-8").read()
        return body

    def test_the_phase_is_initialised_before_the_try(self):
        """Otherwise the handler itself can raise UnboundLocalError on an import failure.

        The first statement inside the try is `from google.genai import types`, so an
        uninstalled SDK would reach the handler with `phase` never bound — the diagnostic
        would replace one failure with a second, unrelated one.
        """
        code = self._code()
        init = code.index('phase = "context"')
        handler = code.index('if phase == "generation":')
        assert init < handler
        enclosing_try = code.index("\n            try:\n", init)
        assert init < enclosing_try < handler, (
            "the initialisation must sit between `if client:` and the try it reports on"
        )

    def test_all_three_phases_are_assigned_in_order(self):
        code = self._code()
        positions = [
            code.index('phase = "context"'),
            code.index('phase = "generation"'),
            code.index('phase = "post-processing"'),
        ]
        assert positions == sorted(positions), "the phases must advance, not jump back"

    def test_the_historical_label_is_kept_for_the_generation_phase(self):
        code = self._code()
        assert 'if phase == "generation":' in code
        assert code.count('logger.error("Gemini API алдаа: %s"') == 1

    def test_the_other_phases_are_named_in_the_log(self):
        code = self._code()
        assert "(Gemini API биш)" in code, (
            "a non-AI failure must say so explicitly; silence invites the old reading"
        )
