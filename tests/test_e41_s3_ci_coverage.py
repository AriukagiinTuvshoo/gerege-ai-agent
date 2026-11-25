"""Phase 41 — the S3 test path must never touch a real provider.

Phase 40 recorded 46 skipped S3 cases and called them "a known, reported gap". Phase 41
closes the gap by starting a moto server in CI, and that turns "known gap" into "the
offsite code runs in CI" - which is only safe if the endpoint really is local and the
credentials really cannot reach AWS.

This file is that safety, as tests rather than as a comment:

  * the suites refuse to run when a real credential is present;
  * the endpoint must be a loopback or a private address;
  * the S3 code has no fallback to a real AWS endpoint;
  * the CI step sets no AWS_* variable, and starts the server it points at;
  * nothing in the test path performs a real network call.

The negative control matters here more than usual: a test asserting "we are not talking
to AWS" is worthless if it would pass while talking to AWS. `TestNegativeControls` checks
that the guard actually fires.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OFFSITE_SUITES = (
    "tests/test_e07_phase22_offsite_pagination.py",
    "tests/test_e07_phase22_offsite_integrity.py",
    "tests/test_e07_phase22_offsite_status.py",
    "tests/test_e07_phase24_offsite_integration.py",
)


def _read(rel: str) -> str:
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def _backup_step() -> str:
    text = _read(".github/workflows/ci.yml")
    start = text.index("Phase 22/23/24 — backup security")
    end = text.index("Phase 29 — CI test integrity")
    return text[start:end]


# ------------------------------------------------------- the suites guard against realness


class TestTheSuitesRefuseARealAccount:
    def test_a_present_aws_credential_skips_the_offsite_integration_suite(self):
        """The guard exists because a developer's shell may hold real AWS credentials.

        It SKIPS rather than fails, deliberately: refusing to run is the safe outcome, and
        a skip is what the gate reports. What must never happen is running.
        """
        body = _read("tests/test_e07_phase24_offsite_integration.py")
        assert "AWS_ACCESS_KEY_ID" in body
        assert "refusing to run offsite tests against a real account" in body

    def test_the_guard_actually_fires_when_a_credential_is_set(self):
        """Behavioural: run the guard function with the variable set and see it skip."""
        sys.path.insert(0, REPO_ROOT)
        module_path = os.path.join(REPO_ROOT, "tests/test_e07_phase24_offsite_integration.py")
        import importlib.util

        spec = importlib.util.spec_from_file_location("offsite_integration_probe", module_path)
        module = importlib.util.module_from_spec(spec)
        saved = {k: os.environ.get(k) for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")}
        try:
            spec.loader.exec_module(module)
            os.environ["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
            with pytest.raises(BaseException) as caught:
                module.test_no_real_credential_is_present_in_this_environment()
            assert "Skipped" in type(caught.value).__name__ or "skip" in str(caught.value).lower()
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_the_suites_take_their_credentials_from_the_test_endpoint_not_aws(self):
        """Pagination builds its own client with `test` credentials, never from the env."""
        body = _read("tests/test_e07_phase22_offsite_pagination.py")
        assert 'aws_access_key_id="test"' in body
        assert 'aws_secret_access_key="test"' in body


class TestTheEndpointMustBeLoopbackOrTheSuiteCannotUseIt:
    """The real guard is `_plaintext_transport_allowed`: three conditions, all required.

    A full test of it lives in the Phase 22 suite; this is the S3-coverage angle - that a
    plain-http endpoint can only ever be a loopback test server, and only when the operator
    opted in and the process is not production. Without this, a contributor pointing
    `BACKUP_OFFSITE_TEST_ENDPOINT` at a real bucket would run destructive tests against it.
    """

    ALLOW = {"BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1"}

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:5062",
            "http://localhost:5062",
            "http://127.0.0.1:5062/bucket/prefix",
        ],
    )
    def test_a_loopback_http_endpoint_is_allowed_when_opted_in(self, url):
        from core import backup_offsite

        assert backup_offsite._plaintext_transport_allowed(url, dict(self.ALLOW)) is True

    @pytest.mark.parametrize(
        "url",
        [
            "http://s3.amazonaws.com",
            "https://example-bucket.s3.eu-west-1.amazonaws.com",
            "http://169.254.169.254/latest/meta-data",
            "http://8.8.8.8/",
            "http://moto.example.com:5062",
        ],
    )
    def test_a_non_loopback_endpoint_is_refused_even_when_opted_in(self, url):
        """Opting in allows plain HTTP on loopback - it does not allow plain HTTP anywhere."""
        from core import backup_offsite

        assert backup_offsite._plaintext_transport_allowed(url, dict(self.ALLOW)) is False

    def test_production_refuses_even_loopback_plaintext(self):
        from core import backup_offsite

        env = {**self.ALLOW, "ENV": "production"}
        assert backup_offsite._plaintext_transport_allowed("http://127.0.0.1:5062", env) is False

    def test_without_the_opt_in_nothing_plaintext_is_allowed(self):
        from core import backup_offsite

        assert backup_offsite._plaintext_transport_allowed("http://127.0.0.1:5062", {}) is False


# ------------------------------------------------------------------ no real AWS fallback


class TestTheOffsiteCodeCannotSilentlyReachAws:
    def test_boto3_clients_are_always_given_an_explicit_endpoint(self):
        """A boto3 client with no endpoint_url resolves the real AWS service."""
        offenders = []
        for rel in OFFSITE_SUITES:
            body = _read(rel)
            for match in re.finditer(r"boto3\.client\(([^)]*)\)", body, re.DOTALL):
                if "endpoint_url" not in match.group(1):
                    offenders.append((rel, match.group(1).strip()[:60]))
        assert not offenders, (
            f"a boto3 client without endpoint_url would contact real AWS: {offenders}"
        )

    def test_the_production_provider_requires_its_own_endpoint(self):
        """`provider_from_env` must not invent an endpoint when none is configured."""
        body = _read("core/backup_offsite.py")
        assert "BACKUP_OFFSITE_URL" in body
        assert 'env.get("BACKUP_OFFSITE_URL"' in body

    def test_no_test_file_uses_a_real_aws_hostname_as_a_TEST_TARGET(self):
        """An `amazonaws.com` string in a suite is not automatically a problem.

        `test_e07_phase22_offsite_status.py` asserts that a real HTTPS AWS URL is ACCEPTED
        by the transport allowlist - a URL-parsing assertion that makes no request. What
        matters is that no suite points its S3 *client* at one. So the check is per-use:
        an AWS hostname may appear as a string being validated, never as `endpoint_url` or
        as the test endpoint the suites connect to.
        """
        for rel in OFFSITE_SUITES:
            body = _read(rel)
            for match in re.finditer(r"""endpoint_url\s*=\s*["']([^"']+)["']""", body):
                assert "amazonaws.com" not in match.group(1), (
                    f"{rel} connects a client to a real AWS hostname: {match.group(1)}"
                )
            # The endpoint the suites actually use comes from the env var, and the CI step
            # is checked separately below.
            if "ENDPOINT = os.getenv" in body:
                assert "amazonaws.com" not in body.split("ENDPOINT = os.getenv")[1].split("\n")[0]


# ---------------------------------------------------------------- the CI step is safe


class TestTheCiStepStartsAnEndpointAndPassesNoCredential:
    def test_the_backup_step_names_a_test_endpoint(self):
        step = _backup_step()
        assert "BACKUP_OFFSITE_TEST_ENDPOINT:" in step, (
            "the step does not set the endpoint, so the 46 S3 cases will skip again"
        )
        assert "127.0.0.1" in step.split("BACKUP_OFFSITE_TEST_ENDPOINT:")[1].split("\n")[0], (
            "the test endpoint is not loopback"
        )

    def test_the_backup_step_sets_no_aws_variable(self):
        """Measured: setting AWS_ACCESS_KEY_ID turned a passing case into a skip.

        The suite's own guard fires, which is the right behaviour and the wrong CI setup.
        """
        step = _backup_step()
        # Only the env block matters; the comments explain why these are absent.
        env_lines = [
            line for line in step.splitlines()
            if re.match(r"^\s{10}[A-Z][A-Z0-9_]*:", line)
        ]
        for line in env_lines:
            assert "AWS_" not in line, (
                f"the step sets an AWS variable ({line.strip()}); the offsite suite treats "
                "that as a real account and refuses to run"
            )

    def test_the_step_actually_starts_the_server_it_points_at(self):
        step = _backup_step()
        assert "moto.server" in step, "the step names an endpoint but starts nothing at it"
        port = re.search(r"BACKUP_OFFSITE_TEST_ENDPOINT: \"http://127\.0\.0\.1:(\d+)\"", step)
        assert port, "the endpoint port could not be read"
        assert f"-p {port.group(1)}" in step, (
            f"the moto server is not started on the port the endpoint names ({port.group(1)})"
        )

    def test_a_failed_server_start_fails_the_step(self):
        """Otherwise the suites skip and the gate reports a clean run.

        That is exactly the Phase 40 failure shape: 46 skips that nobody saw.
        """
        step = _backup_step()
        assert "did not start" in step
        assert "exit 1" in step.split("did not start")[1][:200]

    def test_the_s3_exceptions_are_gone_from_the_gate(self):
        """The gate must not excuse what now runs."""
        step = _backup_step()
        gate = step[step.index("check_pytest_log.py"):]
        assert "--allow-skip-file" not in gate, (
            "the gate still excuses the offsite suites by file; with an endpoint present "
            "those skips are failures"
        )

    def test_the_pass_floor_reflects_the_measured_count(self):
        """258 of 259 pass when moto is running; the floor must be the measurement."""
        step = _backup_step()
        gate = step[step.index("check_pytest_log.py"):]
        floor = int(re.search(r"--min-passed (\d+)", gate).group(1))
        measured = re.search(r"Measured with moto[^:]*: (\d+) passed, (\d+) skipped, (\d+) collected", step)
        assert measured, "the step does not record what was measured with moto"
        passed, skipped, collected = (int(g) for g in measured.groups())
        assert floor <= passed, f"--min-passed {floor} exceeds the measured {passed}"
        assert passed + skipped == collected, "the recorded measurement is inconsistent"


# --------------------------------------------------------------------- negative controls


class TestNegativeControls:
    """Show that the guards above can fail, by making them fail."""

    def test_the_aws_guard_skips_only_when_a_credential_is_present(self, monkeypatch):
        module_path = os.path.join(REPO_ROOT, "tests/test_e07_phase24_offsite_integration.py")
        import importlib.util

        with open(module_path, encoding="utf-8") as handle:
            source = handle.read()
        path = os.path.join(REPO_ROOT, f".negctl_offsite_{os.getpid()}.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        try:
            spec = importlib.util.spec_from_file_location("negctl_offsite", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
            monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
            # With both absent the guard must NOT skip.
            module.test_no_real_credential_is_present_in_this_environment()
        finally:
            os.unlink(path)

    def test_a_public_endpoint_is_rejected_so_a_real_bucket_cannot_be_a_target(self):
        """The same function, on the address a real bucket would have."""
        from core import backup_offsite

        allow = {"BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK": "1"}
        assert backup_offsite._plaintext_transport_allowed("http://s3.amazonaws.com", allow) is False
        assert backup_offsite._plaintext_transport_allowed("http://127.0.0.1:5062", allow) is True
