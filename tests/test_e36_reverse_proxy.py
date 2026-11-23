"""Structural checks for the reverse-proxy configuration (Phase 36).

**What this file does NOT do: it does not run `caddy validate`.** Neither Caddy nor
Docker is installed in the audit sandbox, and the Caddy release assets are served from
`release-assets.githubusercontent.com`, which is outside the sandbox's egress allowlist.
So the Caddyfile has never been parsed by Caddy itself. Anything that only real Caddy
can catch — a misspelled directive, an adapter-level error — is still unverified.

What these tests *do* catch is the class of mistake that is easy to make and expensive
to discover in production: a proxy that forgets to pass `X-Forwarded-Proto` (payment
links become `http://`), publishes the app port directly, or sends no HSTS. They are a
regression fence around the security *decisions*, not a syntax checker.

The operator must run `caddy validate --config deploy/Caddyfile --adapter caddyfile`
on the staging host before first start. That is listed in the deployment runbook.
"""

from __future__ import annotations

import os
import re

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CADDYFILE = os.path.join(REPO_ROOT, "deploy", "Caddyfile")


@pytest.fixture(scope="module")
def caddyfile() -> str:
    with open(CADDYFILE, encoding="utf-8") as handle:
        return handle.read()


def _strip_comments(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


class TestCaddyfileStructure:
    def test_file_exists(self):
        assert os.path.isfile(CADDYFILE)

    def test_braces_are_balanced(self, caddyfile):
        body = _strip_comments(caddyfile)
        assert body.count("{") == body.count("}"), "unbalanced braces in Caddyfile"

    def test_declares_a_site_block_for_a_configured_domain(self, caddyfile):
        """The site address must come from the environment, not a placeholder domain."""
        body = _strip_comments(caddyfile)
        assert "{$STAGING_DOMAIN}" in body, "domain must be env-driven, not hard-coded"
        # A bare `:80`/`:443` site block would serve plaintext; the domain form makes
        # Caddy obtain and serve a certificate automatically.
        assert re.search(r"^\{\$STAGING_DOMAIN\}\s*\{", body, re.MULTILINE)

    def test_upstream_is_the_internal_service_not_a_public_host(self, caddyfile):
        body = _strip_comments(caddyfile)
        assert "reverse_proxy web:8000" in body
        assert "localhost" not in body

    def test_passes_forwarded_proto(self, caddyfile):
        """Without this the app mints http:// payment callbacks (F-36-3)."""
        assert "X-Forwarded-Proto {http.request.scheme}" in caddyfile

    def test_passes_forwarded_for(self, caddyfile):
        assert "X-Forwarded-For {http.request.remote.host}" in caddyfile

    def test_overwrites_rather_than_appends_forwarding_headers(self, caddyfile):
        """`header_up X` replaces; `header_up X+` would append and let a client inject.

        Appending is the dangerous form: the app's chain walk would then see
        client-supplied hops ahead of the proxy's. Assert no `+` form is used.
        """
        body = _strip_comments(caddyfile)
        assert not re.search(r"header_up\s+X-Forwarded-For\+", body)
        assert not re.search(r"header_up\s+X-Forwarded-Proto\+", body)

    def test_sets_hsts(self, caddyfile):
        assert "Strict-Transport-Security" in caddyfile
        assert "max-age=31536000" in caddyfile

    def test_sets_nosniff_and_frame_options(self, caddyfile):
        assert "X-Content-Type-Options" in caddyfile
        assert "X-Frame-Options" in caddyfile

    def test_bounds_request_body_size(self, caddyfile):
        """An unbounded body is a trivial disk/memory exhaustion vector."""
        assert "max_size" in caddyfile
        match = re.search(r"max_size\s+(\d+)(MB|GB|KB)", caddyfile)
        assert match, "max_size must state a unit"
        value, unit = int(match.group(1)), match.group(2)
        megabytes = {"KB": value / 1024, "MB": value, "GB": value * 1024}[unit]
        assert megabytes <= 100, f"{megabytes}MB request bodies is too permissive"

    def test_bounds_upstream_timeouts(self, caddyfile):
        """An unbounded response timeout lets a hung upstream pin a connection."""
        for directive in ("dial_timeout", "response_header_timeout"):
            assert directive in caddyfile

    def test_does_not_disable_tls(self, caddyfile):
        """Guard against someone adding `auto_https off` to debug something."""
        body = _strip_comments(caddyfile)
        assert "auto_https off" not in body
        assert "tls internal" not in body, "internal CA is for local dev, not staging"

    def test_health_probe_answered_by_proxy(self, caddyfile):
        """A proxy-level /healthz must not consume app pool slots."""
        assert "/healthz" in caddyfile


class TestComposeExposure:
    """The app port must not stay published once a proxy exists."""

    def test_prod_compose_does_not_publish_app_port_behind_proxy(self):
        """Documented architectural intent, asserted against the prod compose file.

        The prod compose still publishes 8000 because Phase 36 does not change the
        production topology (no deployment was performed). The staging compose is the
        one that must be proxy-only, and that is asserted below. This test records the
        distinction so the two files are not confused later.
        """
        import yaml

        with open(os.path.join(REPO_ROOT, "docker-compose.staging.yml"), encoding="utf-8") as h:
            staging = yaml.safe_load(h)

        web = staging["services"]["web"]
        assert "ports" not in web, (
            "staging must not publish the app port; Caddy reaches it over the "
            "internal network only"
        )

    def test_staging_publishes_only_the_proxy(self):
        import yaml

        with open(os.path.join(REPO_ROOT, "docker-compose.staging.yml"), encoding="utf-8") as h:
            staging = yaml.safe_load(h)

        published = {
            name: svc.get("ports")
            for name, svc in staging["services"].items()
            if svc.get("ports")
        }
        assert set(published) == {"proxy"}, (
            f"only the proxy may publish host ports, found: {sorted(published)}"
        )
