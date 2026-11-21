"""
Stage D — SEC-03 / P2-04: no Content-Security-Policy and no HSTS.

`dashboard.html` renders tenant data and loads four third-party origins. With no CSP, a
compromised CDN — or any stored XSS reachable through a lead name or message body —
executes with the operator's session.

These tests pin the two behaviours that matter and are easy to get wrong:

* HSTS is emitted **only** in production. Sending it from a local HTTP dev server pins
  `localhost` to HTTPS in the developer's browser for a year.
* The headers are present on **error** responses too. That path is written separately and
  is exactly where security headers are usually lost.
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import security as core_security  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = tmp_path / "hdr.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.setattr(database, "DB_PATH", str(db))
    database.init_db()
    import main

    return TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture()
def prod_mode(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://app.example.mn")
    return True


def test_csp_is_present_in_production(client, prod_mode):
    r = client.get("/api/health")
    csp = r.headers.get("Content-Security-Policy")
    assert csp, "production responses must carry a Content-Security-Policy"
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_hsts_present_in_production(client, prod_mode):
    r = client.get("/api/health")
    hsts = r.headers.get("Strict-Transport-Security", "")
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts


def test_hsts_absent_on_http_dev(client, monkeypatch):
    """HSTS in dev would pin localhost to HTTPS for a year — never send it."""
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("STRICT_SECURITY", raising=False)
    r = client.get("/api/health")
    assert "Strict-Transport-Security" not in r.headers, (
        "HSTS must not be sent outside production"
    )
    # The CSP is unconditional: it is useful in every environment.
    assert "Content-Security-Policy" in r.headers


def test_existing_headers_are_preserved(client, prod_mode):
    r = client.get("/api/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_headers_present_on_error_responses(client, prod_mode):
    """The 500 path is written separately; it must not silently drop the headers."""
    import main

    original = database.get_page
    database.get_page = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    try:
        r = client.get("/api/pages")
    finally:
        database.get_page = original
    assert r.status_code >= 400
    assert "Content-Security-Policy" in r.headers, "error responses must carry the CSP"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Request-ID")


def test_csp_names_only_real_third_party_origins():
    """
    No wildcard script source: a CDN compromise is the scenario CSP bounds, so the policy
    names hosts rather than trusting everything.
    """
    policy = core_security.build_content_security_policy()
    script_src = next(
        part for part in policy.split("; ") if part.startswith("script-src")
    )
    assert "https://" in script_src, "expected explicit CDN origins"
    for wildcard in ("*", "https:", "http:", "data:"):
        tokens = script_src.split()
        assert wildcard not in tokens[1:], f"{wildcard!r} must not appear in script-src"


def test_csp_does_not_grant_frame_ancestors():
    policy = core_security.build_content_security_policy()
    assert "frame-ancestors 'none'" in policy, "clickjacking must stay blocked"
