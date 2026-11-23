#!/usr/bin/env python3
"""Structural validation of deploy/Caddyfile (Phase 37).

**This is not `caddy validate`.** Caddy is not installed in the audit environment, no Go
toolchain is available to build it, and Docker Hub is outside the egress allowlist, so the
Caddyfile has never been parsed by Caddy itself. A real `caddy validate` remains a required
staging gate (see docs/deployment/STAGING_DEPLOYMENT.md).

What this script does is catch the class of mistake that actually happened: Phase 36's
Caddyfile repeated `format` inside one `log` block, which the documentation states is an
error, and the proxy would have refused to start. That defect was invisible to every test
because the tests asserted that strings were present rather than that the structure was
legal.

It checks only rules that are stated in Caddy's own directive documentation and that can be
determined without running Caddy:

  * balanced braces (outside comments and quoted strings)
  * at most one occurrence of each single-value `log` subdirective
  * `header` blocks that set values also set `defer`, or use an explicit prefix
  * no `:80`-only site address that would serve plaintext
  * the reverse_proxy upstream is an internal service, not a host

Exit codes: 0 clean, 1 problems found, 2 the file could not be read.
"""

from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CADDYFILE = os.path.join(REPO_ROOT, "deploy", "Caddyfile")

#: Subdirectives that Caddy permits at most once per `log` block.
#: Docs: "Other than `hostnames`, each subdirective may only be specified once per `log`
#: block (and each `sampling` option once per `sampling` block); repeating one is an error."
LOG_SINGLE_VALUE = ("output", "format", "level", "no_hostname")

#: Header prefixes that set or delete rather than silently overwrite.
HEADER_SAFE_PREFIXES = ("+", "-", "?", ">")


def strip_comments(text: str) -> str:
    """Remove `#` comments without touching `#` inside quoted values."""
    out = []
    for line in text.splitlines():
        in_quote = False
        cut = len(line)
        for index, char in enumerate(line):
            if char == '"':
                in_quote = not in_quote
            elif char == "#" and not in_quote:
                cut = index
                break
        out.append(line[:cut])
    return "\n".join(out)


def find_block(text: str, start_marker: str) -> str:
    """Return the text of the brace block that follows ``start_marker``."""
    start = text.index(start_marker)
    open_brace = text.index("{", start)
    depth = 0
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:index]
    return text[open_brace + 1:]


def check() -> list:
    problems = []
    try:
        with open(CADDYFILE, encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as exc:
        print(f"cannot read {CADDYFILE}: {exc}", file=sys.stderr)
        raise SystemExit(2)

    text = strip_comments(raw)

    if text.count("{") != text.count("}"):
        problems.append(
            f"unbalanced braces: {text.count('{')} open, {text.count('}')} close"
        )

    if "$STAGING_DOMAIN" not in text:
        problems.append("the site address is not driven by $STAGING_DOMAIN")
    if re.search(r"^\s*:80\s*\{", text, re.MULTILINE):
        problems.append("a :80-only site block would serve plaintext")
    if "auto_https off" in text:
        problems.append("auto_https is disabled, so no certificate is obtained")
    if "tls internal" in text:
        problems.append("tls internal uses a private CA, unsuitable for staging")

    if "log {" in text:
        block = find_block(text, "log {")
        for name in LOG_SINGLE_VALUE:
            count = len(re.findall(rf"^\s*{name}\b", block, re.MULTILINE))
            if count > 1:
                problems.append(
                    f"`log` block declares `{name}` {count} times; Caddy rejects a "
                    f"repeated subdirective (only `hostnames` may repeat)"
                )

    if "header {" in text:
        block = find_block(text, "header {")
        has_defer = re.search(r"^\s*defer\s*$", block, re.MULTILINE) is not None
        # A line like `Field "value"` with no prefix silently overwrites the upstream
        # value; `?Field`, `+Field`, `-Field` and `>Field` do not.
        bare_sets = [
            line.strip() for line in block.splitlines()
            if line.strip()
            and not re.match(r"^\s*(defer|match)\b", line)
            and not line.strip().startswith(HEADER_SAFE_PREFIXES)
            and not line.strip().startswith("#")
        ]
        if bare_sets and not has_defer:
            problems.append(
                "the `header` block sets headers without `defer`; a bare `field value` "
                f"overwrites the application's value (offending lines: {bare_sets})"
            )

    if "reverse_proxy" in text:
        upstreams = re.findall(r"reverse_proxy\s+(\S+)", text)
        for upstream in upstreams:
            if upstream.startswith(("http://", "https://")):
                host = re.sub(r"^https?://", "", upstream)
            else:
                host = upstream
            if host.split(":")[0] in ("localhost", "127.0.0.1"):
                problems.append(
                    f"upstream {upstream!r} points at this container, not the app service"
                )

    if "X-Forwarded-Proto" not in raw:
        problems.append(
            "X-Forwarded-Proto is not forwarded; the app would mint http:// payment URLs"
        )

    return problems


def main() -> int:
    problems = check()
    if problems:
        print(f"{CADDYFILE}: {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"{CADDYFILE}: structural checks passed (NOT a substitute for `caddy validate`)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
