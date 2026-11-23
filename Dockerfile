# Phase 36: the base image is parameterised so it can be pinned by digest without
# editing this file.
#
# `python:3.12-slim` is a MUTABLE tag: the same Dockerfile can build against a different
# slim layer next week, so "it built yesterday" says nothing about today. Phase 35 rated
# that Medium.
#
# Why the default is still a tag rather than a digest: the digest could not be resolved
# from the audit environment (Docker Hub is outside the egress allowlist) and a fabricated
# digest makes `FROM` unpullable, which breaks the CI image build outright - strictly worse
# than the mutable tag it was meant to fix. An earlier attempt at a placeholder digest did
# exactly that and failed CI, which is how this was caught.
#
# Pin it at build time, with no file edit:
#
#   docker buildx imagetools inspect python:3.12-slim --format '{{.Manifest.Digest}}'
#   docker build --build-arg BASE_IMAGE=python:3.12-slim@sha256:<digest> -t gerege .
#
# `tests/test_e36_lock.py` xfails while the default is a tag, so the gap stays visible and
# turns green once the default is pinned.
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install postgresql-client for pg_dump/psql backup & restore support and create non-root user
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r gerege && useradd -r -g gerege -d /app gerege

# Phase 36: install from the locked set of exact versions, not the ranges.
#
# `requirements.txt` allows `fastapi>=0.115.0,<1.0.0`, so two builds of one commit could
# ship different code. `requirements.lock` pins all 46 packages in the transitive closure
# to the versions that pass the suite in CI, so a rebuild installs the same code.
#
# `--require-hashes` is deliberately NOT used here. It was, and it broke this build: the
# lock's hashes were generated on CPython 3.11 (cp311 wheels) while this image is 3.12,
# and pip refuses any wheel whose hash is not listed — so nothing was installable. See the
# header of requirements.lock for the full explanation and the command that regenerates
# hashes on the correct interpreter. Reproducible by *version* today; hash-verified once
# that is done.
COPY requirements.lock .
RUN pip install --no-cache-dir --no-deps -r requirements.lock

# requirements.txt is still copied for the dev/test path and for auditability; the
# production layer above does not read it.
COPY requirements.txt requirements-dev.txt ./

COPY . .

RUN mkdir -p /app/static/qrcodes /app/backups && \
    python -c "import database; database.init_db()" && \
    chown -R gerege:gerege /app

USER gerege

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ready', timeout=4)" || exit 1

# E-02 Phase 3: `--no-proxy-headers` is load-bearing, not cosmetic.
#
# With uvicorn's default (`--proxy-headers` on, trusting 127.0.0.1/::1) any request whose
# TCP peer is inside the container network has `scope["client"]` overwritten from
# `X-Forwarded-For` — port forced to 0, right-most entry, no validation. The application
# then cannot tell the real peer from a forged one, and its trusted-proxy policy would be
# built on a value an attacker controls.
#
# Disabling it keeps `scope["client"]` as the actual socket peer. Forwarding is then
# handled in exactly one place, `core.rate_limit.resolve_client_ip()`, governed by
# TRUSTED_PROXIES (empty by default = trust nothing).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-proxy-headers"]
