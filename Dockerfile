FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install postgresql-client for pg_dump/psql backup & restore support and create non-root user
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r gerege && useradd -r -g gerege -d /app gerege

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
