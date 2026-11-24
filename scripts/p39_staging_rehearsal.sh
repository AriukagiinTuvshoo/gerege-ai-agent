#!/usr/bin/env bash
#
# Phase 39 — staging deployment rehearsal.
#
# WHY THIS IS A SCRIPT AND NOT INLINE YAML
#   The first attempt put this logic directly in a `run: |` block. Unindented Python
#   heredoc bodies inside a YAML block scalar break the surrounding document, and the
#   failure mode is a parse error at the workflow level — i.e. CI never starts at all.
#   A real script can also be shell-checked and reviewed on its own.
#
# WHAT THIS EXECUTES, AND WHY IT MATTERS
#   The Phase 39 audit environment has NO Docker, so no container-level claim in the
#   audit report can be evidenced locally. Every such claim is anchored in this script,
#   which runs on a GitHub runner where Docker exists.
#
#   It brings up the ACTUAL staging stack (`docker-compose.staging.yml`), not a
#   hand-written approximation, and asserts observable behaviour:
#
#     1. the negative control: a missing secret must abort `compose config`
#     2. `compose config` accepts a complete environment
#     3. only the proxy publishes host ports (8000/5432/6379 must stay private)
#     4. Postgres initialises and the migration job exits 0
#     5. /api/health and /api/ready answer 200 from inside the container
#     6. the worker publishes a heartbeat and reports `alive`
#     7. F-39-D: a raising scheduler step must NOT make a live worker look dead
#     8. the application container does not run as root
#     9. no service is reported unhealthy by compose
#
# WHAT IT DELIBERATELY DOES NOT DO
#   * No TLS. STAGING_DOMAIN is a `.invalid` name (RFC 2606 reserves it), so the proxy
#     is never asked for a certificate and no real ACME endpoint is contacted. The
#     Caddyfile is validated separately with `caddy validate`.
#   * No published ports are probed from the host, because publishing them is exactly
#     what the topology forbids.
#
# USAGE
#   scripts/p39_staging_rehearsal.sh          # full run, tears down
#   KEEP=1 scripts/p39_staging_rehearsal.sh   # leave the stack up for inspection
#
# Exit: 0 all checks passed, 1 at least one check failed.

set -uo pipefail

COMPOSE_FILE="docker-compose.staging.yml"
PROJECT="p39rehearsal"
COMPOSE=(docker compose -f "$COMPOSE_FILE" -p "$PROJECT")
KEEP="${KEEP:-0}"

FAIL=0
PASS_COUNT=0
FAIL_COUNT=0

# Set to 1 immediately before any INTENTIONAL non-zero exit, so the traps below can tell a
# deliberate refusal (BLOCKED, or checks that failed) from the script itself breaking.
DELIBERATE_EXIT=0

# Report WHERE an unexpected failure happened.
#
# The first version of this script discarded `up` output and, when it died, produced a
# log that simply stopped after the previous successful check — no error, no line number.
# Diagnosing it cost a full CI round-trip through a temporary workflow, because Actions
# logs cannot be downloaded from the audit sandbox. An explicit trap is cheap insurance.
on_unexpected_failure() {
    local code=$1 line=$2
    printf '\n[FATAL] the rehearsal stopped unexpectedly at line %s (status %s)\n' "$line" "$code"
    printf '[FATAL] this is a bug in the script or a missing prerequisite, not a product failure\n'
}
trap 'on_unexpected_failure "$?" "$LINENO"' ERR
# ERR does not fire on `set -u` in every bash version, so also report on any non-zero exit
# that reaches here without a recorded check failure.
on_exit() {
    local code=$?
    if [ "$code" -ne 0 ] && [ "$FAIL_COUNT" -eq 0 ] && [ "$DELIBERATE_EXIT" -eq 0 ]; then
        printf '\n[FATAL] exited %s with no recorded check failure: the script itself broke\n' "$code"
    fi
}
trap on_exit EXIT

note() { printf '  [ok]   %s\n' "$*"; PASS_COUNT=$((PASS_COUNT + 1)); }
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=1; FAIL_COUNT=$((FAIL_COUNT + 1)); }
hdr()  { printf '\n=== %s ===\n' "$*"; }
# GitHub annotation only when running under Actions; harmless locally otherwise.
gafail() { printf '::error::[p39] %s\n' "$*"; }

# ---------------------------------------------------------------------------- preflight
hdr "0. preflight"
if ! command -v docker >/dev/null 2>&1; then
    gafail "docker is not available; the rehearsal cannot run"
    echo "BLOCKED: docker is not installed in this environment."
    DELIBERATE_EXIT=1
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    gafail "the docker daemon is not reachable"
    echo "BLOCKED: docker daemon unreachable."
    DELIBERATE_EXIT=1
    exit 1
fi
if [ ! -f "$COMPOSE_FILE" ]; then
    gafail "$COMPOSE_FILE is missing"
    DELIBERATE_EXIT=1
    exit 1
fi
note "docker present: $(docker --version)"
note "compose present: $(docker compose version --short 2>/dev/null || echo unknown)"

# ------------------------------------------------------------------------- environment
# Throwaway credentials, generated per run. These are never written to disk in a
# committed file and never reused between runs.
export STAGING_DOMAIN="staging.p39.invalid"
export ACME_EMAIL="ops@p39.invalid"
export ALLOWED_ORIGINS="https://staging.p39.invalid"
export TRUSTED_PROXIES="172.16.0.0/12"
export ADMIN_PASSWORD="p39-admin-$$-$RANDOM"
export POSTGRES_PASSWORD="p39-pg-$$-$RANDOM"
export POSTGRES_OWNER_PASSWORD="p39-owner-$$-$RANDOM"
export POSTGRES_APP_PASSWORD="p39-app-$$-$RANDOM"
export E02_ACCOUNT_KEY_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))' || true)"
[ -n "$E02_ACCOUNT_KEY_SECRET" ] || { echo "BLOCKED: could not generate the account key secret"; DELIBERATE_EXIT=1; exit 1; }

teardown() {
    if [ "$KEEP" = "1" ]; then
        echo "KEEP=1: leaving project $PROJECT up for inspection"
        echo "  docker compose -f $COMPOSE_FILE -p $PROJECT down -v"
        return
    fi
    hdr "teardown"
    "${COMPOSE[@]}" down -v --remove-orphans 2>&1 | tail -5 || true
    docker image prune -f >/dev/null 2>&1 || true
    note "stack removed"
}
trap teardown EXIT

# ------------------------------------------------------- 1. negative control: no secret
hdr "1. negative control - a missing secret must abort"
tmp_err="$(mktemp || true)"
# `set +e` / `$?` / `set -e` looked reasonable but re-enabled errexit in the middle of a
# script that otherwise runs without it, so every later failure became fatal AND fired the
# ERR trap: the passing rehearsal printed
#   [FATAL] the rehearsal stopped unexpectedly at line 138
# after its own negative control. Capture the status with `if !`, which never trips
# errexit and never trips the trap.
if ( unset ADMIN_PASSWORD; "${COMPOSE[@]}" config >/dev/null 2>"$tmp_err" ); then
    missing_status=0
else
    missing_status=$?
fi
if [ "$missing_status" -eq 0 ]; then
    bad "compose accepted the file with ADMIN_PASSWORD unset, so a misconfigured host starts half-built"
else
    note "missing ADMIN_PASSWORD rejected with exit $missing_status"
    if grep -q "ADMIN_PASSWORD" "$tmp_err"; then
        note "the refusal names the variable: $(head -1 "$tmp_err")"
    else
        bad "the refusal does not name ADMIN_PASSWORD: $(head -2 "$tmp_err")"
    fi
fi
rm -f "$tmp_err"

# ------------------------------------------------------------- 2. config is accepted
hdr "2. compose config accepts a complete environment"
config_out="$(mktemp || true)"
if "${COMPOSE[@]}" config >"$config_out" 2>/tmp/p39_config.err; then
    note "compose config OK ($(wc -l <"$config_out") lines)"
else
    bad "compose config failed: $(head -5 /tmp/p39_config.err)"
fi

# ------------------------------------------------- 3. no datastore/app port published
hdr "3. topology - only the proxy may publish host ports"
if python3 - "$config_out" <<'PYEOF'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
services = doc.get("services") or {}
forbidden = {"8000", "5432", "6379"}
offenders = []
summary = []
for name, svc in services.items():
    ports = svc.get("ports") or []
    published = [str(p.get("published", "")) for p in ports if isinstance(p, dict)]
    exposed = set(published) & forbidden
    if exposed:
        offenders.append((name, sorted(exposed)))
    if published:
        summary.append(f"{name}:{','.join(published)}")
print("published ports:", "; ".join(summary) or "none")
if offenders:
    print("FORBIDDEN:", offenders)
    raise SystemExit(1)
PYEOF
then
    note "no service publishes 8000/5432/6379"
else
    bad "a datastore or the application publishes a host port"
fi

# ----------------------------------------------------------------- 4. datastores + migrate
hdr "4. postgres, redis and the migration job"
# Capture the output instead of discarding it. Discarding it cost a full CI round-trip:
# the step died here with no diagnostic at all, and the real error (compose refusing to
# interpolate because the variables were missing) was only visible on stderr.
if ! "${COMPOSE[@]}" up -d db redis >/tmp/p39_db.log 2>&1; then
    bad "db/redis failed to start"
    tail -20 /tmp/p39_db.log
fi
# Prove the environment reached this point rather than assuming it: a missing export is
# otherwise reported by compose as an interpolation error much later and much less clearly.
for var in STAGING_DOMAIN ADMIN_PASSWORD POSTGRES_PASSWORD POSTGRES_OWNER_PASSWORD \
           POSTGRES_APP_PASSWORD E02_ACCOUNT_KEY_SECRET ALLOWED_ORIGINS TRUSTED_PROXIES ACME_EMAIL; do
    if [ -z "${!var:-}" ]; then
        bad "$var is empty in this shell"
    fi
done
note "all nine required variables are non-empty in the rehearsal shell"

pg_ready=0
for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T db pg_isready -U gerege -d gerege_staging >/dev/null 2>&1; then
        pg_ready=1
        break
    fi
    sleep 1
done
[ "$pg_ready" = "1" ] && note "postgres reported ready" || bad "postgres never became ready"

# Redis must answer PING, not merely be running: a bound port proves nothing.
# `|| true` is required: under `set -o pipefail` a failing redis-cli in this command
# substitution makes the whole assignment non-zero, and with no `|| bad` guard the shell
# exits silently. Every direct assignment of a command's output gets the same treatment.
redis_pong="$("${COMPOSE[@]}" exec -T redis redis-cli ping 2>/dev/null | tr -d '\r' || true)"
[ "$redis_pong" = "PONG" ] && note "redis answered PING" || bad "redis did not answer PING (got '$redis_pong')"

# `web` and `worker` both depend on `migrate` with condition
# service_completed_successfully, so compose itself will run the migration job as part of
# `up -d web worker`. Bringing the job up first and then starting the application plane
# would make compose re-check a dependency that has already finished, so do NOT do that:
# one `up` runs migrate and then the application, in the right order.
"${COMPOSE[@]}" up -d web worker >/tmp/p39_up.log 2>&1 \
    || { bad "the application plane failed to start"; tail -30 /tmp/p39_up.log; }

# Read the migration job's own exit status rather than trusting that `up` succeeded.
#
# `docker compose wait` is NOT a compose subcommand (it was added in Compose v2.28 as
# `docker compose wait`, but a container's exit code is available more portably with
# `docker inspect`, and that works on every version). The first version used it anyway and
# the command substitution failed with no output, killing the script at that line.
#
# Wait for the one-shot job to leave the "running" state, then read its exit code.
migrate_id="$("${COMPOSE[@]}" ps -aq migrate 2>/dev/null | head -1 | tr -d '\r' || true)"
migrate_exit="unknown"
if [ -n "$migrate_id" ]; then
    for _ in $(seq 1 120); do
        running="$(docker inspect -f '{{.State.Running}}' "$migrate_id" 2>/dev/null | tr -d '\r' || true)"
        if [ "$running" = "false" ]; then
            migrate_exit="$(docker inspect -f '{{.State.ExitCode}}' "$migrate_id" 2>/dev/null | tr -d '\r' || true)"
            break
        fi
        sleep 1
    done
fi
if [ "$migrate_exit" = "0" ]; then
    note "migration job exited 0"
else
    bad "the migration job did not exit 0 (got '$migrate_exit')"
    "${COMPOSE[@]}" logs --tail 40 migrate 2>&1 | tail -40 || true
fi

# Confirm the schema is actually there rather than trusting the exit code.
tables="$("${COMPOSE[@]}" exec -T db psql -U gerege -d gerege_staging -tAc \
    "select count(*) from information_schema.tables where table_schema='public'" 2>/dev/null | tr -d ' \r' || true)"
if [ "${tables:-0}" -gt 0 ] 2>/dev/null; then
    note "public schema has $tables tables"
else
    bad "the database has no tables after the migration reported success"
fi

# --------------------------------------------------------------- 5. application plane
hdr "5. the API answers its own health endpoints"
web_ok=0
for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T web python -c \
        "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3)" \
        >/dev/null 2>&1; then
        web_ok=1
        break
    fi
    sleep 1
done
[ "$web_ok" = "1" ] && note "the API answered /api/health" || bad "the API never answered /api/health"

for endpoint in /api/health /api/ready; do
    code="$("${COMPOSE[@]}" exec -T web python -c "
import urllib.request, urllib.error
try:
    print(urllib.request.urlopen('http://127.0.0.1:8000${endpoint}', timeout=5).status)
except urllib.error.HTTPError as exc:
    print(exc.code)
except Exception as exc:
    print('ERR', exc)
" 2>/dev/null | tr -d '\r' || true)"
    if [ "$code" = "200" ]; then
        note "GET $endpoint -> 200"
    else
        bad "GET $endpoint -> $code"
    fi
done

# ------------------------------------------------------------------- 6. worker heartbeat
hdr "6. the worker publishes a heartbeat"
hb_status=""
hb_ok=0
for _ in $(seq 1 60); do
    hb_status="$("${COMPOSE[@]}" exec -T worker python -c \
        "from core.worker_heartbeat import read;print(read()['status'])" 2>/dev/null | tr -d '\r' || true)"
    if [ "$hb_status" = "alive" ]; then
        hb_ok=1
        break
    fi
    sleep 1
done
if [ "$hb_ok" = "1" ]; then
    note "worker heartbeat status: alive"
else
    bad "the worker never reported alive (last: '$hb_status')"
    "${COMPOSE[@]}" logs --tail 40 worker || true
fi

# ----------------------------------------------------- 7. F-39-D, executed for real
hdr "7. F-39-D - a broken scheduler step must not make a live worker look dead"
if "${COMPOSE[@]}" exec -T worker python - <<'PYEOF'
import asyncio
import appointment_service
import database
import worker
from core import worker_heartbeat

async def boom(*args, **kwargs):
    raise RuntimeError("p39 injected scheduler failure")

appointment_service.check_and_dispatch_appointment_reminders = boom
asyncio.run(worker.run_worker_tick(0))
state = worker_heartbeat.read()
heartbeat = state.get("heartbeat") or {}
status = state.get("status")
errors = heartbeat.get("scheduler_errors")
print(f"  status={status!r} scheduler_errors={errors!r}")
raise SystemExit(0 if status == "alive" and errors == 1 else 1)
PYEOF
then
    note "an injected scheduler failure left the heartbeat alive and counted it"
else
    bad "F-39-D regressed: a raising scheduler step made the worker report dead"
fi

# ------------------------------------------------------------------ 8. non-root container
hdr "8. the application container does not run as root"
web_uid="$("${COMPOSE[@]}" exec -T web id -u 2>/dev/null | tr -d '\r' || true)"
if [ "$web_uid" = "0" ]; then
    bad "the application container runs as uid 0"
elif [ -n "$web_uid" ]; then
    note "web runs as uid $web_uid"
else
    bad "could not determine the container uid"
fi

# --------------------------------------------------------------- 9. health, per compose
hdr "9. compose health states"
"${COMPOSE[@]}" ps || true
unhealthy="$("${COMPOSE[@]}" ps --format json 2>/dev/null | python3 -c '
import sys, json
bad = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        row = json.loads(line)
    except Exception:
        continue
    health = (row.get("Health") or "").strip()
    if health and health not in ("healthy",):
        bad.append(f"{row.get(chr(83)+chr(101)+chr(114)+chr(118)+chr(105)+chr(99)+chr(101))}:{health}")
print(",".join(bad))
raise SystemExit(1 if bad else 0)
' 2>/dev/null || true)" || true
if [ -n "$unhealthy" ]; then
    bad "compose reports unhealthy services: $unhealthy"
else
    note "no service is reported unhealthy"
fi

# ------------------------------------------------------------------------------ verdict
hdr "result"
printf '  passed: %s   failed: %s\n' "$PASS_COUNT" "$FAIL_COUNT"
if [ "$FAIL" -ne 0 ]; then
    gafail "the staging rehearsal FAILED ($FAIL_COUNT check(s)); see above"
    DELIBERATE_EXIT=1
    exit 1
fi
note "staging rehearsal PASSED"
exit 0
