from typing import Dict, Any
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse

import database
from core.security import require_admin
from core import backup_service
from core.monitoring import telemetry
from core.task_queue import task_queue

router = APIRouter(prefix="/api/admin", tags=["System Administration, Backups & Monitoring"])


@router.get("/backups")
async def list_backups_endpoint(_admin: Dict[str, Any] = Depends(require_admin)):
    """Хадгалагдсан өгөгдлийн сангийн backup-уудын жагсаалт (Зөвхөн Админ)"""
    return {"backups": backup_service.list_backups()}


# E-05: `POST /backups/create` and `POST /backups/restore` were removed.
#
# They cannot be done correctly by the runtime credential. `pg_dump` needs
# `LOCK TABLE ... ACCESS SHARE` on every table and restore needs `DROP`/`CREATE` on the
# schema — ownership, which `gerege_app` deliberately does not have. Measured on
# PostgreSQL 16: as a non-owner, `pg_dump` exits 1 with
# "permission denied for table registrations" and the wrapper wrote its empty stdout to
# gzip, so the API returned `success: true` for a **0-byte backup**.
#
# The alternative was to grant the runtime role the very privileges this phase exists to
# remove, so the operations moved to `scripts/maintenance.py` (owner credential, explicit
# operator action, pre-restore snapshot, verification) or the one-shot `maintenance`
# Compose service. They are gone rather than left returning 503: an endpoint that exists
# but cannot work invites retries and, worse, silently-successful no-ops.
#
# `GET /backups` and `POST /backups/verify` remain: they only read the backups
# directory and a file's checksum, which the runtime role may do.


@router.post("/backups/verify")
async def verify_backup_endpoint(
    payload: Dict[str, Any],
    _admin: Dict[str, Any] = Depends(require_admin),
):
    """Backup файлын SHA-256 болон SQLite/PostgreSQL бүрэн бүтэн байдал шалгах"""
    filename = str(payload.get("filename", "")).strip()
    return backup_service.verify_backup(filename)


@router.get("/metrics")
async def system_metrics_endpoint(_admin: Dict[str, Any] = Depends(require_admin)):
    """Системийн латенси, алдааны бүртгэл болон телеметрийн үзүүлэлтүүд"""
    return telemetry.get_snapshot()


@router.get("/queue/stats")
async def queue_stats_endpoint(_admin: Dict[str, Any] = Depends(require_admin)):
    """Task Queue-ийн бодит статистик (Pending, Processing, Completed, Dead-Letter)"""
    return task_queue.get_queue_stats()


@router.get("/queue/failed")
async def queue_failed_jobs_endpoint(_admin: Dict[str, Any] = Depends(require_admin)):
    """Dead-Letter болон Failed төлөвт орсон даалгавруудын жагсаалт"""
    return {"jobs": task_queue.list_failed_jobs(limit=50)}


@router.get("/worker/health")
async def worker_health_endpoint(_admin: Dict[str, Any] = Depends(require_admin)):
    """Worker liveness, queue backlog and scheduler state (Phase 36).

    Phase 35's finding: nothing could answer "is the worker alive?" over HTTP. Queue depth
    and failed jobs were visible, but a worker that died while the queue was empty was
    completely invisible -- the symptom would have been silently missing daily reports.

    The heartbeat is a short-TTL Redis key (no schema change, and expiry means a dead
    worker cannot leave a stale "healthy" flag behind). ``status`` is one of:

      alive    a heartbeat completed within the freshness window
      stale    a heartbeat exists but is older than expected -- wedged, not merely absent
      missing  no heartbeat at all: never started, or its TTL lapsed
      unknown  Redis could not be read, so no claim is made either way

    Admin-only, because queue and scheduler state are deployment-internal.
    """
    from core import worker_heartbeat

    worker_state = worker_heartbeat.read()
    try:
        stats = task_queue.get_queue_stats()
    except Exception as exc:
        stats = {"error": type(exc).__name__}

    # Scheduler health is reported from the same queue stats the worker writes to: the
    # worker owns the scheduler in production (DISABLE_INLINE_SCHEDULER=1 in `web`), so a
    # dead worker is *also* a dead scheduler. Saying so explicitly prevents an operator
    # from reading "worker missing" as a delivery problem only.
    dead_letter = int(stats.get("dead_letter") or 0)
    pending = int(stats.get("pending") or 0)
    backlogged = pending > 100

    # Phase 41: `worker` is now the POOL, and the old single-worker shape is preserved
    # under `worker.heartbeat` for the case of exactly one worker so existing consumers do
    # not break. Two shapes used to be one: "this deployment has a worker" and "every
    # worker in the pool is healthy". They are reported separately now, because with one
    # key the second question could not be asked at all.
    healthy = worker_state["status"] == "alive"
    single = worker_state.get("workers") or []
    compat = {
        # Pre-Phase-41 consumers read worker.heartbeat.worker_id / .loop_count. Keep that
        # available when there is exactly one worker, and never invent one when there are
        # several - a fabricated "the worker" is how the pool became invisible.
        "heartbeat": (
            {k: v for k, v in single[0].items() if k not in ("status", "age_seconds")}
            if len(single) == 1
            else None
        ),
        "fresh_window_seconds": worker_state.get("fresh_window_seconds"),
        "ttl_seconds": worker_state.get("ttl_seconds"),
    }
    if worker_state.get("reason"):
        compat["reason"] = worker_state["reason"]
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "worker": {**worker_state, **{k: v for k, v in compat.items() if k not in worker_state}},
            "scheduler": {
                # In this topology the scheduler runs inside the worker.
                "location": "worker",
                "healthy": healthy,
                "note": (
                    "the API runs with DISABLE_INLINE_SCHEDULER=1, so a stopped worker "
                    "also stops scheduled reports and retention"
                ),
            },
            "queue": stats,
            "alerts": {
                "worker_not_alive": not healthy,
                # Phase 41: a pool with some workers dead is a partial outage, and it is
                # invisible in a single boolean. Reported separately so an alert rule can
                # fire on "degraded" rather than waiting for total loss.
                "worker_pool_degraded": worker_state.get("stale_count", 0) > 0,
                "worker_count": worker_state.get("worker_count", 0),
                "alive_worker_count": worker_state.get("alive_count", 0),
                "backlog_over_100": backlogged,
                "dead_letter_jobs": dead_letter,
            },
        },
    )


@router.post("/queue/process")
async def process_task_queue_endpoint(_admin: Dict[str, Any] = Depends(require_admin)):
    """Task Queue дахь хүлээгдэж буй даалгавруудыг яг одоо гүйцэтгэх"""
    count = await task_queue.process_pending_jobs(batch_size=20)
    return {"success": True, "processed_count": count}


@router.get("/audit-logs")
async def list_audit_logs_endpoint(
    page_id: str = "",
    limit: int = 100,
    _admin: Dict[str, Any] = Depends(require_admin),
):
    """Аюулгүй байдал болон AI Tool үйлдлийн Audit Log жагсаалт"""
    return {"logs": database.list_audit_logs(page_id=page_id or None, limit=min(500, max(1, limit)))}
