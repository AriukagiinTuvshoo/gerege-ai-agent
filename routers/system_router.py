from typing import Dict, Any
from fastapi import APIRouter, Request, Depends

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


@router.post("/backups/create")
async def create_backup_endpoint(
    payload: Dict[str, Any] = {},
    _admin: Dict[str, Any] = Depends(require_admin),
):
    """Өгөгдлийн сангийн шинэ backup үүсгэх (Зөвхөн Админ)"""
    label = str(payload.get("label", "manual")).strip() or "manual"
    return backup_service.create_backup(label=label)


@router.post("/backups/verify")
async def verify_backup_endpoint(
    payload: Dict[str, Any],
    _admin: Dict[str, Any] = Depends(require_admin),
):
    """Backup файлын SHA-256 болон SQLite/PostgreSQL бүрэн бүтэн байдал шалгах"""
    filename = str(payload.get("filename", "")).strip()
    return backup_service.verify_backup(filename)


@router.post("/backups/restore")
async def restore_backup_endpoint(
    payload: Dict[str, Any],
    _admin: Dict[str, Any] = Depends(require_admin),
):
    """Backup-аас өгөгдлийн санг сэргээх (Pre-restore snapshot үүсгээд атомик сэргээнэ)"""
    filename = str(payload.get("filename", "")).strip()
    return backup_service.restore_backup(filename)


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
