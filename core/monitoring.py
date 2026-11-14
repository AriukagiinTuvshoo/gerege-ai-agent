import os
import re
import json
import time
import shutil
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("core.monitoring")

_SECRET_PATTERNS = [
    (re.compile(r"AIza[0-9A-Za-z\-_]{20,}"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"sk-[0-9A-Za-z\-_]{20,}"), "[REDACTED_SK_KEY]"),
    (re.compile(r"(?i)(bearer\s+)[0-9A-Za-z\-_\.]{12,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(?i)(password|secret|api_key|access_token)\s*[:=]\s*['\"]?[^\s,'\"\}]+"), r"\1=[REDACTED]"),
]


def redact_secrets(text: str) -> str:
    """Лог болон алдааны мэдээллээс нууц түлхүүр, токен, нууц үгийг шүүж нууцлах."""
    if not text:
        return ""
    cleaned = str(text)
    for pattern, repl in _SECRET_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned


def log_structured_event(event: str, level: str = "INFO", **fields: Any) -> Dict[str, Any]:
    """Structured JSON лог үүсгэж бичих (trace/request ID болон secret redaction-тэй)."""
    safe_fields: Dict[str, Any] = {}
    for k, v in fields.items():
        if isinstance(v, str):
            safe_fields[k] = redact_secrets(v)
        else:
            safe_fields[k] = v

    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level.upper(),
        "event": event,
        **safe_fields,
    }
    serialized = json.dumps(record, ensure_ascii=False, default=str)
    if level.upper() in ("ERROR", "CRITICAL"):
        logger.error(serialized)
    elif level.upper() == "WARNING":
        logger.warning(serialized)
    else:
        logger.info(serialized)
    return record


class TelemetryCollector:
    """
    Phase 5 & 9: Системийн мониторинг, латенси хэмжилт, DB Pool / Queue / AI Circuit хяналт ба алдааны бүртгэл.
    """

    def __init__(self):
        self.started_at = time.time()
        self.total_requests = 0
        self.total_errors = 0
        self.status_counts: Dict[int, int] = {}
        self.recent_errors: List[Dict[str, Any]] = []
        self.latency_ms_sum = 0.0

    def record_request(
        self,
        path: str,
        method: str,
        status_code: int,
        duration_ms: float,
        error_detail: str = "",
        request_id: Optional[str] = None,
    ) -> None:
        self.total_requests += 1
        self.latency_ms_sum += duration_ms
        self.status_counts[status_code] = self.status_counts.get(status_code, 0) + 1

        if status_code >= 500 or error_detail:
            self.total_errors += 1
            safe_err = redact_secrets(error_detail)[:300]
            err_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "request_id": request_id or "",
                "method": method,
                "path": path,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 2),
                "error": safe_err,
            }
            self.recent_errors.append(err_entry)
            if len(self.recent_errors) > 50:
                del self.recent_errors[:10]

    def get_snapshot(self) -> Dict[str, Any]:
        uptime_sec = int(time.time() - self.started_at)
        avg_latency = round(self.latency_ms_sum / self.total_requests, 2) if self.total_requests > 0 else 0.0

        db_pool_info: Dict[str, Any] = {}
        try:
            from core.db_engine import get_pool_status
            db_pool_info = get_pool_status()
        except Exception:
            pass

        queue_info: Dict[str, Any] = {}
        try:
            from core.task_queue import task_queue
            queue_info = task_queue.get_queue_stats()
        except Exception:
            pass

        disk_free_mb = 0.0
        try:
            usage = shutil.disk_usage(os.getcwd())
            disk_free_mb = round(usage.free / (1024 * 1024), 2)
        except Exception:
            pass

        return {
            "uptime_seconds": uptime_sec,
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "avg_latency_ms": avg_latency,
            "status_counts": self.status_counts,
            "recent_errors": self.recent_errors[-10:],
            "db_pool": db_pool_info,
            "queue": queue_info,
            "disk_free_mb": disk_free_mb,
        }


telemetry = TelemetryCollector()
