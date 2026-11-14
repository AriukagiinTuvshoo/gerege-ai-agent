import os
import time
import logging
from typing import Dict, Any, List
from fastapi import Request

logger = logging.getLogger("core.monitoring")


class TelemetryCollector:
    """
    Phase 5: Системийн мониторинг, латенси хэмжилт ба алдааны бүртгэл (Error Tracking).
    """

    def __init__(self):
        self.started_at = time.time()
        self.total_requests = 0
        self.total_errors = 0
        self.status_counts: Dict[int, int] = {}
        self.recent_errors: List[Dict[str, Any]] = []
        self.latency_ms_sum = 0.0

    def record_request(self, path: str, method: str, status_code: int, duration_ms: float, error_detail: str = "") -> None:
        self.total_requests += 1
        self.latency_ms_sum += duration_ms
        self.status_counts[status_code] = self.status_counts.get(status_code, 0) + 1

        if status_code >= 500 or error_detail:
            self.total_errors += 1
            self.recent_errors.append({
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "method": method,
                "path": path,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 2),
                "error": error_detail[:300],
            })
            if len(self.recent_errors) > 50:
                del self.recent_errors[:10]

    def get_snapshot(self) -> Dict[str, Any]:
        uptime_sec = int(time.time() - self.started_at)
        avg_latency = round(self.latency_ms_sum / self.total_requests, 2) if self.total_requests > 0 else 0.0
        return {
            "uptime_seconds": uptime_sec,
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "avg_latency_ms": avg_latency,
            "status_counts": self.status_counts,
            "recent_errors": self.recent_errors[-10:],
        }


telemetry = TelemetryCollector()
