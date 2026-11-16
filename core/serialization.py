"""
API-boundary JSON normalisation.

**Why this module exists (finding P0-01 / B-01).**

`database.py` uses the raw DB-API. Depending on which schema is in force, a
`created_at` column is either `TEXT` (Alembic migration `0001`) or `TIMESTAMP`
(`init_db()` runtime DDL). With `psycopg2` the latter yields `datetime.datetime`,
and `starlette.responses.JSONResponse` calls `json.dumps` directly — which raises
`TypeError: Object of type datetime is not JSON serializable`, surfacing as HTTP 500
on `/api/auth/me`, `/api/leads`, `/api/pages`.

FastAPI's `jsonable_encoder` already handles datetimes for plain `dict` returns, but
every explicit `JSONResponse(...)` bypasses it. Rather than audit 50+ call sites by
hand (and re-audit them forever), the response class itself normalises.

Contract:
    * `datetime` / `date` / `time` -> ISO-8601 string
    * `Decimal`                    -> int when integral, else float
    * `UUID`                       -> str
    * `bytes` / `bytearray`        -> UTF-8 text when decodable, else tagged base64
    * `set` / `tuple` / generators -> list
    * anything else                -> `TypeError` (never silently stringified)
"""
from __future__ import annotations

import base64
import json
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID

from starlette.responses import JSONResponse


def jsonable(value: Any) -> Any:
    """Recursively convert DB-driver values into JSON-safe primitives."""
    if value is None or isinstance(value, (bool, int, str)):
        return value

    if isinstance(value, float):
        # NaN/Infinity are not valid JSON; let json.dumps raise on them explicitly.
        return value

    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()

    if isinstance(value, Decimal):
        # Integral decimals stay integral (money in MNT is integer), otherwise float.
        if value == value.to_integral_value():
            return int(value)
        return float(value)

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return "base64:" + base64.b64encode(bytes(value)).decode("ascii")

    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in value]

    # Support sqlite3.Row / mapping-like objects without importing sqlite3 here.
    if hasattr(value, "keys") and callable(getattr(value, "keys", None)):
        try:
            return {str(k): jsonable(value[k]) for k in value.keys()}
        except Exception:  # pragma: no cover - defensive
            pass

    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


class SafeJSONResponse(JSONResponse):
    """`JSONResponse` that normalises driver values before serialisation."""

    def render(self, content: Any) -> bytes:
        return json.dumps(
            jsonable(content),
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")
