#!/usr/bin/env python3
"""
Phase 2: Production-Grade SQLite-to-PostgreSQL Data Migration & Verification Engine

Features:
1. Point-in-time consistent SQLite snapshot via `sqlite3.Connection.backup`.
2. Batch processing (`--batch-size`, default 500) ordered by primary/unique key.
3. Deterministic canonical row serialization & SHA-256 hashing:
   - Stable column order
   - Strict distinction between NULL (`None`) and empty string (`""`)
   - Fixed decimal/float precision (`6` decimal places)
   - Normalized timestamp representation (`YYYY-MM-DD HH:MM:SS`)
   - NFC Unicode normalization & canonical JSON key sorting (`knowledge_json`, `payload_json`, etc.)
4. Strict Conflict Policy (No blind `ON CONFLICT DO NOTHING`):
   - Compares existing target row by primary/unique key against source row canonical hash.
   - If identical -> `identical_skipped` (idempotent safe resume/re-run).
   - If different -> aborts without overwriting and outputs a detailed `conflict_report`.
5. Post-migration row-level & table checksum verification + financial integrity check.
"""
import os
import re
import sys
import json
import math
import sqlite3
import hashlib
import tempfile
import argparse
import unicodedata
from datetime import datetime, date
from decimal import Decimal
from typing import Dict, Any, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

JSON_COLUMNS = {"knowledge_json", "deep_links_json", "payload_json", "details_json"}
FLOAT_COLUMNS = {"weight_kg"}
TIMESTAMP_COLUMNS = {
    "created_at",
    "updated_at",
    "expires_at",
    "revoked_at",
    "paid_at",
    "notified_at",
    "arrived_at",
    "delivered_at",
    "sent_at",
    "next_run_at",
    "locked_at",
}

#: Table and column names that may appear in generated SQL.
#:
#: Phase 26. `MIGRATION_TABLES` is a constant, but the *column* list is not: it is read at
#: runtime from `PRAGMA table_info` of whichever SQLite file the operator points `--sqlite-path`
#: at, and interpolated straight into `SELECT ... FROM ...`. SQLite stores ANY string as a
#: column name when it is quoted, so a source database can carry
#:
#:     CREATE TABLE invoices (invoice_id TEXT, "a\" , (SELECT 1) --" TEXT)
#:
#: and the ETL then builds `SELECT invoice_id, a" , (SELECT 1) -- FROM invoices`. That exact
#: payload is a syntax error, not an exploit - `--` needs a newline to terminate. The
#: balanced form is the one that executes:
#:
#:     column name:  a, (SELECT 1) AS injected
#:     built SQL:    SELECT invoice_id, a, (SELECT 1) AS injected FROM invoices
#:
#: which runs the subquery. The migration connects with the owner credential on the target -
#: the privilege context that exists precisely because the runtime role is too restricted to
#: restore - so an injected expression executes as a role that can read and write every
#: tenant's rows. Row-returning injection is the realistic consequence; stacked statements
#: are not, because `sqlite3`/DBAPI `execute()` refuses more than one statement.
#:
#: Identifiers cannot be parameterised - `SELECT :col FROM t` binds a value, not a name - so
#: they are validated instead. Every sink goes through `_q_ident()` / `_q_ident_list()`.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _q_ident(name: Any) -> str:
    """Validate one identifier and return it quoted for the engine in use.

    Rejects anything that is not a plain identifier, so a name carrying a quote, a
    parenthesis, a semicolon or a comment marker never reaches a SQL string. Quoting is
    not sufficient on its own: the caller builds syntax around this value, and an
    unbalanced quote would still break out. Validation first, quoting second.

    Quoting is engine-specific - SQLite and PostgreSQL both accept `"x"`, but the escape
    for an embedded quote differs (SQLite doubles it, PostgreSQL doubles it too, but a
    MySQL-style backtick is valid in neither). The value is validated before quoting, so
    no embedded quote can reach the quoting step.
    """
    text = str(name)
    if not _IDENT_RE.match(text):
        # Do not echo the name back: it is attacker-controlled, and a rejected identifier is
        # still a string that will be written to a log, a terminal or an alert. A newline or
        # an escape sequence here is a log-injection primitive. Describe it instead.
        raise ValueError(
            "refusing to build SQL with an unsafe identifier "
            f"({len(text)} character(s), first byte 0x{text.encode('utf-8', 'replace')[:1].hex() or '00'}): "
            "a table or column name must match [A-Za-z_][A-Za-z0-9_$]*. A source database "
            "with an unusual column name must be normalised before migration."
        )
    return '"' + text + '"'


def _q_ident_list(names: Any) -> List[str]:
    """Validate and quote a list of identifiers."""
    return [_q_ident(n) for n in names]


MIGRATION_TABLES: List[Dict[str, Any]] = [
    {"table": "pages", "pk_cols": ["page_id"]},
    {"table": "registrations", "pk_cols": ["id"], "has_serial_id": True},
    {"table": "messages", "pk_cols": ["id"], "has_serial_id": True},
    # E-01: session identity is tenant-scoped; the ETL must upsert on the real key.
    {"table": "session_states", "pk_cols": ["page_id", "sender_id"]},
    {"table": "sessions", "pk_cols": ["session_token"]},
    {"table": "user_memories", "pk_cols": ["page_id", "user_id"], "has_serial_id": True},
    {"table": "invoices", "pk_cols": ["invoice_id"], "has_serial_id": True},
    {"table": "cargo_packages", "pk_cols": ["page_id", "tracking_code"], "has_serial_id": True},
    {"table": "automated_rules", "pk_cols": ["page_id", "rule_type"], "has_serial_id": True},
    {"table": "marketing_campaigns", "pk_cols": ["id"], "has_serial_id": True},
    {"table": "sent_followups", "pk_cols": ["page_id", "rule_type", "sender_id"], "has_serial_id": True},
    {"table": "appointments", "pk_cols": ["id"], "has_serial_id": True},
    {"table": "notification_locks", "pk_cols": ["idempotency_key"]},
    {"table": "task_jobs", "pk_cols": ["id"], "natural_unique_cols": ["idempotency_key"], "has_serial_id": True},
    {"table": "audit_logs", "pk_cols": ["id"], "has_serial_id": True},
    {"table": "comment_automations", "pk_cols": ["id"], "has_serial_id": True},
    {"table": "tracked_links", "pk_cols": ["id"], "natural_unique_cols": ["code"], "has_serial_id": True},
]


def canonicalize_value(col_name: str, val: Any) -> Dict[str, Any]:
    """
    Produce a deterministic typed representation of a single column value:
    - Distinguishes NULL (`{"t": "null", "v": None}`) from empty string (`{"t": "str", "v": ""}`).
    - Normalizes timestamps, JSON payloads, floats, integers, and Unicode NFC strings.
    """
    if val is None:
        return {"t": "null", "v": None}

    if isinstance(val, bool):
        return {"t": "int", "v": 1 if val else 0}

    if col_name in FLOAT_COLUMNS or isinstance(val, (float, Decimal)):
        try:
            fval = float(val)
            if math.isnan(fval) or math.isinf(fval):
                fval = 0.0
            return {"t": "float", "v": f"{round(fval, 6):.6f}"}
        except Exception:
            pass

    if isinstance(val, int):
        return {"t": "int", "v": int(val)}

    if isinstance(val, (datetime, date)):
        if isinstance(val, datetime):
            return {"t": "ts", "v": val.strftime("%Y-%m-%d %H:%M:%S")}
        return {"t": "date", "v": val.strftime("%Y-%m-%d")}

    sval = unicodedata.normalize("NFC", str(val))

    if col_name in TIMESTAMP_COLUMNS and sval:
        clean_ts = sval.replace("T", " ").strip()
        if "." in clean_ts:
            clean_ts = clean_ts.split(".")[0]
        if "+" in clean_ts:
            clean_ts = clean_ts.split("+")[0].strip()
        if clean_ts.endswith("Z"):
            clean_ts = clean_ts[:-1].strip()
        return {"t": "ts", "v": clean_ts}

    if col_name in JSON_COLUMNS and sval:
        try:
            parsed = json.loads(sval)
            norm_json = json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            return {"t": "json", "v": unicodedata.normalize("NFC", norm_json)}
        except Exception:
            return {"t": "str", "v": sval}

    return {"t": "str", "v": sval}


def compute_canonical_row_hash(row: Dict[str, Any], columns: List[str], exclude_cols: Optional[set] = None) -> str:
    """Compute a deterministic SHA-256 hash for a row across sorted columns."""
    excl = exclude_cols or set()
    ordered_cols = [c for c in sorted(columns) if c not in excl]
    canonical_map = {c: canonicalize_value(c, row.get(c)) for c in ordered_cols}
    serialized = json.dumps(canonical_map, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_row_pk_tuple(row: Dict[str, Any], pk_cols: List[str]) -> Tuple[Any, ...]:
    return tuple(canonicalize_value(c, row.get(c))["v"] for c in pk_cols)


def compute_table_checksum(rows: List[Dict[str, Any]], columns: List[str], pk_cols: List[str]) -> str:
    """Compute a deterministic SHA-256 checksum for an entire table's rows ordered by primary key."""
    row_digests: List[str] = []
    for r in rows:
        pk_str = "|".join(str(canonicalize_value(c, r.get(c))["v"]) for c in pk_cols)
        r_hash = compute_canonical_row_hash(r, columns)
        row_digests.append(f"{pk_str}:{r_hash}")
    row_digests.sort()
    combined = "\n".join(row_digests)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def diff_rows(src_row: Dict[str, Any], tgt_row: Dict[str, Any], columns: List[str]) -> Dict[str, Any]:
    diffs: Dict[str, Any] = {}
    for c in sorted(columns):
        sv = canonicalize_value(c, src_row.get(c))
        tv = canonicalize_value(c, tgt_row.get(c))
        if sv != tv:
            diffs[c] = {"source": sv, "target": tv}
    return diffs


def create_sqlite_snapshot(sqlite_path: Optional[str] = None) -> str:
    """Create a consistent point-in-time snapshot of the SQLite database using sqlite3.backup."""
    import database
    if not sqlite_path:
        sqlite_path = database.DB_PATH
    if not os.path.exists(sqlite_path):
        database.init_db()
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite database not found: {sqlite_path}")
    fd, snap_path = tempfile.mkstemp(prefix="gerege_sqlite_snap_", suffix=".db")
    os.close(fd)
    # Phase 56 (F-56-9). Two connections were opened here - `dst` on the fresh snapshot and `src`
    # on the live SQLite database that is about to be migrated - and both were closed on the last
    # two lines of the body. `src.backup(dst)` is the statement that can actually fail (a locked
    # database, a full disk, a corrupt page), and on failure it raised past both closes, leaving
    # the live database held open for the rest of the migration process. `with dst:` commits or
    # rolls the destination back but does not close it.
    #
    # The same shape as F-55-1 (59 request handlers leaked a write lock) and F-56-8 below, found
    # by the AST sweep rather than by reading: "every `sqlite3.connect` in this repository is
    # closed in a `finally`". The partial snapshot file is removed too, because the caller never
    # learns its path when this raises.
    src = sqlite3.connect(sqlite_path)
    backed_up = False
    try:
        dst = sqlite3.connect(snap_path)
        try:
            with dst:
                src.backup(dst)
        finally:
            dst.close()
        backed_up = True
        return snap_path
    finally:
        src.close()
        if not backed_up:
            try:
                os.unlink(snap_path)
            except OSError:
                pass


def inspect_sqlite_snapshot(snap_path: str) -> Dict[str, Any]:
    """Read row counts, column names, table checksums, and financial totals from SQLite snapshot.

    Phase 56 (F-56-8). The connection is opened here and released in a `finally`, around the
    roughly fifty statements in `_inspect_sqlite_snapshot`. Before this, `conn.close()` was the
    second-to-last line of the body, so any error in between - a snapshot missing a column, a
    checksum computed over a corrupt page, a `None` where a total was expected - left the snapshot
    file open for the rest of the migration process. That is the same class as F-55-1, in a script
    rather than in a request handler: a SQLite connection holds a lock, and this one is opened on
    the database that is about to be migrated. The signature is unchanged, and the body moved
    verbatim into the helper below.
    """
    conn = sqlite3.connect(snap_path)
    try:
        return _inspect_sqlite_snapshot(conn)
    finally:
        conn.close()


def _inspect_sqlite_snapshot(conn) -> Dict[str, Any]:
    """The body of :func:`inspect_sqlite_snapshot`. It owns no connection and closes none."""
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    existing_tables = {
        r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }

    table_stats: Dict[str, Any] = {}
    table_checksums: List[str] = []
    for item in MIGRATION_TABLES:
        tname = item["table"]
        pk_cols = item["pk_cols"]
        if tname not in existing_tables:
            table_stats[tname] = {"exists": False, "row_count": 0, "columns": [], "checksum": ""}
            continue
        # Phase 26: `tname` is a constant but `pk_cols` is written in the same constant;
        # both are validated so a future entry cannot introduce an unquoted name.
        qtname = _q_ident(tname)
        cols = [r[1] for r in cur.execute(f"PRAGMA table_info({qtname})").fetchall()]
        order_clause = ", ".join(_q_ident_list(pk_cols))
        rows = [dict(r) for r in cur.execute(f"SELECT * FROM {qtname} ORDER BY {order_clause}").fetchall()]  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
        tbl_checksum = compute_table_checksum(rows, cols, pk_cols)
        table_stats[tname] = {
            "exists": True,
            "row_count": len(rows),
            "columns": cols,
            "pk_cols": pk_cols,
            "checksum": tbl_checksum,
        }
        table_checksums.append(f"{tname}:{tbl_checksum}")

    overall_checksum = hashlib.sha256("\n".join(sorted(table_checksums)).encode("utf-8")).hexdigest()

    financials = {
        "invoices_total_amount": 0,
        "invoices_paid_amount": 0,
        "cargo_total_price": 0,
    }
    if "invoices" in existing_tables:
        financials["invoices_total_amount"] = int(
            cur.execute("SELECT COALESCE(SUM(amount), 0) FROM invoices").fetchone()[0] or 0
        )
        financials["invoices_paid_amount"] = int(
            cur.execute("SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE status = 'PAID'").fetchone()[0] or 0
        )
    if "cargo_packages" in existing_tables:
        financials["cargo_total_price"] = int(
            cur.execute("SELECT COALESCE(SUM(price_amount), 0) FROM cargo_packages").fetchone()[0] or 0
        )

    return {
        "tables": table_stats,
        "overall_checksum": overall_checksum,
        "financials": financials,
    }


def run_migration(
    sqlite_path: Optional[str] = None,
    postgres_url: Optional[str] = None,
    dry_run: bool = False,
    report_path: Optional[str] = None,
    batch_size: int = 500,
) -> Dict[str, Any]:
    if not sqlite_path:
        import database
        sqlite_path = database.DB_PATH
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    snap_path = create_sqlite_snapshot(sqlite_path)
    try:
        source_summary = inspect_sqlite_snapshot(snap_path)
        report: Dict[str, Any] = {
            "started_at": started_at,
            "completed_at": None,
            "timestamp": started_at,
            "sqlite_source": os.path.abspath(sqlite_path),
            "dry_run": dry_run,
            "batch_size": batch_size,
            "source_summary": source_summary,
            "migrated_tables": {},
            "conflicts": [],
            "verification": {},
            "status": "DRY_RUN_OK" if dry_run else "PENDING",
        }

        if dry_run:
            report["completed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if report_path:
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
            return report

        if not postgres_url:
            raise ValueError("Target database URL (--postgres-url or DATABASE_URL) is required when not running --dry-run")

        src_conn = sqlite3.connect(snap_path)
        src_conn.row_factory = sqlite3.Row
        src_cur = src_conn.cursor()

        is_sqlite_target = postgres_url.startswith("sqlite:///")
        if is_sqlite_target:
            tgt_sqlite_path = postgres_url.replace("sqlite:///", "", 1)
            tgt_raw_conn = sqlite3.connect(tgt_sqlite_path)
            tgt_raw_conn.row_factory = sqlite3.Row
            # Ensure target has identical schema DDL without auto-seeded random rows
            for ddl_row in src_cur.execute(
                "SELECT sql FROM sqlite_master WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL"
            ).fetchall():
                ddl_sql = re.sub(r"^CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS\b)", "CREATE TABLE IF NOT EXISTS ", ddl_row[0], flags=re.IGNORECASE)
                ddl_sql = re.sub(r"^CREATE\s+(UNIQUE\s+)?INDEX\s+(?!IF\s+NOT\s+EXISTS\b)", r"CREATE \1INDEX IF NOT EXISTS ", ddl_sql, flags=re.IGNORECASE)
                tgt_raw_conn.execute(ddl_sql)
            tgt_raw_conn.commit()

            def _tgt_fetch_one(q_cols: List[str], tname: str, pk_cols: List[str], pk_vals: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                w_sql = " AND ".join(f"{_q_ident(c)} = ?" for c in pk_cols)
                row = tgt_raw_conn.execute(
                    f"SELECT {', '.join(_q_ident_list(q_cols))} FROM {_q_ident(tname)} WHERE {w_sql}",  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                    tuple(pk_vals[c] for c in pk_cols),
                ).fetchone()
                return dict(row) if row is not None else None

            def _tgt_insert(tname: str, q_cols: List[str], row_dict: Dict[str, Any]) -> None:
                c_list = ", ".join(_q_ident_list(q_cols))
                q_marks = ", ".join("?" for _ in q_cols)
                tgt_raw_conn.execute(
                    f"INSERT INTO {_q_ident(tname)} ({c_list}) VALUES ({q_marks})",  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                    tuple(row_dict.get(c) for c in q_cols),
                )

            def _tgt_fetch_batch(
                q_cols: List[str], tname: str, order_clause: str, limit: int, offset: int
            ) -> List[Dict[str, Any]]:
                rows = tgt_raw_conn.execute(
                    f"SELECT {', '.join(_q_ident_list(q_cols))} FROM {_q_ident(tname)} ORDER BY {order_clause} LIMIT ? OFFSET ?",  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                    (limit, offset),
                ).fetchall()
                return [dict(r) for r in rows]

            def _tgt_scalar(sql_str: str) -> int:
                r = tgt_raw_conn.execute(sql_str).fetchone()
                return int(r[0] or 0) if r else 0

            def _tgt_reset_seq(tname: str) -> None:
                pass

            def _tgt_commit() -> None:
                tgt_raw_conn.commit()
                tgt_raw_conn.close()

            def _tgt_rollback() -> None:
                tgt_raw_conn.rollback()
                tgt_raw_conn.close()
        else:
            from sqlalchemy import create_engine, text
            from core.models import Base

            pg_engine = create_engine(postgres_url, pool_pre_ping=True, future=True)
            Base.metadata.create_all(bind=pg_engine)
            pg_conn = pg_engine.connect()
            pg_trans = pg_conn.begin()

            def _tgt_fetch_one(q_cols: List[str], tname: str, pk_cols: List[str], pk_vals: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                w_sql = " AND ".join(f"{_q_ident(c)} = :{c}" for c in pk_cols)
                row = pg_conn.execute(
                    text(f"SELECT {', '.join(_q_ident_list(q_cols))} FROM {_q_ident(tname)} WHERE {w_sql}"),  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                    pk_vals,
                ).mappings().first()
                return dict(row) if row is not None else None

            def _tgt_insert(tname: str, q_cols: List[str], row_dict: Dict[str, Any]) -> None:
                c_list = ", ".join(_q_ident_list(q_cols))
                b_list = ", ".join(f":{c}" for c in q_cols)
                pg_conn.execute(
                    text(f"INSERT INTO {_q_ident(tname)} ({c_list}) VALUES ({b_list})"),  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                    row_dict,
                )

            def _tgt_fetch_batch(
                q_cols: List[str], tname: str, order_clause: str, limit: int, offset: int
            ) -> List[Dict[str, Any]]:
                rows = (
                    pg_conn.execute(
                        text(
                            f"SELECT {', '.join(_q_ident_list(q_cols))} FROM {_q_ident(tname)} "  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                            f"ORDER BY {order_clause} LIMIT :lim OFFSET :off"
                        ),
                        {"lim": limit, "off": offset},
                    )
                    .mappings()
                    .all()
                )
                return [dict(r) for r in rows]

            def _tgt_scalar(sql_str: str) -> int:
                return int(pg_conn.execute(text(sql_str)).scalar() or 0)

            def _tgt_reset_seq(tname: str) -> None:
                pg_conn.execute(
                    text(
                        f"SELECT setval(pg_get_serial_sequence('{_q_ident(tname)}', 'id'), "  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                        f"COALESCE((SELECT MAX(id) FROM {_q_ident(tname)}), 1), true)"
                    )
                )

            def _tgt_commit() -> None:
                pg_trans.commit()
                pg_conn.close()

            def _tgt_rollback() -> None:
                pg_trans.rollback()
                pg_conn.close()

        try:
            for item in MIGRATION_TABLES:
                tname = item["table"]
                pk_cols = item["pk_cols"]
                tinfo = source_summary["tables"].get(tname, {})
                if not tinfo.get("exists"):
                    tgt_cnt_empty = _tgt_scalar(f"SELECT COUNT(*) FROM {_q_ident(tname)}")  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                    report["migrated_tables"][tname] = {
                        "source_rows": 0,
                        "target_rows": tgt_cnt_empty,
                        "inserted_rows": 0,
                        "identical_skipped": 0,
                        "missing_rows": 0,
                        "target_only_rows": tgt_cnt_empty,
                        "conflicting_rows": 0,
                        "source_checksum": "",
                        "target_checksum": "",
                        "checksum_match": tgt_cnt_empty == 0,
                        "match": tgt_cnt_empty == 0,
                    }
                    continue

                cols = tinfo["columns"]
                order_clause = ", ".join(_q_ident_list(pk_cols))
                total_src_rows = tinfo["row_count"]

                inserted_count = 0
                identical_skipped = 0
                table_conflicts: List[Dict[str, Any]] = []

                offset = 0
                while offset < total_src_rows:
                    batch_rows = [
                        dict(r)
                        for r in src_cur.execute(
                            f"SELECT * FROM {_q_ident(tname)} ORDER BY {order_clause} LIMIT ? OFFSET ?",  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                            (batch_size, offset),
                        ).fetchall()
                    ]
                    if not batch_rows:
                        break

                    for src_row in batch_rows:
                        where_params = {c: src_row.get(c) for c in pk_cols}
                        existing_target = _tgt_fetch_one(cols, tname, pk_cols, where_params)

                        if existing_target is not None:
                            src_hash = compute_canonical_row_hash(src_row, cols)
                            tgt_hash = compute_canonical_row_hash(existing_target, cols)
                            if src_hash == tgt_hash:
                                identical_skipped += 1
                            else:
                                conflict_entry = {
                                    "table": tname,
                                    "primary_key": where_params,
                                    "source_hash": src_hash,
                                    "target_hash": tgt_hash,
                                    "column_diffs": diff_rows(src_row, existing_target, cols),
                                }
                                table_conflicts.append(conflict_entry)
                                report["conflicts"].append(conflict_entry)
                        else:
                            _tgt_insert(tname, cols, src_row)
                            inserted_count += 1

                    offset += len(batch_rows)

                if table_conflicts:
                    raise RuntimeError(
                        f"Conflict detected in table '{tname}': {len(table_conflicts)} conflicting row(s) found."
                    )

                if item.get("has_serial_id") and "id" in cols:
                    _tgt_reset_seq(tname)

                # Bounded-memory batch-based streaming verification:
                # 1) Stream source batches -> verify every PK & row hash exists identically on target
                # 2) Stream target batches -> detect any target-only extra rows
                target_count = _tgt_scalar(f"SELECT COUNT(*) FROM {_q_ident(tname)}")  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                missing_rows = 0
                verify_conflicts = 0
                src_stream_hasher = hashlib.sha256()
                tgt_stream_hasher = hashlib.sha256()

                v_offset = 0
                while v_offset < total_src_rows:
                    src_batch = [
                        dict(r)
                        for r in src_cur.execute(
                            f"SELECT * FROM {_q_ident(tname)} ORDER BY {order_clause} LIMIT ? OFFSET ?",  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                            (batch_size, v_offset),
                        ).fetchall()
                    ]
                    if not src_batch:
                        break
                    for srow in src_batch:
                        pk_params = {c: srow.get(c) for c in pk_cols}
                        pk_str = "|".join(str(canonicalize_value(c, srow.get(c))["v"]) for c in pk_cols)
                        s_hash = compute_canonical_row_hash(srow, cols)
                        src_stream_hasher.update(f"{pk_str}:{s_hash}\n".encode("utf-8"))

                        trow = _tgt_fetch_one(cols, tname, pk_cols, pk_params)
                        if trow is None:
                            missing_rows += 1
                        else:
                            t_hash = compute_canonical_row_hash(trow, cols)
                            tgt_stream_hasher.update(f"{pk_str}:{t_hash}\n".encode("utf-8"))
                            if s_hash != t_hash:
                                verify_conflicts += 1
                    v_offset += len(src_batch)

                target_only_rows = 0
                extra_target_samples: List[Dict[str, Any]] = []
                pk_where_src = " AND ".join(f"{_q_ident(c)} = ?" for c in pk_cols)
                tgt_offset = 0
                while True:
                    tgt_batch = _tgt_fetch_batch(cols, tname, order_clause, batch_size, tgt_offset)
                    if not tgt_batch:
                        break
                    for trow in tgt_batch:
                        pk_tuple = tuple(trow.get(c) for c in pk_cols)
                        exists_in_src = src_cur.execute(
                            f"SELECT 1 FROM {_q_ident(tname)} WHERE {pk_where_src} LIMIT 1",  # nosec B608 - Phase 26: identifiers go through _q_ident()/_q_ident_list(); values are bound
                            pk_tuple,
                        ).fetchone()
                        if exists_in_src is None:
                            target_only_rows += 1
                            if len(extra_target_samples) < 10:
                                extra_target_samples.append({c: trow.get(c) for c in pk_cols})
                    tgt_offset += len(tgt_batch)

                src_checksum = src_stream_hasher.hexdigest()
                tgt_checksum = tgt_stream_hasher.hexdigest()
                exact_count_match = total_src_rows == target_count
                checksum_match = (
                    (src_checksum == tgt_checksum)
                    and exact_count_match
                    and (missing_rows == 0)
                    and (target_only_rows == 0)
                    and (verify_conflicts == 0)
                )

                report["migrated_tables"][tname] = {
                    "source_rows": total_src_rows,
                    "target_rows": target_count,
                    "inserted_rows": inserted_count,
                    "identical_skipped": identical_skipped,
                    "missing_rows": missing_rows,
                    "target_only_rows": target_only_rows,
                    "extra_target_samples": extra_target_samples,
                    "conflicting_rows": len(table_conflicts) + verify_conflicts,
                    "source_checksum": src_checksum,
                    "target_checksum": tgt_checksum,
                    "checksum_match": checksum_match,
                    "match": checksum_match and (len(table_conflicts) == 0),
                }

            pg_inv_total = _tgt_scalar("SELECT COALESCE(SUM(amount), 0) FROM invoices")
            pg_inv_paid = _tgt_scalar("SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE status = 'PAID'")
            pg_cargo_total = _tgt_scalar("SELECT COALESCE(SUM(price_amount), 0) FROM cargo_packages")
            _tgt_commit()
        except RuntimeError as conflict_err:
            _tgt_rollback()
            src_conn.close()
            report["completed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report["status"] = "CONFLICT_DETECTED"
            report["error"] = str(conflict_err)
            if report_path:
                with open(report_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
            return report
        except Exception:
            _tgt_rollback()
            src_conn.close()
            raise

        src_conn.close()

        src_fin = source_summary["financials"]
        fin_ok = (
            pg_inv_total == src_fin["invoices_total_amount"]
            and pg_inv_paid == src_fin["invoices_paid_amount"]
            and pg_cargo_total == src_fin["cargo_total_price"]
        )
        rows_ok = all(
            v.get("match", False)
            and v.get("checksum_match", False)
            and v.get("missing_rows", 1) == 0
            and v.get("target_only_rows", 1) == 0
            and v.get("conflicting_rows", 1) == 0
            and v.get("source_rows") == v.get("target_rows")
            for v in report["migrated_tables"].values()
        )
        total_target_only = sum(v.get("target_only_rows", 0) for v in report["migrated_tables"].values())

        report["completed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report["verification"] = {
            "rows_verified": rows_ok,
            "checksums_verified": rows_ok,
            "conflicts_count": len(report["conflicts"]),
            "target_only_rows_total": total_target_only,
            "financials_verified": fin_ok,
            "source_financials": src_fin,
            "target_financials": {
                "invoices_total_amount": pg_inv_total,
                "invoices_paid_amount": pg_inv_paid,
                "cargo_total_price": pg_cargo_total,
            },
        }
        report["status"] = "SUCCESS" if (rows_ok and fin_ok and not report["conflicts"]) else "VERIFICATION_MISMATCH"

        if report_path:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        return report
    finally:
        if os.path.exists(snap_path):
            try:
                os.remove(snap_path)
            except Exception:
                pass


def main() -> None:
    import database
    parser = argparse.ArgumentParser(description="Safe SQLite-to-PostgreSQL Migration Tool")
    parser.add_argument("--sqlite-path", default=os.getenv("DB_PATH", database.DB_PATH))
    parser.add_argument("--postgres-url", default=os.getenv("POSTGRES_URL") or os.getenv("DATABASE_URL"))
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--dry-run", action="store_true", help="Inspect SQLite snapshot and compute canonical checksums without writing to target")
    parser.add_argument("--report", default="", help="Optional path to write JSON migration report")
    args = parser.parse_args()

    res = run_migration(
        sqlite_path=args.sqlite_path,
        postgres_url=args.postgres_url,
        dry_run=args.dry_run,
        report_path=args.report or None,
        batch_size=args.batch_size,
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    if res["status"] not in ("DRY_RUN_OK", "SUCCESS"):
        sys.exit(1)


if __name__ == "__main__":
    main()
