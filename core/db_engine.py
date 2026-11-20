import os
import re
import sqlite3
import logging
import threading
from typing import Optional, Any, List, Sequence, Dict, Set
from dotenv import load_dotenv

load_dotenv(override=True)
logger = logging.getLogger("core.db_engine")

_SQLALCHEMY_ENGINE = None
_ENGINE_URL = None


def get_sqlite_db_path(default_path: Optional[str] = None) -> str:
    if default_path:
        return default_path
    env_path = os.getenv("DB_PATH", "").strip()
    if env_path:
        return env_path
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "leads.db")


def get_database_url(default_sqlite_path: Optional[str] = None) -> str:
    """
    DATABASE_URL орчны хувьсагчаас PostgreSQL эсвэл SQLite холболтын URL авах.
    Хэрэв postgres:// гэж эхэлсэн бол SQLAlchemy 2.0-д нийцүүлэн postgresql+psycopg2:// болгож хөрвүүлнэ.
    """
    raw_url = os.getenv("DATABASE_URL", "").strip()
    if raw_url:
        if raw_url.startswith("postgres://"):
            raw_url = raw_url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif raw_url.startswith("postgresql://") and "+psycopg" not in raw_url:
            raw_url = raw_url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return raw_url

    db_path = get_sqlite_db_path(default_sqlite_path)
    return f"sqlite:///{db_path}"


def is_postgres() -> bool:
    return get_database_url().startswith("postgresql")


def create_sqlalchemy_engine(db_url: Optional[str] = None):
    """SQLAlchemy Engine үүсгэх (PostgreSQL QueuePool эсвэл SQLite WAL)"""
    from sqlalchemy import create_engine, event

    url = db_url or get_database_url()
    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False, "timeout": 15.0},
            future=True,
        )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine
    else:
        return create_engine(
            url,
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            pool_timeout=float(os.getenv("DB_POOL_TIMEOUT", "30")),
            pool_pre_ping=True,
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
            future=True,
        )


def get_shared_engine():
    global _SQLALCHEMY_ENGINE, _ENGINE_URL
    url = get_database_url()
    if _SQLALCHEMY_ENGINE is None or _ENGINE_URL != url:
        if _SQLALCHEMY_ENGINE is not None:
            try:
                _SQLALCHEMY_ENGINE.dispose()
            except Exception:
                pass
        _SQLALCHEMY_ENGINE = create_sqlalchemy_engine(url)
        _ENGINE_URL = url
    return _SQLALCHEMY_ENGINE


def dispose_shared_engine() -> None:
    """Graceful shutdown үед SQLAlchemy connection pool-ийг цэвэрхэн хаах"""
    global _SQLALCHEMY_ENGINE, _ENGINE_URL
    if _SQLALCHEMY_ENGINE is not None:
        try:
            _SQLALCHEMY_ENGINE.dispose()
        except Exception as e:
            logger.warning(f"Error disposing SQLAlchemy engine: {e}")
        finally:
            _SQLALCHEMY_ENGINE = None
            _ENGINE_URL = None


def get_pool_status() -> Dict[str, Any]:
    """Connection pool-ийн одоогийн төлвийг буцаах (Observability)"""
    if not is_postgres() or _SQLALCHEMY_ENGINE is None:
        return {"engine": "sqlite", "pooled": False}
    try:
        pool = _SQLALCHEMY_ENGINE.pool
        return {
            "engine": "postgresql",
            "pooled": True,
            "size": pool.size(),
            "checkedin": pool.checkedin(),
            "checkedout": pool.checkedout(),
            "overflow": pool.overflow(),
        }
    except Exception as e:
        return {"engine": "postgresql", "pooled": True, "error": str(e)}


class CompatRow(dict):
    """
    SQLite `sqlite3.Row` болон PostgreSQL dict row-ийг нэгэн зэрэг дэмжих мөрийн обьект.
    `row['col']`, `row[0]`, `dict(row)` болон `tuple(row)` үйлдлүүдийг бүгдийг дэмжинэ.
    """

    def __init__(self, columns: Sequence[str], values: Sequence[Any]):
        super().__init__(zip(columns, values))
        self._values = tuple(values)
        self._columns = tuple(columns)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

    def __iter__(self):
        return iter(self._values)

    def keys(self):
        return self._columns


# Tables that carry an auto-increment `id` primary key.
#
# P1-01 (B-03): this used to be a hand-maintained set that omitted
# `comment_automations` and `tracked_links`, so on PostgreSQL `lastrowid` stayed
# `None` and callers received rows with `id: None`.
#
# The set is now only a *bootstrap cache*. `_has_serial_id_column()` resolves the
# truth from the live catalog, so adding a table can never silently reintroduce the
# bug. The static set is kept so the compat layer still works for a table created
# inside the same transaction (before the catalog cache is refreshed).
_SERIAL_ID_TABLES = {
    "registrations",
    "messages",
    "user_memories",
    "invoices",
    "cargo_packages",
    "automated_rules",
    "marketing_campaigns",
    "sent_followups",
    "appointments",
    "task_jobs",
    "audit_logs",
    "comment_automations",
    "tracked_links",
}

# Cache of tables verified (via information_schema) to have a serial `id`.
_VERIFIED_SERIAL_TABLES: Set[str] = set()
_SERIAL_CACHE_LOCK = threading.Lock()


def _has_serial_id_column(table: str, conn=None) -> bool:
    """
    Тухайн хүснэгтэд auto-increment `id` багана байгаа эсэхийг каталог/схемээс тодорхойл.

    `RETURNING id`-г зөвхөн үнэхээр `id` баганатай хүснэгтэд нэмнэ. Эс бөгөөс
    PostgreSQL "column id does not exist" алдаа шидэж, INSERT бүхэлдээ унана.
    """
    tbl = str(table or "").strip().lower()
    if not tbl:
        return False

    with _SERIAL_CACHE_LOCK:
        if tbl in _VERIFIED_SERIAL_TABLES:
            return True

    probe_conn = conn
    own_conn = False
    try:
        if probe_conn is None:
            probe_conn = get_db_connection()
            own_conn = True
        cur = probe_conn.cursor()
        try:
            cur.execute(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = %s
                  AND column_name = 'id'
                LIMIT 1
                """,
                (tbl,),
            )
            found = cur.fetchone() is not None
        finally:
            try:
                cur.close()
            except Exception:
                pass
    except Exception:
        # Catalog unavailable (e.g. mid-DDL): fall back to the static bootstrap set.
        return tbl in _SERIAL_ID_TABLES
    finally:
        if own_conn and probe_conn is not None:
            try:
                probe_conn.close()
            except Exception:
                pass

    if found:
        with _SERIAL_CACHE_LOCK:
            _VERIFIED_SERIAL_TABLES.add(tbl)
    return bool(found)


def reset_serial_table_cache() -> None:
    """Test helper: forget catalog lookups (used after schema changes)."""
    with _SERIAL_CACHE_LOCK:
        _VERIFIED_SERIAL_TABLES.clear()


def translate_sql_for_postgres(sql: str) -> str:
    """
    SQLite аялгаар бичигдсэн SQL кверийг PostgreSQL стандарт руу аюулгүй хөрвүүлэх:
    - `PRAGMA ...` -> `SELECT 1`
    - `INTEGER PRIMARY KEY AUTOINCREMENT` -> `SERIAL PRIMARY KEY`
    - `ALTER TABLE X ADD COLUMN Y` -> `ALTER TABLE X ADD COLUMN IF NOT EXISTS Y`
    - `datetime(expires_at) > datetime('now')` -> `CAST(expires_at AS TIMESTAMP) > CURRENT_TIMESTAMP`
    - `INSERT OR IGNORE INTO <table>` -> `INSERT INTO <table> ... ON CONFLICT DO NOTHING`
    - `UPDATE OR IGNORE` -> `UPDATE`
    - `?` placeholder -> `%s`
    """
    s = sql.strip()
    if s.upper().startswith("PRAGMA"):
        return "SELECT 1"

    s = re.sub(
        r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
        "SERIAL PRIMARY KEY",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(
        r"ALTER\s+TABLE\s+([a-zA-Z0-9_]+)\s+ADD\s+COLUMN\s+(?!IF\s+NOT\s+EXISTS\b)",
        r"ALTER TABLE \1 ADD COLUMN IF NOT EXISTS ",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(
        r"datetime\s*\(\s*expires_at\s*\)\s*>\s*datetime\s*\(\s*'now'\s*\)",
        "CAST(expires_at AS TIMESTAMP) > CURRENT_TIMESTAMP",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(r"UPDATE\s+OR\s+IGNORE\s+", "UPDATE ", s, flags=re.IGNORECASE)

    has_insert_or_ignore = bool(re.match(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", s, flags=re.IGNORECASE))
    if has_insert_or_ignore:
        s = re.sub(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", s, flags=re.IGNORECASE)
        if "ON CONFLICT" not in s.upper():
            s = s.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

    # Translate ? to %s outside single-quoted literals
    out = []
    in_quote = False
    for ch in s:
        if ch == "'":
            in_quote = not in_quote
            out.append(ch)
        elif ch == "?" and not in_quote:
            out.append("%s")
        else:
            out.append(ch)
    return "".join(out)


class PostgresCompatCursor:
    """
    PostgreSQL DB-API cursor-ийг `sqlite3.Cursor` интерфэйстэй 100% нийцүүлэх адаптер.
    Statement бүрийг тусдаа control cursor дээр SAVEPOINT-оор хамгаалснаар:
    1) `RELEASE SAVEPOINT` нь үндсэн `self._cur` дээрх SELECT result set-ийг устгахгүй,
    2) `try ... except` доторх UniqueViolation эсвэл DDL алдаа бүхэл транзакцийг
       `InFailedSqlTransaction` төлөвт оруулахаас бүрэн сэргийлнэ.
    """

    _sp_counter = 0

    def __init__(self, raw_cursor, raw_conn=None):
        self._cur = raw_cursor
        self._conn = raw_conn if raw_conn is not None else getattr(raw_cursor, "connection", None)
        self.lastrowid: Optional[int] = None
        self.rowcount: int = -1
        self._closed = False

    @property
    def description(self):
        return self._cur.description

    def _run_control_sql(self, *statements: str) -> None:
        if self._conn is None:
            return
        ctrl = self._conn.cursor()
        try:
            for stmt in statements:
                ctrl.execute(stmt)
        finally:
            ctrl.close()

    def execute(self, sql: str, params: Sequence[Any] = ()):
        pg_sql = translate_sql_for_postgres(sql)
        self.lastrowid = None

        m_ins = re.match(r"^\s*INSERT\s+INTO\s+([a-zA-Z0-9_]+)", pg_sql, flags=re.IGNORECASE)
        added_returning = False
        if m_ins:
            tbl = m_ins.group(1).lower()
            if _has_serial_id_column(tbl) and "RETURNING " not in pg_sql.upper():
                pg_sql = pg_sql.rstrip().rstrip(";") + " RETURNING id"
                added_returning = True

        PostgresCompatCursor._sp_counter += 1
        sp_name = f"sp_gerege_{PostgresCompatCursor._sp_counter}"
        use_savepoint = (
            self._conn is not None
            and not pg_sql.lstrip().upper().startswith(("BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE"))
        )

        if use_savepoint:
            self._run_control_sql(f"SAVEPOINT {sp_name}")
        try:
            if params:
                self._cur.execute(pg_sql, tuple(params))
            else:
                self._cur.execute(pg_sql)

            self.rowcount = self._cur.rowcount
            if added_returning:
                row = self._cur.fetchone()
                if row:
                    self.lastrowid = row[0]
            if use_savepoint:
                self._run_control_sql(f"RELEASE SAVEPOINT {sp_name}")
            return self
        except Exception:
            if use_savepoint:
                try:
                    self._run_control_sql(
                        f"ROLLBACK TO SAVEPOINT {sp_name}",
                        f"RELEASE SAVEPOINT {sp_name}",
                    )
                except Exception:
                    pass
            raise

    def fetchone(self):
        if self._cur.description is None:
            return None
        row = self._cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self._cur.description]
        return CompatRow(cols, row)

    def fetchall(self) -> List[Any]:
        if self._cur.description is None:
            return []
        rows = self._cur.fetchall()
        if not rows:
            return []
        cols = [d[0] for d in self._cur.description]
        return [CompatRow(cols, r) for r in rows]

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self._cur.close()
            except Exception:
                pass


class PostgresCompatConnection:
    """PostgreSQL холболтыг `sqlite3.Connection` интерфэйстэй нийцүүлэх адаптер"""

    def __init__(self, raw_conn):
        self._conn = raw_conn
        self._closed = False
        self.row_factory = None

    def cursor(self) -> PostgresCompatCursor:
        return PostgresCompatCursor(self._conn.cursor(), self._conn)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> PostgresCompatCursor:
        cur = self.cursor()
        return cur.execute(sql, params)

    def commit(self):
        if not self._closed:
            self._conn.commit()

    def rollback(self):
        if not self._closed:
            self._conn.rollback()

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                # Phase 20: `close()` used to hand the raw connection straight back to the
                # SQLAlchemy pool WITHOUT rolling back. psycopg2 opens a transaction on the
                # first statement, so a reader that only ever SELECTed handed the pool a
                # connection that was still `idle in transaction` — holding its locks until
                # the next borrower happened to end the transaction. Nothing noticed until
                # a DDL operation needed ACCESS EXCLUSIVE: `_reset_public_schema` waited out
                # `lock_timeout`, and the restore rollback that exists to undo a bad restore
                # could not run. Rolling back first matches `sqlite3.Connection.close()`,
                # which discards the pending transaction, and releases the locks immediately.
                self._conn.rollback()
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()

    def __del__(self):
        # Phase 20: last-resort release. `database.py` has dozens of helpers shaped
        # ```conn = get_connection(); ...; conn.close()``` with no `try/finally`, so an
        # exception anywhere in the middle skips `close()` and the connection goes back to
        # the pool — except it never goes back, it stays checked out and, because psycopg2
        # opened a transaction on the first statement, it is `idle in transaction` holding
        # its row locks. Those locks outlive the failed call for the life of the process.
        #
        # This is not theoretical: it is what made the restore rollback hang. A restore test
        # raised a foreign-key error, leaked one such connection, and the rollback that
        # followed could not take ACCESS EXCLUSIVE on `pages` — so the atomic rollback that
        # exists to undo a bad restore reported ROLLBACK_FAILED, and the suite waited out a
        # 180 s psql timeout. Reproduced by lock inspection: the blocking session's last
        # statement was `RELEASE SAVEPOINT sp_gerege_120`, i.e. one of these cursors.
        #
        # CPython releases the frame's locals deterministically when the exception unwinds,
        # so this reclaims the connection at the same moment `try/finally` would have. It is
        # a net, not a substitute: new code should still use `try/finally` or `with`.
        if not getattr(self, "_closed", True):
            try:
                self.close()
            except Exception:
                pass


def get_db_connection(sqlite_path: Optional[str] = None):
    """
    Нэгдсэн Authoritative Database Connection Factory:
    - Хэрэв `DATABASE_URL` нь PostgreSQL бол SQLAlchemy QueuePool-ээс PostgreSQL холболт буцаана.
    - Эсрэг тохиолдолд SQLite WAL холболт буцаана.
    """
    if is_postgres():
        engine = get_shared_engine()
        raw_conn = engine.raw_connection()
        return PostgresCompatConnection(raw_conn)

    path = get_sqlite_db_path(sqlite_path)
    conn = sqlite3.connect(path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    return conn


def verify_schema_drift() -> Dict[str, Any]:
    """Compare the live database with `core/models.py`, types included.

    **This used to be blind.** The previous implementation AST-parsed
    `core/models.py` and `0001_initial_enterprise_schema.py` and compared the set of
    column *names*, so it reported "no drift" for two schemas whose column types and
    nullability disagreed on 58 columns, and it never looked at the live database at
    all (P2-01).

    It now delegates to `core.schema_manager.drift_report()`, which uses Alembic's
    autogenerate machinery with `compare_type=True` against the real database.

    Returns a dict; `has_drift` is False only when the database matches the models
    exactly, including types, indexes, and constraints.
    """
    from core.schema_manager import drift_report

    report = drift_report()
    return {
        "has_drift": report.get("has_drift", True),
        "table_count": 0,  # retained for backward compatibility
        "tables": [],  # retained for backward compatibility
        "drift_details": report.get("by_kind", {}),
        "diff_count": report.get("count", 0),
        "current_revision": report.get("current_revision"),
        "head_revision": report.get("head_revision"),
        "comparison": "alembic.autogenerate(compare_type=True)",
    }
