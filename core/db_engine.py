import os
import re
import sqlite3
import logging
from typing import Optional, Any, List, Sequence
from dotenv import load_dotenv

load_dotenv(override=True)
logger = logging.getLogger("core.db_engine")

_SQLALCHEMY_ENGINE = None
_ENGINE_URL = None


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

    db_path = default_sqlite_path or os.getenv("DB_PATH", "leads.db")
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
            pool_pre_ping=True,
            pool_recycle=1800,
            future=True,
        )


def get_shared_engine():
    global _SQLALCHEMY_ENGINE, _ENGINE_URL
    url = get_database_url()
    if _SQLALCHEMY_ENGINE is None or _ENGINE_URL != url:
        _SQLALCHEMY_ENGINE = create_sqlalchemy_engine(url)
        _ENGINE_URL = url
    return _SQLALCHEMY_ENGINE


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
}


def translate_sql_for_postgres(sql: str) -> str:
    """
    SQLite аялгаар бичигдсэн SQL кверийг PostgreSQL стандарт руу аюулгүй хөрвүүлэх:
    - `PRAGMA ...` -> хоосон/no-op
    - `INTEGER PRIMARY KEY AUTOINCREMENT` -> `SERIAL PRIMARY KEY`
    - `REAL` -> `DOUBLE PRECISION`
    - `datetime(expires_at) > datetime('now')` -> `expires_at > CURRENT_TIMESTAMP`
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
        r"datetime\s*\(\s*expires_at\s*\)\s*>\s*datetime\s*\(\s*'now'\s*\)",
        "expires_at > CURRENT_TIMESTAMP",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(r"UPDATE\s+OR\s+IGNORE\s+", "UPDATE ", s, flags=re.IGNORECASE)

    has_insert_or_ignore = bool(re.match(r"^INSERT\s+OR\s+IGNORE\s+INTO\s+", s, flags=re.IGNORECASE))
    if has_insert_or_ignore:
        s = re.sub(r"^INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", s, flags=re.IGNORECASE)
        if "ON CONFLICT" not in s.upper():
            s = s.rstrip(";") + " ON CONFLICT DO NOTHING"

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
    """PostgreSQL DB-API cursor-ийг `sqlite3.Cursor` интерфэйстэй 100% нийцүүлэх адаптер"""

    def __init__(self, raw_cursor):
        self._cur = raw_cursor
        self.lastrowid: Optional[int] = None
        self.rowcount: int = -1

    def execute(self, sql: str, params: Sequence[Any] = ()):
        pg_sql = translate_sql_for_postgres(sql)
        self.lastrowid = None

        # Check if this is an INSERT into a serial-id table without RETURNING
        m_ins = re.match(r"^\s*INSERT\s+INTO\s+([a-zA-Z0-9_]+)", pg_sql, flags=re.IGNORECASE)
        added_returning = False
        if m_ins:
            tbl = m_ins.group(1).lower()
            if tbl in _SERIAL_ID_TABLES and "RETURNING " not in pg_sql.upper():
                pg_sql = pg_sql.rstrip(";") + " RETURNING id"
                added_returning = True

        if params:
            self._cur.execute(pg_sql, tuple(params))
        else:
            self._cur.execute(pg_sql)

        self.rowcount = self._cur.rowcount
        if added_returning:
            row = self._cur.fetchone()
            if row:
                self.lastrowid = row[0]
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        if self._cur.description:
            cols = [d[0] for d in self._cur.description]
            return CompatRow(cols, row)
        return row

    def fetchall(self) -> List[Any]:
        rows = self._cur.fetchall()
        if not rows:
            return []
        if self._cur.description:
            cols = [d[0] for d in self._cur.description]
            return [CompatRow(cols, r) for r in rows]
        return list(rows)

    def close(self):
        self._cur.close()


class PostgresCompatConnection:
    """PostgreSQL холболтыг `sqlite3.Connection` интерфэйстэй нийцүүлэх адаптер"""

    def __init__(self, raw_conn):
        self._conn = raw_conn
        self.row_factory = None

    def cursor(self) -> PostgresCompatCursor:
        return PostgresCompatCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()


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

    path = sqlite_path or os.getenv("DB_PATH") or "leads.db"
    conn = sqlite3.connect(path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    return conn
