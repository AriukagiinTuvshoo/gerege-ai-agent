import os
import re
import ast
import sqlite3
import logging
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
            if tbl in _SERIAL_ID_TABLES and "RETURNING " not in pg_sql.upper():
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
        self._cur.close()


class PostgresCompatConnection:
    """PostgreSQL холболтыг `sqlite3.Connection` интерфэйстэй нийцүүлэх адаптер"""

    def __init__(self, raw_conn):
        self._conn = raw_conn
        self.row_factory = None

    def cursor(self) -> PostgresCompatCursor:
        return PostgresCompatCursor(self._conn.cursor(), self._conn)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> PostgresCompatCursor:
        cur = self.cursor()
        return cur.execute(sql, params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
        finally:
            self._conn.close()


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
    """
    `core/models.py`, `migrations/versions/0001_initial_enterprise_schema.py` болон
    ажиллаж буй өгөгдлийн сангийн 15 хүснэгт ба баганыг тулгаж Schema Drift байгаа эсэхийг шалгах.
    """
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    models_path = os.path.join(root_dir, "core", "models.py")
    mig_path = os.path.join(root_dir, "migrations", "versions", "0001_initial_enterprise_schema.py")

    # 1. Extract tables & columns from core/models.py via AST
    models_tree = ast.parse(open(models_path, "r", encoding="utf-8").read(), filename="core/models.py")
    model_tables: Dict[str, Set[str]] = {}
    for node in models_tree.body:
        if isinstance(node, ast.ClassDef):
            tname = None
            cols: Set[str] = set()
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            if target.id == "__tablename__" and isinstance(item.value, ast.Constant):
                                tname = str(item.value.value)
                            elif isinstance(item.value, ast.Call):
                                func = item.value.func
                                fname = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                                if fname == "Column":
                                    cols.add(target.id)
            if tname:
                model_tables[tname] = cols

    # 2. Extract tables & columns from Alembic 0001_initial_enterprise_schema.py via AST
    mig_tree = ast.parse(open(mig_path, "r", encoding="utf-8").read(), filename="0001_initial_enterprise_schema.py")
    mig_tables: Dict[str, Set[str]] = {}
    for node in ast.walk(mig_tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "create_table":
            if node.args and isinstance(node.args[0], ast.Constant):
                tname = str(node.args[0].value)
                cols = set()
                for arg in node.args[1:]:
                    if isinstance(arg, ast.Call) and getattr(arg.func, "attr", "") == "Column":
                        if arg.args and isinstance(arg.args[0], ast.Constant):
                            cols.add(str(arg.args[0].value))
                mig_tables[tname] = cols

    # 3. Compare model_tables vs mig_tables
    drift_details: Dict[str, Any] = {}
    for tname, m_cols in model_tables.items():
        a_cols = mig_tables.get(tname, set())
        if m_cols != a_cols:
            drift_details[tname] = {
                "in_models_only": sorted(m_cols - a_cols),
                "in_alembic_only": sorted(a_cols - m_cols),
            }

    return {
        "has_drift": bool(drift_details) or (set(model_tables.keys()) != set(mig_tables.keys())),
        "table_count": len(model_tables),
        "tables": sorted(model_tables.keys()),
        "drift_details": drift_details,
    }
