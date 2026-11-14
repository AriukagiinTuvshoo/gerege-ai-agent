import os
import logging
from typing import Optional
from dotenv import load_dotenv

load_dotenv(override=True)
logger = logging.getLogger("core.db_engine")


def get_database_url() -> str:
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

    db_path = os.getenv("DB_PATH", "leads.db")
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
            connect_args={"check_same_thread": False, "timeout": 10.0},
            future=True,
        )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
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
