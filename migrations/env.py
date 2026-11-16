"""Alembic runtime configuration.

`compare_type=True` and `compare_server_default=True` are the fix for audit finding
**P2-01**. Without them autogenerate only compared column *names*, so `0001`'s
`VARCHAR(64)` timestamps were reported as matching `core/models.py`'s `DateTime`
columns: the drift checker was structurally incapable of seeing the drift it existed
to detect. With them enabled, `alembic revision --autogenerate` and
`core.schema_manager.drift_report()` both report real type differences.

`render_as_batch` is enabled because SQLite cannot `ALTER COLUMN` in place; without it
any future type change would fail on the default `sqlite:///leads.db` deployment.
"""
import os
from logging.config import fileConfig

import sqlalchemy as sa
from alembic import context

from core.db_engine import get_database_url
from core.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# A programmatic caller (`core.schema_manager`) may have pinned a specific SQLite file,
# normally `database.DB_PATH`. That must win over the generic environment default, or
# Alembic migrates one database while the application reads another.
_pinned = (config.get_main_option("sqlalchemy.url") or "").strip()
_environ_url = get_database_url()
if not os.getenv("DATABASE_URL", "").strip() and _pinned.startswith("sqlite:"):
    _url = _pinned
else:
    _url = _environ_url
config.set_main_option("sqlalchemy.url", _url)
target_metadata = Base.metadata


def _is_sqlite() -> bool:
    return config.get_main_option("sqlalchemy.url", "").startswith("sqlite")


def _common_options() -> dict:
    """Options shared by the online and offline paths (kept in sync deliberately)."""
    return {
        "target_metadata": target_metadata,
        # P2-01: compare types and server defaults, not just names.
        "compare_type": True,
        "compare_server_default": True,
        # SQLite has no ALTER COLUMN; batch mode rewrites the table instead.
        "render_as_batch": _is_sqlite(),
    }


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        **_common_options(),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Build the engine from the *resolved* URL so a pinned SQLite path is honoured.
    connectable = sa.create_engine(config.get_main_option("sqlalchemy.url"))
    with connectable.connect() as connection:
        context.configure(connection=connection, **_common_options())
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
