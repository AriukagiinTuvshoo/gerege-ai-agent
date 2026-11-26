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
# F-50-4: `fileConfig()` defaults to `disable_existing_loggers=True`, and `alembic.ini` sets
# `[logger_root] level = WARN`. Together those two defaults silenced the application that ran
# the migration: `main.py` imports — and therefore creates the loggers of — `agent`,
# `database`, `core.security`, `core.secret_guard`, `core.ai_router`, `core.monitoring`,
# `core.task_queue`, `core.rate_limit` and `fintech_service` *before* `database.init_db()`
# reaches this file. Measured on a first boot (empty database, so the migrations do run):
# 10 of 15 application loggers left permanently disabled, root's level replaced by WARN, and
# an error logged afterwards by `agent` or `core.ai_readiness` reached no handler at all. A
# freshly deployed instance therefore ran blind exactly when an operator most needs the log,
# while looking completely healthy.
#
# `core.schema_manager.ensure_schema()` skips this on purpose when it calls Alembic as a
# library: the application has already configured logging, and a library call must not undo
# it. `disable_existing_loggers=False` is the second guard, so a CLI `alembic upgrade head`
# run alongside a live process cannot silence that process either. Alembic's own output is
# unaffected — its loggers are named in alembic.ini and are configured either way.
if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# A programmatic caller (`core.schema_manager`) may have pinned a specific SQLite file,
# normally `database.DB_PATH`. That must win over the generic environment default, or
# Alembic migrates one database while the application reads another.
_pinned = (config.get_main_option("sqlalchemy.url") or "").strip()
_environ_url = get_database_url()
_named_url = bool(os.getenv("DATABASE_URL", "").strip())
_named_path = bool(os.getenv("DB_PATH", "").strip())
if not _named_url and _pinned.startswith("sqlite:"):
    _url = _pinned
else:
    _url = _environ_url

# B5: `alembic.ini` no longer names a database. With nothing set, `get_database_url()` falls
# through `get_sqlite_db_path()` to the repository's own `leads.db`, so a shell run would
# migrate the checkout's database in place and report success. Measured before this guard:
# `python -m alembic upgrade head` with an empty environment rewrote `leads.db`. Refusing is
# the only outcome that cannot be mistaken for a successful migration of the intended file.
# Programmatic callers are unaffected: `core.schema_manager._alembic_config()` pins the URL,
# which is what `_pinned` is for.
if not (_named_url or _named_path or _pinned):
    raise RuntimeError(
        "Alembic was invoked without a target database. Set DATABASE_URL (or DB_PATH for a "
        "SQLite file) and re-run; refusing to fall back to the repository's own leads.db. "
        "Programmatic runs through core.schema_manager pin the URL and never reach this."
    )

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
