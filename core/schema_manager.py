"""
Single schema authority (finding P1-02 / P2-01, Stage C).

**Problem this solves.** The application used to have *two* schema definitions:

  1. `database.init_db()` — raw `CREATE TABLE ...` DDL executed at import time.
  2. `migrations/versions/0001_...` — an Alembic migration written independently.

They disagreed on **251 column definitions** (timestamps were `VARCHAR(64)` in the
migration but `TIMESTAMP` at runtime), so the schema depended on *how* a database was
created. `verify_schema_drift()` reported "no drift" because it compared the two
source files by column *name* only, never types and never the live database.

**This module makes `core/models.py` + Alembic the only authority.** `database.init_db()`
no longer emits DDL: it asks Alembic to bring the database to `head`.

Concurrency: several uvicorn/gunicorn workers may boot simultaneously. On PostgreSQL we
take a session-level advisory lock so exactly one process migrates while the others wait,
then re-verify. On SQLite the filesystem + short retry is sufficient (single writer).
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from sqlalchemy import text

logger = logging.getLogger("core.schema")

# Arbitrary but stable 64-bit key for pg_advisory_lock ("gerege schema").
_ADVISORY_LOCK_KEY = 6_477_728_151_042_314_001

_HEAD_REVISION: Optional[str] = None


def _resolved_sqlite_path() -> Optional[str]:
    """The SQLite file the *application* is actually using.

    Delegated to `database.resolved_sqlite_path()` — one authority, so Alembic can
    never migrate a different file than the repositories read and write. That
    divergence used to happen: the migration path resolved `DB_PATH` from the
    environment while the connection path used the module attribute, so `init_db()`
    could report success against a schema it had created somewhere else.
    """
    if os.getenv("DATABASE_URL", "").strip():
        return None  # an explicit URL always wins
    try:
        import database as _database

        resolver = getattr(_database, "resolved_sqlite_path", None)
        if callable(resolver):
            return resolver()
        return getattr(_database, "DB_PATH", None)
    except Exception:  # pragma: no cover - database module is always importable in practice
        return None


def _alembic_config():
    from alembic.config import Config

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(root, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(root, "migrations"))
    sqlite_path = _resolved_sqlite_path()
    if sqlite_path:
        # `env.py` re-reads the URL from the environment; `sqlalchemy.url` here keeps
        # `--sql`/offline mode and programmatic runs pointed at the same file.
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{sqlite_path}")
    return cfg


def head_revision() -> str:
    """The revision the code expects (`migrations/versions/*` head)."""
    global _HEAD_REVISION
    if _HEAD_REVISION is None:
        from alembic.script import ScriptDirectory

        script = ScriptDirectory.from_config(_alembic_config())
        _HEAD_REVISION = script.get_current_head() or ""
    return _HEAD_REVISION


def _engine_for(engine=None):
    """Return `engine`, or build the engine for the database the app actually uses.

    `get_shared_engine()` resolves the URL from the environment, which is *not* the
    same as `database.DB_PATH` when that has been rebound. Using one engine for the
    revision stamp and another for the migration silently produced "already at head"
    while the target file stayed empty, so the two resolutions are unified here.
    """
    if engine is not None:
        return engine
    sqlite_path = _resolved_sqlite_path()
    if sqlite_path:
        from sqlalchemy import create_engine

        return create_engine(f"sqlite:///{sqlite_path}")
    from core.db_engine import get_shared_engine

    return get_shared_engine()


def current_revision(engine=None) -> Optional[str]:
    """Revision actually stamped in the database (None when unmigrated)."""
    eng = _engine_for(engine)
    with eng.connect() as conn:
        try:
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        except Exception:
            return None


def is_at_head(engine=None) -> bool:
    return current_revision(engine) == head_revision()


def ensure_schema(stamp_only: bool = False) -> Dict[str, Any]:
    """
    Bring the database to the head revision.

    Returns a small report so callers/tests can assert what happened:
        {"from": <rev|None>, "to": <rev>, "upgraded": bool, "dialect": "postgresql"}
    """
    from alembic import command
    from core.db_engine import is_postgres

    # Fail early and clearly if the migration scripts were not shipped with the app
    # (e.g. a serverless bundle that omitted `migrations/`, or `alembic.ini`).
    _assert_migrations_available()

    engine = _engine_for()
    before = current_revision(engine)
    target = head_revision()

    if before == target:
        return {"from": before, "to": target, "upgraded": False, "dialect": engine.dialect.name}

    cfg = _alembic_config()
    if is_postgres():
        # Serialise concurrent worker boots: only one process may run DDL.
        with engine.connect() as lock_conn:
            lock_conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
            try:
                before = current_revision(engine)
                if before != target:
                    logger.info(f"Applying schema migrations {before or '<empty>'} -> {target}")
                    command.upgrade(cfg, "head")
                    before = current_revision(engine)
            finally:
                try:
                    lock_conn.execute(
                        text("SELECT pg_advisory_unlock(:k)"), {"k": _ADVISORY_LOCK_KEY}
                    )
                    lock_conn.commit()
                except Exception:
                    pass
    else:
        logger.info(f"Applying schema migrations {before or '<empty>'} -> {target} (non-postgres)")
        command.upgrade(cfg, "head")
        before = current_revision(engine)

    after = current_revision(engine)
    if after != target:
        raise RuntimeError(
            f"Schema migration failed: expected head '{target}', database is at '{after}'"
        )
    return {"from": before, "to": after, "upgraded": True, "dialect": engine.dialect.name}


def _assert_migrations_available() -> None:
    """Raise a descriptive error when the migration scripts are missing.

    Without this the failure surfaces as an opaque `No such file or directory` from
    inside Alembic. Deployment bundles (Vercel, Docker) must include `migrations/`
    and `alembic.ini`; `vercel.json` declares them via `includeFiles`.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    missing = [
        name
        for name in ("alembic.ini", os.path.join("migrations", "env.py"))
        if not os.path.exists(os.path.join(root, name))
    ]
    if missing:
        raise RuntimeError(
            "Schema migrations are missing from this deployment: "
            + ", ".join(missing)
            + ". The database cannot be created or upgraded without them. "
            "Include `migrations/` and `alembic.ini` in the deployment bundle."
        )


def assert_at_head(engine=None) -> None:
    """Fail fast (used by `/api/ready` and boot in production) if the schema is stale."""
    cur, head = current_revision(engine), head_revision()
    if cur != head:
        raise RuntimeError(
            f"Database schema is not at head (db='{cur}', expected='{head}'). "
            f"Run `alembic upgrade head` before starting the app."
        )


def compare_with_models(
    engine=None,
    include_types: bool = True,
    include_server_defaults: bool = False,
) -> list:
    """Live-database vs `core/models.py` diff via Alembic autogenerate.

    An empty list means the database matches the single source of truth,
    **including column types** — which the old name-only checker never verified.

    Server defaults are compared only when `include_server_defaults=True`.
    `0001` attached a large set of literal defaults (`status DEFAULT 'Шинэ'`,
    `channel DEFAULT 'web'`, …) that `core/models.py` expresses as Python-side
    `default=` arguments instead. Both are safe: every insert path in `database.py`
    passes those columns explicitly. Treating them as drift would demand ~62 purely
    cosmetic `ALTER COLUMN ... SET DEFAULT` statements, so the default deployment
    gate compares types, nullability, indexes, and constraints, and leaves literal
    defaults to an explicit opt-in audit.
    """
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from core.models import Base

    eng = _engine_for(engine)
    opts = {"compare_type": include_types}
    if include_server_defaults:
        opts["compare_server_default"] = True
    with eng.connect() as conn:
        ctx = MigrationContext.configure(conn, opts=opts)
        return compare_metadata(ctx, Base.metadata)


def drift_report(engine=None) -> Dict[str, Any]:
    """Human-readable drift summary for CI/tests/`/api/admin/metrics`."""
    diffs = compare_with_models(engine)
    flat = [x for d in diffs for x in (d if isinstance(d, list) else [d])]
    by_kind: Dict[str, int] = {}
    for item in flat:
        kind = item[0] if isinstance(item, tuple) else str(item)
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {
        "has_drift": bool(flat),
        "count": len(flat),
        "by_kind": by_kind,
        "current_revision": current_revision(engine),
        "head_revision": head_revision(),
    }


# ---------------------------------------------------------------------------
# Preflight reporting (used before an upgrade runs in production)
# ---------------------------------------------------------------------------
def preflight() -> Dict[str, Any]:
    """Describe what an upgrade would do, without changing anything.

    Called by `scripts/migrate.py --check` and by the deploy pipeline so an operator
    can see the current revision, the target revision, and the number of pending
    steps before approving a migration.
    """
    from alembic.script import ScriptDirectory

    engine = _engine_for()
    script = ScriptDirectory.from_config(_alembic_config())
    cur = current_revision(engine)
    head = head_revision()

    pending: list[str] = []
    try:
        if cur is None:
            # `walk_revisions()` yields head -> base; reverse for apply order.
            pending = [r.revision for r in script.walk_revisions()][::-1]
        elif cur != head:
            pending = [
                r.revision
                for r in script.iterate_revisions(head, cur)
                if r.revision != cur
            ]
    except Exception as exc:  # pragma: no cover - defensive
        pending = [f"<unresolved: {exc}>"]

    return {
        "dialect": engine.dialect.name,
        "current_revision": cur,
        "head_revision": head,
        "up_to_date": cur == head,
        "pending_count": len(pending),
        "pending": pending,
    }
