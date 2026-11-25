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
        # E-33-2: only a **non-SQLite** URL means "ignore the SQLite file entirely".
        # A SQLite `DATABASE_URL` names a concrete file and is now honoured by
        # `get_sqlite_db_path()`, so the application reads and writes *that* file.
        # Returning `None` here would leave `init_db()`/Alembic with no file to target
        # while the repositories used one — the split-brain this function exists to stop.
        from core.db_engine import _sqlite_path_from_url

        if not _sqlite_path_from_url(os.getenv("DATABASE_URL", "").strip()):
            return None  # an explicit non-SQLite URL always wins
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
        # E-02 Phase 8 (R10). Being at the head revision is not the same as holding the
        # security invariants that revision creates. The R10 uniqueness index can be missing
        # for reasons Alembic cannot see: someone dropped it, `downgrade()` removed it, or a
        # pre-Phase-8 `_sync_indexes()` created a non-unique look-alike under the same name.
        # In every one of those cases the database would happily run on and concurrent
        # tenants could claim one username again — silently. So the invariant is checked on
        # every boot, not just the boot that applies the migration.
        assert_security_invariants(engine)
        _assert_least_privilege()
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
    assert_security_invariants(engine)
    _assert_least_privilege()
    return {"from": before, "to": after, "upgraded": True, "dialect": engine.dialect.name}


def _assert_least_privilege() -> None:
    """Refuse to serve on an over-privileged runtime credential (finding E-05).

    Called from :func:`ensure_schema`, which is the one place both boot paths already
    pass through: ``main.py`` at import time and ``worker.worker_main_loop``. Putting it
    here rather than in each entry point is what stops the two from drifting apart —
    a worker that skipped the check would still be able to ``DROP TRIGGER``.

    Enforced only in production mode (or when ``REQUIRE_LEAST_PRIVILEGE=1``); see
    :func:`core.db_privileges.enforcement_enabled`. It runs *after* the schema
    invariants so that a database which is simply un-migrated still reports that,
    rather than reporting a privilege problem it cannot have caused.

    The import is local because ``core.db_privileges`` imports ``core.security``, and
    ``core.security`` is imported by nearly everything; a module-level import here
    would risk a cycle at start-up.
    """
    from core import db_privileges

    db_privileges.assert_runtime_is_least_privileged()


def assert_security_invariants(engine=None) -> None:
    """
    Refuse to run on a database that is missing a database-enforced security invariant.

    Three invariants:
      * the unique username index from revision `0005` (finding R10),
      * the cross-column login-identity namespace from `0006` (finding R16),
      * the `audit_logs` append-only guard from `0007` (finding F-D, Phase 13).

    They are checked in dependency order: the namespace is meaningless without the
    index, and the audit question is only asked once identity is sound.

    This is checked on every schema bring-up, including the "already at head" fast path,
    because the failure mode it prevents is silent. Without this, a deployment whose index
    was dropped — or replaced by the non-unique look-alike that the pre-Phase-8
    `_sync_indexes()` produced under the same name — boots normally, reports healthy, and
    permits exactly the concurrent cross-tenant username claim that Phase 7 reproduced
    12/12 times on both engines.

    Raising here turns that into a loud startup failure that names the remedy.
    """
    from core import audit_integrity, login_identity, username_uniqueness

    engine = engine or _engine_for()
    with engine.connect() as conn:
        username_ok = username_uniqueness.index_is_correct(conn)
        found = None if username_ok else username_uniqueness.describe_index(conn)

        # E-02 Phase 10 (R16). The username index alone is not the whole identity
        # invariant: it cannot see a username that equals another row's page_id, nor
        # two page_ids differing only by case. Revision `0006` closes both with a
        # projected namespace table whose PRIMARY KEY is the identifier. That table is
        # only enforcement while its triggers exist — without them it is a stale
        # snapshot that *looks* enforced, which is worse than absent.
        identity_ok = False
        if username_ok:
            identity_ok = login_identity.namespace_is_correct(
                conn
            ) and login_identity.trigger_present(conn)

        # Phase 13 (finding F-D). `audit_logs` must be append-only. Checked by SHAPE,
        # not by name: a trigger can exist under the expected name while wired to the
        # wrong event or the wrong row/statement level, which protects nothing. The
        # specific defect this catches is a silently dropped guard — the table looks
        # exactly like one that is protected, and nothing re-checks it otherwise.
        audit_ok = False
        audit_problem = ""
        if username_ok and identity_ok:
            try:
                audit_ok = audit_integrity.guard_is_correct(conn)
                if not audit_ok:
                    missing = audit_integrity.missing_triggers(conn)
                    wrong = audit_integrity.wrongly_defined_triggers(conn)
                    audit_problem = (
                        f"missing: {missing or 'none'}; "
                        f"present but wrongly defined: {wrong or 'none'}"
                    )
            except Exception as exc:  # pragma: no cover - defensive
                audit_problem = f"could not be inspected: {type(exc).__name__}: {exc}"

        if username_ok and identity_ok and audit_ok:
            return
    if not username_ok:
        raise RuntimeError(
        "Missing database-enforced security invariant: the unique index "
        f"'{username_uniqueness.USERNAME_UNIQUE_INDEX}' on LOWER(TRIM(client_username)) is "
        f"not in force (found: {found!r}).\n"
        "Without it, concurrent tenants can claim the same normalized username, which makes "
        "login identity ambiguous and shares one failed-login budget between two tenants "
        "(finding R10).\n"
        "Refusing to serve.\n"
        "Repair, in order of preference:\n"
        "  1. python scripts/repair_username_uniqueness.py --check   (safe, read-only)\n"
        "  2. python scripts/repair_username_uniqueness.py           (re-creates the index)\n"
        "  3. alembic upgrade head   (only works if this database is BELOW revision "
        "'0005_username_uniqueness'; it is a no-op when already stamped at head, which is "
        "why step 1 exists)\n"
        "If step 1 reports duplicate usernames, the index cannot be installed until those "
        "collisions are resolved deliberately with the tenant owners. Procedure: "
        "docs/operations/USERNAME_UNIQUENESS_MIGRATION.md"
    )
    if identity_ok and not audit_ok:
        raise RuntimeError(
            "Missing database-enforced security invariant: the audit trail is not "
            f"append-only (finding F-D). `audit_integrity` requires every guard trigger "
            f"on '{audit_integrity.AUDIT_TABLE}' to exist and to be wired to the right "
            f"event ({audit_problem}).\n"
            "Without it, an application-level UPDATE, DELETE or TRUNCATE silently "
            "rewrites or erases audit history. That history is the only durable record "
            "that a payment was confirmed, a credential was rotated, or a tenant was "
            "deleted.\n"
            "Refusing to serve.\n"
            "Repair, in order of preference:\n"
            "  1. python scripts/repair_audit_integrity.py --check   (safe, read-only)\n"
            "  2. python scripts/repair_audit_integrity.py           (re-installs the guard)\n"
            "  3. alembic upgrade head   (only below revision '0007_audit_append_only')\n"
            "NOTE: this guard is tamper *resistance*, not tamper evidence. A database "
            "owner or superuser can DISABLE the triggers or DROP them; nothing inside "
            "the database can prevent that."
        )
    raise RuntimeError(
        "Missing database-enforced security invariant: cross-column login-identity "
        f"uniqueness (finding R16) is not in force. The '{login_identity.NAMESPACE_TABLE}' "
        "projection and its maintenance triggers on `pages` must BOTH exist.\n"
        "Without them a username can equal another tenant's page_id, and two page_ids "
        "differing only by case become one login identifier — both make login identity "
        "ambiguous and can lock the shadowed tenant out of its own page_id login.\n"
        "Refusing to serve.\n"
        "Repair, in order of preference:\n"
        "  1. python scripts/repair_login_identity.py --check   (safe, read-only)\n"
        "  2. python scripts/repair_login_identity.py           (rebuilds the projection)\n"
        "  3. alembic upgrade head   (only below revision '0006_login_identity')\n"
        "If step 1 reports collisions, they must be resolved deliberately with the "
        "tenant owners first. Procedure: docs/operations/USERNAME_UNIQUENESS_MIGRATION.md"
    )


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
        diffs = compare_metadata(ctx, Base.metadata)

        # E-02 Phase 8 (R10). Alembic cannot compare a FUNCTIONAL index it read back from
        # the database (as a `_textual_index_element` parsed from the DDL) against the
        # SQLAlchemy expression in `core/models.py` (`func.lower(func.trim(col))`). It
        # therefore always reports the username invariant as one `remove_index` plus one
        # `add_index`, even when the two are semantically identical — a false positive that
        # would fail every deployment gate.
        #
        # Rather than blanket-ignoring the name (which would also hide a REAL problem), the
        # pair is dropped only when `index_is_correct()` confirms the live index has all four
        # required properties. That check is strictly stronger than the autogenerate
        # comparison it replaces: it verifies UNIQUE, the `lower` expression, the `TRIM`
        # expression, and the partial predicate against the engine's own definition text. If
        # anything about the invariant is wrong, this filter does not apply and the drift is
        # reported as normal.
        diffs = _drop_verified_functional_index_noise(eng, diffs)
        return diffs


def _drop_verified_functional_index_noise(eng, diffs: list) -> list:
    """Remove the username-index add/remove pair when the live index is verified correct."""
    from core import username_uniqueness

    name = username_uniqueness.USERNAME_UNIQUE_INDEX
    relevant = [
        d for d in diffs
        if isinstance(d, tuple) and d and name in str(d)
    ]
    if not relevant:
        return diffs
    # Only these two shapes are the known functional-index artefact.
    if not all(isinstance(d, tuple) and d[0] in ("add_index", "remove_index") for d in relevant):
        return diffs
    try:
        with eng.connect() as conn:
            if not username_uniqueness.index_is_correct(conn):
                return diffs
    except Exception:
        return diffs
    return [d for d in diffs if not (isinstance(d, tuple) and d and name in str(d))]


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
