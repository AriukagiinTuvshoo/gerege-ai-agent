"""Least-privilege runtime credentials (finding E-05).

Background
----------
Until this module existed, the web process, the worker process and the migration
tool all connected to PostgreSQL as the *bootstrap superuser* named in
``POSTGRES_USER``. That single credential owned every table, could ``DROP TRIGGER``,
could ``SET session_replication_role = replica`` and could grant itself anything.

Phase 13 (finding F-D) installed append-only triggers on ``audit_logs`` and a startup
guard that verifies they are present. Measurement during Phase 13 showed the guard
raises the cost of *accidental* mutation but cannot stop whoever holds the runtime
credential: a stolen ``DATABASE_URL`` was still enough to ``DROP TRIGGER`` and then
rewrite history. The trigger is only a real control if the credential that runs the
application cannot remove it.

So the runtime now connects as ``gerege_app``: a login role that owns nothing, holds
no DDL rights, and has ``SELECT, INSERT`` — and only those — on ``audit_logs``.

What this module does
---------------------
``assert_runtime_is_least_privileged()`` inspects the *live catalogue* for the role it
is actually connected as and refuses to continue if that role is more powerful than
the model below. It is deliberately not a list of "expected" grants checked against a
hardcoded snapshot: it asks PostgreSQL, through ``has_table_privilege()`` and
``pg_has_role()``, what the current role can really do — including anything inherited
through role membership. A grant added out of band, a role accidentally added to
``gerege_owner``, or a deployment that quietly reverted ``DATABASE_URL`` to the
superuser is therefore caught at startup rather than assumed absent.

Where it runs
-------------
From ``core.schema_manager.ensure_schema()``, which both boot paths
(``main.py`` module import and ``worker.worker_main_loop``) already call. The check is
enforced when ``core.security.is_production_mode()`` is true, or unconditionally when
``REQUIRE_LEAST_PRIVILEGE=1``. Development, the SQLite default and CI's
single-superuser PostgreSQL run are unaffected — none of them is a deployment.

It is a no-op on SQLite, which has no role system. SQLite deployments are protected
by the Phase 13 triggers alone; that asymmetry is documented, not hidden.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("core.db_privileges")

#: The runtime login role this project provisions. Named here so the failure messages
#: can tell an operator what the role *should* be, not only what is wrong.
RUNTIME_ROLE = "gerege_app"
OWNER_ROLE = "gerege_owner"

#: Every table the application reads or writes, and the privileges it is allowed to
#: hold on that table. This is the privilege matrix from the E-05 design, restated as
#: executable policy so it cannot drift from the grants.
#:
#: ``audit_logs`` is the reason this phase exists, and it is the only table where the
#: minimum is narrower than CRUD: SELECT (the admin log view and the retention
#: reporting) and INSERT (every audited operation). UPDATE, DELETE and TRUNCATE are
#: absent because Phase 13's guard must be unremovable by the role it protects against.
#:
#: ``page_login_namespace`` needs full CRUD even though no application code names it:
#: it is written by the ``pages`` triggers in ``core/login_identity.py``, and a trigger
#: runs with the privileges of the *invoking* role. The measurement that established
#: this is recorded in the E-05 report; the earlier assumption that nothing wrote to
#: the table would have broken page creation for every tenant.
#:
#: The sixteen business tables keep full CRUD. That is a deliberate, documented
#: decision rather than a convenience: a static grep of the source is not a sound
#: oracle for *absence* of a write path (dynamic SQL, ORM paths and future code all
#: escape it), under-granting fails at runtime with a 500 for a real customer rather
#: than at review time, and these tables carry no audit evidence. The restrictive
#: control belongs where the evidence lives.
BUSINESS_TABLES: Tuple[str, ...] = (
    "pages",
    "registrations",
    "messages",
    "session_states",
    "sessions",
    "user_memories",
    "invoices",
    "cargo_packages",
    "automated_rules",
    "marketing_campaigns",
    "sent_followups",
    "appointments",
    "notification_locks",
    "task_jobs",
    "comment_automations",
    "tracked_links",
)

_CRUD = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})

REQUIRED_TABLE_PRIVILEGES: Dict[str, frozenset] = {
    name: _CRUD for name in BUSINESS_TABLES
}
REQUIRED_TABLE_PRIVILEGES["page_login_namespace"] = _CRUD
REQUIRED_TABLE_PRIVILEGES["audit_logs"] = frozenset({"SELECT", "INSERT"})

#: Privileges that must never be held on *any* table by the runtime role.
#: TRUNCATE removes every row without firing the row-level guard; REFERENCES would let
#: the role add a foreign key; TRIGGER would let it attach a function to a table.
ALWAYS_FORBIDDEN_PRIVILEGES = frozenset({"TRUNCATE", "REFERENCES", "TRIGGER"})

#: Privileges that must never be held on a *sequence* by the runtime role.
#: USAGE is what `nextval()` needs. UPDATE/SELECT are not: UPDATE would let the runtime
#: move a serial counter backwards, which is a duplicate-key and data-integrity
#: primitive rather than a query need. (Phase 16, MEDIUM-01 completeness.)
ALWAYS_FORBIDDEN_SEQUENCE_PRIVILEGES = frozenset({"UPDATE", "SELECT"})

#: Predefined roles that grant power far beyond what the application needs. Membership
#: is inherited, so holding one of these silently re-expands the credential.
FORBIDDEN_PREDEFINED_ROLES = (
    "pg_read_all_data",
    "pg_write_all_data",
    "pg_read_all_settings",
    "pg_read_all_stats",
    "pg_stat_scan_tables",
    "pg_monitor",
    "pg_signal_backend",
    "pg_checkpoint",
    "pg_maintain",
    "pg_create_subscription",
    "pg_execute_server_program",
    "pg_read_server_files",
    "pg_write_server_files",
)


class PrivilegedRuntimeError(RuntimeError):
    """The runtime connection holds privileges the application must not have.

    Raised at startup, before the process serves a request, so a misconfigured
    deployment stops instead of running with an over-privileged credential that would
    make the audit guard removable.
    """


def enforcement_enabled() -> bool:
    """Should the check be fatal in this process?

    Fatal in production mode (``ENV=production|prod`` or ``STRICT_SECURITY=1``), and
    whenever ``REQUIRE_LEAST_PRIVILEGE=1`` explicitly asks for it — which is how the
    adversarial suite exercises the check without pretending to be production.
    """
    if os.getenv("REQUIRE_LEAST_PRIVILEGE", "").strip().lower() in ("1", "true", "yes"):
        return True
    try:
        from core.security import is_production_mode

        return is_production_mode()
    except Exception:  # pragma: no cover - import cycle guard
        return False


def _fetch(conn, sql: str, params: Iterable[Any] = ()) -> List[Tuple]:
    cur = conn.cursor()
    try:
        cur.execute(sql, tuple(params))
        return list(cur.fetchall())
    finally:
        try:
            cur.close()
        except Exception:
            pass


def _fetch_safe(conn, sql: str, params: Iterable[Any] = ()) -> List[Tuple]:
    """Run a probe, containing its failure in a SAVEPOINT.

    A failed statement aborts the *entire* transaction, so a bare ``except: continue``
    around a probe does not make the loop continue — it makes every later probe fail
    with ``InFailedSqlTransaction``. That is not a hypothetical: the first version of
    this module called ``pg_has_role`` for ``pg_maintain``, which does not exist before
    PostgreSQL 17, so the membership loop silently poisoned the connection and the
    ownership check reported "no owner" on a database that had one.

    The savepoint makes each probe independent, so an unknown role or a missing table
    costs one probe rather than the whole report.
    """
    # In autocommit mode every statement is its own transaction, so a failure has
    # nothing to poison and `SAVEPOINT` is not even legal (NoActiveSqlTransaction).
    # The provisioning/verification scripts run that way; the application's pooled
    # connection runs inside a transaction and needs the savepoint.
    if getattr(conn, "autocommit", False):
        cur = conn.cursor()
        try:
            cur.execute(sql, tuple(params))
            return list(cur.fetchall())
        except Exception:
            return []
        finally:
            try:
                cur.close()
            except Exception:
                pass

    cur = conn.cursor()
    try:
        cur.execute("SAVEPOINT db_privileges_probe")
        try:
            cur.execute(sql, tuple(params))
            return list(cur.fetchall())
        except Exception:
            return []
        finally:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT db_privileges_probe")
            except Exception:
                pass
    finally:
        try:
            cur.close()
        except Exception:
            pass


def _scalar(conn, sql: str, params: Iterable[Any] = (), safe: bool = False):
    rows = (_fetch_safe if safe else _fetch)(conn, sql, params)
    return rows[0][0] if rows else None


def collect_runtime_privileges(conn) -> Dict[str, Any]:
    """Ask the live catalogue what the connected role can actually do.

    Read-only. Every query here works for a plain ``NOINHERIT``-free non-superuser, so
    the function can be used by the provisioning script, by the startup assertion and
    by the adversarial tests against the same source of truth.
    """
    schema = _scalar(conn, "SELECT current_schema()") or "public"

    role_attrs = _fetch(
        conn,
        """
        SELECT rolname, rolsuper, rolcreaterole, rolcreatedb,
               rolreplication, rolbypassrls
          FROM pg_roles
         WHERE rolname = current_user
        """,
    )
    if role_attrs:
        name, superuser, createrole, createdb, replication, bypassrls = role_attrs[0]
    else:  # pragma: no cover - current_user always resolves
        name, superuser, createrole, createdb, replication, bypassrls = (
            _scalar(conn, "SELECT current_user"), False, False, False, False, False,
        )

    # Membership is reported for the *effective* role set, because privileges are
    # inherited. `pg_has_role(..., 'MEMBER')` is the question that matters: could this
    # role `SET ROLE` into the target, or inherit its rights?
    #
    # Only roles that exist on this server are asked about: `pg_has_role` raises for an
    # unknown role, and the predefined-role list spans several major versions
    # (`pg_maintain` is 17+). Asking the catalogue first also keeps this working on the
    # PostgreSQL 13+ versions the project may be deployed against.
    existing_roles = {
        r[0]
        for r in _fetch_safe(conn, "SELECT rolname FROM pg_roles")
    }
    memberships: Set[str] = set()
    for candidate in (OWNER_ROLE,) + FORBIDDEN_PREDEFINED_ROLES:
        # `pg_has_role(current_user, current_user, 'MEMBER')` is true: every role is a
        # member of itself. For the owner role that is a real signal; for a role that
        # happens to share a name with a predefined role it is not.
        if candidate not in existing_roles or candidate == name:
            continue
        if _scalar(conn, "SELECT pg_has_role(current_user, %s, 'MEMBER')", (candidate,)):
            memberships.add(candidate)

    # Any *other* group role this login is a member of is also over-privilege: the model
    # allows exactly one role, the runtime login itself. Reported by name so an operator
    # can see which grant to remove.
    other_memberships = _fetch_safe(
        conn,
        """
        SELECT r.rolname
          FROM pg_auth_members m
          JOIN pg_roles r ON r.oid = m.roleid
          JOIN pg_roles u ON u.oid = m.member
         WHERE u.rolname = current_user
         ORDER BY r.rolname
        """,
    )
    for (role_name,) in other_memberships:
        if role_name not in memberships and role_name != "pg_database_owner":
            memberships.add(role_name)

    # Roles that own a relation in the schema. Used to detect "the runtime role is (or
    # can become) an owner", which is what `DROP TRIGGER` and `ALTER TABLE` require.
    owning_roles = {
        r[0]
        for r in _fetch(
            conn,
            """
            SELECT DISTINCT pg_get_userbyid(c.relowner)
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = %s
               AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
            """,
            (schema,),
        )
    }

    owned_relations = _scalar(
        conn,
        """
        SELECT COUNT(*)
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %s
           AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
           AND pg_get_userbyid(c.relowner) = current_user
        """,
        (schema,),
    )

    table_privileges: Dict[str, Set[str]] = {}
    existing_matrix_tables: Set[str] = set()
    for table in REQUIRED_TABLE_PRIVILEGES:
        held: Set[str] = set()
        if _scalar(
            conn,
            "SELECT to_regclass(%s) IS NOT NULL",
            (f"{schema}.{table}",),
            safe=True,
        ):
            existing_matrix_tables.add(table)
        try:
            # One round trip per table rather than one per (table, privilege): a boot
            # path should not issue 126 sequential catalogue queries.
            rows = _fetch_safe(
                conn,
                """
                SELECT p, has_table_privilege(current_user, %s, p)
                  FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE',
                                    'TRUNCATE','REFERENCES','TRIGGER']) AS p
                """,
                (f"{schema}.{table}",),
            )
            held = {priv for priv, ok in rows if ok}
        except Exception:
            # Table missing (un-migrated database) — nothing to grant, nothing held.
            pass
        table_privileges[table] = held

    schema_create = bool(
        _scalar(conn, "SELECT has_schema_privilege(current_user, %s, 'CREATE')", (schema,))
    )

    # The database owner is a member of the predefined role `pg_database_owner`, which
    # owns the `public` schema in PostgreSQL 15+. A runtime connection that owns the
    # database can therefore drop and recreate the schema — and with it every trigger
    # Phase 13 installed. Ownership of the *database* is as fatal as ownership of a table.
    db_owner = _scalar(
        conn,
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
    )
    is_db_owner = bool(db_owner) and db_owner == name
    # Being a member of a role that owns something is equivalent to owning it, because
    # a member can `SET ROLE` to the owner.
    can_become_owner = bool(owning_roles & memberships) or bool(owned_relations)

    return {
        "role": name,
        "schema": schema,
        "superuser": bool(superuser),
        "createrole": bool(createrole),
        "createdb": bool(createdb),
        "replication": bool(replication),
        "bypassrls": bool(bypassrls),
        "memberships": sorted(memberships),
        "owned_relations": int(owned_relations or 0),
        "can_become_owner": can_become_owner,
        "database_owner": db_owner,
        "is_database_owner": is_db_owner,
        "schema_create": schema_create,
        "table_privileges": {k: sorted(v) for k, v in sorted(table_privileges.items())},
        "existing_tables": sorted(existing_matrix_tables),
    }


# ---------------------------------------------------------------------------
# Phase 16 (MEDIUM-01): role-targeted collection that does not require SET ROLE
# ---------------------------------------------------------------------------
#
# `collect_runtime_privileges` answers "what can *this session* do". Verification
# needs to answer "what can *gerege_app* do" from a session that may be neither
# `gerege_app` nor able to `SET ROLE gerege_app` — an owner credential cannot
# impersonate its own member, and the Phase 15 audit showed the previous code
# silently downgraded that to a warning and then printed PASS.
#
# The functions below ask the catalogue the same questions *about a named role*:
# `has_table_privilege(role, ...)` and friends already account for inheritance,
# so no impersonation is needed and nothing can fail silently.

_TABLE_PRIVS = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def _role_attrs(conn, role: str) -> Optional[Tuple]:
    rows = _fetch(
        conn,
        """
        SELECT rolname, rolsuper, rolcreatedb, rolcreaterole,
               rolreplication, rolbypassrls, rolcanlogin
          FROM pg_roles
         WHERE rolname = %s
        """,
        (role,),
    )
    return rows[0] if rows else None


def collect_role_privileges(conn, role: str, schema: Optional[str] = None) -> Dict[str, Any]:
    """Collect what a *named* role can do, without impersonating it.

    Every privilege question is asked with the explicit-role form
    (``has_table_privilege(<role>, ...)``), which the server evaluates against the
    role's own attribute set plus its inherited memberships. That is the same
    effective-rights answer ``SET ROLE`` would give, and it works from any session
    that can read the catalogue.

    The report is deliberately the same shape as :func:`collect_runtime_privileges`
    so one evaluator and one message path serve both the startup assertion and the
    operator-facing ``--verify``. The extra key ``collector`` records which method
    produced it, so a test can prove the fallback ran rather than assume it.
    """
    schema = schema or (_scalar(conn, "SELECT current_schema()") or "public")

    attrs = _role_attrs(conn, role)
    if attrs is None:
        # Distinct sentinel: the evaluator turns this into a hard failure. Returning
        # an empty-but-well-formed report here is exactly the failure mode Phase 15
        # found in the `--verify` path.
        return {"role": role, "schema": schema, "exists": False, "collector": "catalogue"}

    name, superuser, createdb, createrole, replication, bypassrls, canlogin = attrs

    # Membership: every role this login is a member of, excluding itself. A role is
    # a member of itself, and a superuser is implicitly a member of everything, so
    # the superuser case is reported by the attribute check instead.
    memberships = set()
    for (role_name,) in _fetch_safe(
        conn,
        """
        SELECT r.rolname
          FROM pg_auth_members m
          JOIN pg_roles r ON r.oid = m.roleid
          JOIN pg_roles u ON u.oid = m.member
         WHERE u.rolname = %s
         ORDER BY r.rolname
        """,
        (role,),
    ):
        if role_name != name:
            memberships.add(role_name)

    owning_roles = {
        r[0]
        for r in _fetch(
            conn,
            """
            SELECT DISTINCT pg_get_userbyid(c.relowner)
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = %s
               AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
            """,
            (schema,),
        )
    }

    owned_relations = _scalar(
        conn,
        """
        SELECT COUNT(*)
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %s
           AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
           AND pg_get_userbyid(c.relowner) = %s
        """,
        (schema, role),
    )

    # Sequences: USAGE is required for `nextval()` on every SERIAL-backed insert;
    # anything else (UPDATE/SELECT) is escalation and is reported by the evaluator.
    sequence_privileges: Dict[str, Set[str]] = {}
    for (seq_name,) in _fetch_safe(
        conn,
        """
        SELECT c.relname
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relkind = 'S'
         ORDER BY c.relname
        """,
        (schema,),
    ):
        rows = _fetch_safe(
            conn,
            """
            SELECT p, has_sequence_privilege(%s, %s, p)
              FROM unnest(ARRAY['USAGE','SELECT','UPDATE']) AS p
            """,
            (role, f"{schema}.{seq_name}"),
        )
        sequence_privileges[seq_name] = {priv for priv, ok in rows if ok}

    table_privileges: Dict[str, Set[str]] = {}
    existing_matrix_tables: Set[str] = set()
    for table in REQUIRED_TABLE_PRIVILEGES:
        present = _scalar(
            conn,
            "SELECT to_regclass(%s) IS NOT NULL",
            (f"{schema}.{table}",),
            safe=True,
        )
        if not present:
            table_privileges[table] = set()
            continue
        existing_matrix_tables.add(table)
        rows = _fetch_safe(
            conn,
            """
            SELECT p, has_table_privilege(%s, %s, p)
              FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE',
                                'TRUNCATE','REFERENCES','TRIGGER']) AS p
            """,
            (role, f"{schema}.{table}"),
        )
        table_privileges[table] = {priv for priv, ok in rows if ok}

    schema_create = bool(
        _scalar(conn, "SELECT has_schema_privilege(%s, %s, 'CREATE')", (role, schema))
        if _scalar(conn, "SELECT to_regnamespace(%s) IS NOT NULL", (schema,), safe=True)
        else False
    )

    db_owner = _scalar(
        conn,
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
    )
    is_db_owner = bool(db_owner) and db_owner == name

    return {
        "role": name,
        "schema": schema,
        "exists": True,
        "canlogin": bool(canlogin),
        "superuser": bool(superuser),
        "createrole": bool(createrole),
        "createdb": bool(createdb),
        "replication": bool(replication),
        "bypassrls": bool(bypassrls),
        "memberships": sorted(memberships),
        "owned_relations": int(owned_relations or 0),
        "can_become_owner": bool(owning_roles & memberships) or bool(owned_relations),
        "database_owner": db_owner,
        "is_database_owner": is_db_owner,
        "schema_create": schema_create,
        "table_privileges": {k: sorted(v) for k, v in sorted(table_privileges.items())},
        "sequence_privileges": {
            k: sorted(v) for k, v in sorted(sequence_privileges.items())
        },
        "existing_tables": sorted(existing_matrix_tables),
        "collector": "catalogue",
    }


def collect_ownership(conn, schema: Optional[str] = None) -> Dict[str, Any]:
    """Who owns every relation in the schema, and how many the owner role owns.

    Phase 16 (HIGH-01): a deployment can leave every table owned by the bootstrap
    account while every privilege check still passes, because grants and ownership
    are independent. That state cannot be backed up (``pg_dump`` needs ownership),
    so ownership is a first-class invariant of provisioning, not a detail.
    """
    schema = schema or (_scalar(conn, "SELECT current_schema()") or "public")
    rows = _fetch(
        conn,
        """
        SELECT c.relname,
               c.relkind,
               pg_get_userbyid(c.relowner) AS owner
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %s
           AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
         ORDER BY c.relname
        """,
        (schema,),
    )
    by_owner: Dict[str, int] = {}
    names_by_owner: Dict[str, List[str]] = {}
    for relname, _kind, owner in rows:
        by_owner[owner] = by_owner.get(owner, 0) + 1
        names_by_owner.setdefault(owner, []).append(relname)
    return {
        "schema": schema,
        "total": len(rows),
        "by_owner": dict(sorted(by_owner.items())),
        "names_by_owner": {k: sorted(v) for k, v in names_by_owner.items()},
        "owned_by_owner_role": by_owner.get(OWNER_ROLE, 0),
        "relations": sorted((r[0] for r in rows)),
    }


def evaluate_ownership(ownership: Dict[str, Any]) -> List[str]:
    """Violations for the ownership invariant.

    Deliberately all-or-nothing, mirroring the backup guard: ``pg_dump`` locks
    *every* table, so a single bootstrap-owned table defeats maintenance for the
    whole schema. One unowned table is therefore a failure, not a warning.
    """
    problems: List[str] = []
    total = int(ownership.get("total") or 0)
    if total == 0:
        # Same split as the privilege evaluator: a verification gate must refuse an
        # un-migrated schema, while `--apply` runs before the first migration on a
        # fresh install and must not.
        if ownership.get("require_migrated"):
            problems.append(
                "no tables found: the schema has not been migrated, so ownership "
                "convergence and least privilege cannot be verified"
            )
        return problems
    foreign = {
        owner: names
        for owner, names in (ownership.get("names_by_owner") or {}).items()
        if owner != OWNER_ROLE
    }
    if foreign:
        sample = []
        for owner, names in sorted(foreign.items()):
            shown = ", ".join(names[:4])
            more = "" if len(names) <= 4 else f" (+{len(names) - 4} more)"
            sample.append(f"'{owner}': {shown}{more}")
        problems.append(
            f"{total - int(ownership.get('owned_by_owner_role') or 0)} of {total} "
            f"relation(s) in schema '{ownership.get('schema')}' are NOT owned by "
            f"'{OWNER_ROLE}' ({'; '.join(sample)}). pg_dump needs ownership of every "
            f"table, so backup and restore cannot run. Run "
            f"scripts/provision_roles.py --apply (a full pass, not --converge-only)"
        )
    return problems


def evaluate_runtime_privileges(report: Dict[str, Any]) -> List[str]:
    """Return the violations in a privilege report. Empty list means least privilege.

    Split from the collector so a test (and the operator-facing script) can evaluate a
    report it obtained separately, and so the message text is assembled in one place.
    """
    problems: List[str] = []

    # Phase 16 (MEDIUM-01): a report about a role that does not exist must never
    # evaluate to "no problems". The previous `--verify` path produced exactly that
    # by returning `None` from a failed impersonation and printing a note.
    if report.get("exists") is False:
        problems.append(
            f"role '{report.get('role')}' does not exist; provisioning has not run or "
            f"the role was dropped. Nothing can be verified about its privileges"
        )
        return problems

    # A role that cannot log in cannot serve the application, even if every grant is
    # right. Checked here so an incomplete provisioning pass is not reported as PASS.
    if report.get("collector") == "catalogue" and report.get("canlogin") is False:
        problems.append(
            f"role '{report.get('role')}' cannot log in (NOLOGIN); the application "
            "connection would be refused"
        )

    if report.get("superuser"):
        problems.append(
            "role is SUPERUSER: it can DROP the audit triggers, disable them with "
            "ALTER TABLE ... DISABLE TRIGGER, and set session_replication_role"
        )
    if report.get("bypassrls"):
        problems.append("role has BYPASSRLS and ignores row-level security")
    if report.get("createrole") or report.get("createdb") or report.get("replication"):
        problems.append(
            "role has CREATEROLE / CREATEDB / REPLICATION; the runtime needs none of these"
        )

    # A superuser is implicitly a member of every role, so listing those memberships
    # alongside "role is SUPERUSER" repeats one fact seven times and buries the cause.
    # When the role is already disqualified, say why once.
    if not report.get("superuser"):
        for role_name in report.get("memberships", []):
            problems.append(
                f"role is a member of '{role_name}'; membership is inherited and re-expands "
                "the credential beyond the application's needs"
            )

    if report.get("owned_relations"):
        problems.append(
            f"role owns {report['owned_relations']} relation(s) in schema "
            f"'{report.get('schema')}'; ownership is what ALTER TABLE / DROP TRIGGER "
            "require, so the audit guard would be removable"
        )
    if report.get("can_become_owner"):
        problems.append("role can assume ownership of schema objects (directly or via a role it is a member of)")
    if report.get("is_database_owner"):
        problems.append(
            f"role owns the database itself (owner is '{report.get('database_owner')}'); the "
            "database owner is a member of pg_database_owner, which owns the public schema, "
            "so it could DROP SCHEMA public CASCADE and remove the audit triggers"
        )
    if report.get("schema_create"):
        problems.append(
            f"role holds CREATE on schema '{report.get('schema')}'; it could create "
            "objects, including a function that shadows an application code path"
        )

    for table, held in (report.get("table_privileges") or {}).items():
        required = REQUIRED_TABLE_PRIVILEGES.get(table)
        if required is None:
            continue
        held_set = set(held)
        extra = held_set - required
        # A privilege the matrix does not mention at all is over-privilege too, but the
        # ALWAYS_FORBIDDEN set is called out separately: those are the ones that defeat
        # the append-only control.
        fatal_extra = held_set & ALWAYS_FORBIDDEN_PRIVILEGES
        if fatal_extra:
            problems.append(
                f"'{table}': role holds {sorted(fatal_extra)}, which must never be granted "
                "(TRUNCATE bypasses the row guard, TRIGGER lets the role attach code)"
            )
            extra = extra - fatal_extra
        if extra:
            problems.append(
                f"'{table}': role holds {sorted(extra)} beyond the required {sorted(required)}"
            )

    # A role can also be wrong by holding too *little*: after a restore that lost its
    # grants the application boots and then fails every query with "permission denied",
    # which looks like a code bug rather than a provisioning one. Only checked for tables
    # that exist — a database below head legitimately has fewer.
    existing = set(report.get("existing_tables") or ())
    for table in sorted(existing):
        required = REQUIRED_TABLE_PRIVILEGES.get(table)
        if required is None:
            continue
        held_set = set((report.get("table_privileges") or {}).get(table, []))
        missing = set(required) - held_set
        if missing:
            problems.append(
                f"'{table}': role is missing {sorted(missing)}; the application would fail "
                "at query time. Run scripts/provision_roles.py --apply"
            )

    audit = set((report.get("table_privileges") or {}).get("audit_logs", []))
    for priv in ("UPDATE", "DELETE"):
        if priv in audit:
            problems.append(
                f"audit_logs: role holds {priv}; audit history must not be mutable by the "
                "credential that runs the application"
            )

    # Phase 16: incomplete provisioning. If the schema has no tables at all the
    # database was never migrated. Whether that is a *failure* depends on the caller:
    #
    #   * `--verify`  requires a migrated database. A schema with no tables there means
    #     the deploy ran provisioning but never migrated, and reporting PASS would be a
    #     false pre-flight — the same class of mistake as MEDIUM-01, one level up.
    #   * `--apply`   must tolerate it. The `migrate` service runs provisioning *before*
    #     `alembic upgrade head`, deliberately, so the roles exist for the migration to
    #     grant against. Failing there would break a fresh install.
    #
    # So the requirement is a property of the verification mode, not of the report.
    if report.get("require_migrated") and not existing:
        problems.append(
            "no application tables exist in the schema; the migration has not run, so "
            "least privilege cannot be verified"
        )

    # Phase 16: sequence privilege escalation. USAGE is what `nextval()` needs;
    # UPDATE on a sequence would let the runtime move a primary-key counter backwards
    # (a silent duplicate-key or data-corruption primitive). The startup collector does
    # not gather this, so it is only reported when present.
    for seq, held in (report.get("sequence_privileges") or {}).items():
        bad = set(held) & ALWAYS_FORBIDDEN_SEQUENCE_PRIVILEGES
        if bad and not report.get("superuser"):
            problems.append(
                f"sequence '{seq}': role holds {sorted(bad)}; the runtime needs only USAGE"
            )

    return problems


def assert_runtime_is_least_privileged(conn=None, *, force: Optional[bool] = None) -> Dict[str, Any]:
    """Fail closed when the runtime connection is more powerful than the model allows.

    Returns the report on success so a caller (or a test) can assert on what was seen.
    Raises :class:`PrivilegedRuntimeError` with every violation listed — not just the
    first — because an operator fixing this wants the whole list in one restart.
    """
    from core.db_engine import is_postgres

    if not is_postgres():
        # SQLite has no role system; nothing to evaluate and nothing to claim.
        return {"dialect": "sqlite", "enforced": False, "violations": []}

    enforce = enforcement_enabled() if force is None else force
    own_conn = conn is None
    if own_conn:
        from core.db_engine import get_db_connection

        conn = get_db_connection()
    try:
        report = collect_runtime_privileges(conn)
    finally:
        if own_conn and conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    violations = evaluate_runtime_privileges(report)
    report["enforced"] = bool(enforce)
    report["violations"] = violations

    if not violations:
        logger.info(
            "Runtime role '%s' holds least privilege (%s table(s) checked).",
            report.get("role"),
            len(report.get("table_privileges") or {}),
        )
        return report

    detail = "\n".join(f"  - {v}" for v in violations)
    message = (
        f"refusing to start: the database role '{report.get('role')}' is more privileged "
        f"than the application requires.\n{detail}\n"
        f"Provision the runtime role with scripts/provision_roles.py and point DATABASE_URL "
        f"at '{RUNTIME_ROLE}'. Run migrations and maintenance with '{OWNER_ROLE}'."
    )
    if enforce:
        raise PrivilegedRuntimeError(message)

    # Not a deployment: report loudly but do not block development, the SQLite default,
    # or the CI run that intentionally uses one bootstrap superuser for everything.
    # Deliberately a single line — a full violation list on every `python main.py` in
    # development trains people to ignore the message that matters in production.
    logger.warning(
        "Least-privilege check not enforced (%s): role '%s' has %d violation(s) that would "
        "stop a production boot. Run scripts/provision_roles.py --check for the detail.",
        "REQUIRE_LEAST_PRIVILEGE" if os.getenv("REQUIRE_LEAST_PRIVILEGE") else "not production mode",
        report.get("role"),
        len(violations),
    )
    return report
