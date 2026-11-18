#!/usr/bin/env python3
"""Provision the least-privilege PostgreSQL roles for Gerege (finding E-05).

Two roles, and only two:

``gerege_owner``
    ``NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION``. Owns the schema objects.
    Runs Alembic, ``pg_dump``/restore, and the repair scripts. Never used by web/worker.

``gerege_app``
    ``NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION``. Owns nothing, has no DDL.
    ``SELECT, INSERT, UPDATE, DELETE`` on the business tables, ``SELECT, INSERT`` only
    on ``audit_logs``, ``USAGE`` on the sequences, ``SELECT`` on ``alembic_version``.
    This is the credential in ``DATABASE_URL`` for both runtime processes.

No ``gerege_readonly``: no operational consumer needs one, and an unused login role is
standing attack surface rather than a control.

Usage
-----
::

    python scripts/provision_roles.py --check       # read-only report, always exit 0
    python scripts/provision_roles.py --verify      # read-only; exit 1 if not least-privileged
    python scripts/provision_roles.py --dry-run     # print the SQL, change nothing
    python scripts/provision_roles.py --apply       # converge the cluster to the model

    python scripts/provision_roles.py --apply --rotate app    # rotate one password
    python scripts/provision_roles.py --apply --rotate owner

Passwords come from ``GEREGE_OWNER_PASSWORD`` / ``GEREGE_APP_PASSWORD``. If a password
is missing during ``--apply`` a strong one is generated and printed **once** to stdout
with a banner; it is never stored by this script, never logged, and never included in
an exception. ``--check``, ``--verify`` and ``--dry-run`` never print or read one.

Why the script converges instead of only creating
-------------------------------------------------
A restore replaces the schema: ``core.backup_service`` drops and recreates ``public``
and replays a dump taken with ``--no-owner --no-privileges``, so **every grant on
``gerege_app`` is destroyed by a restore**. The role survives; its access does not.
``--apply`` is therefore part of the restore procedure, not just of first-time setup,
and it derives grants from the live catalogue rather than from a hand-typed list so a
new table added by a migration is covered without editing this file.

``--apply`` revokes before it grants, so running it twice converges, and running it
after someone added a grant out of band removes that grant.
"""
from __future__ import annotations

import argparse
import os
import secrets
import string
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db_privileges import (  # noqa: E402
    ALWAYS_FORBIDDEN_PRIVILEGES,
    OWNER_ROLE,
    REQUIRED_TABLE_PRIVILEGES,
    RUNTIME_ROLE,
    collect_runtime_privileges,
    evaluate_runtime_privileges,
)

SCHEMA = "public"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _mask(value: str) -> str:
    """Never let a password reach a log line, even partially."""
    return "********" if value else ""


def _generate_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _quote_literal(conn, value: str) -> str:
    """Quote a string for a DDL statement that cannot take a bind parameter.

    ``CREATE ROLE ... PASSWORD`` is utility syntax, so ``%s`` is not accepted. Rather
    than build the literal by hand (and get it wrong on the first ``'``), ask the
    driver's own quoter.
    """
    cur = conn.cursor()
    try:
        quoted = cur.mogrify("%s", (value,))
        return quoted.decode("utf-8") if isinstance(quoted, bytes) else quoted
    finally:
        cur.close()


def _query(conn, sql: str, params: Sequence[Any] = ()) -> List[Tuple]:
    cur = conn.cursor()
    try:
        cur.execute(sql, tuple(params))
        return list(cur.fetchall())
    finally:
        cur.close()


def _role_exists(conn, name: str) -> bool:
    return bool(_query(conn, "SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)))


def _live_relations(conn) -> Dict[str, List[str]]:
    """Every object in the schema that can carry ownership and grants.

    Derived from ``pg_class`` so a table added by a future migration is provisioned
    without touching this script. ``audit_logs`` is included; the matrix narrows it.
    """
    rows = _query(
        conn,
        """
        SELECT c.relname, c.relkind
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = %s
           AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
         ORDER BY c.relname
        """,
        (SCHEMA,),
    )
    tables = [r[0] for r in rows if r[1] in ("r", "p", "v", "m", "f")]
    sequences = [r[0] for r in rows if r[1] == "S"]
    # Functions matter as much as tables for restore: the dump is applied with `--clean`,
    # which emits `DROP FUNCTION` before recreating. A function left owned by the
    # bootstrap user therefore makes a restore fail with "must be owner of function" —
    # discovered by actually running a restore, not by reading the code.
    functions = [
        r[0]
        for r in _query(
            conn,
            """
            SELECT p.oid::regprocedure::text
              FROM pg_proc p
              JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = %s
             ORDER BY 1
            """,
            (SCHEMA,),
        )
    ]
    return {"tables": tables, "sequences": sequences, "functions": functions}


# ---------------------------------------------------------------------------
# SQL plan
# ---------------------------------------------------------------------------
def build_plan(
    conn,
    *,
    owner_password: Optional[str],
    app_password: Optional[str],
    rotate: Optional[str],
    bootstrap_user: str,
) -> List[str]:
    """Return the ordered list of statements that converge the cluster.

    Returned rather than executed so ``--dry-run`` can print exactly what ``--apply``
    would do, and so a reviewer can read the whole plan in one place.
    """
    plan: List[str] = []
    rels = _live_relations(conn)

    def role_ddl(name: str, password: Optional[str], comment: str) -> None:
        common = (
            f"NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS "
            f"NOINHERIT LOGIN"
        )
        if _role_exists(conn, name):
            plan.append(f"-- {name} exists: normalise attributes (idempotent)")
            plan.append(f"ALTER ROLE {name} {common};")
            if password:
                plan.append(
                    f"ALTER ROLE {name} PASSWORD {_quote_literal(conn, password)};"
                )
        else:
            plan.append(f"-- create {name}: {comment}")
            pw = f" PASSWORD {_quote_literal(conn, password)}" if password else ""
            plan.append(f"CREATE ROLE {name} {common}{pw};")

    # NOINHERIT on the login roles is deliberate. Both roles are members of nothing on
    # purpose; should an operator later grant one of them a group role, NOINHERIT means
    # the extra privileges are not silently active — the role would have to SET ROLE
    # explicitly, which is visible in `pg_stat_activity` and in audit logs.

    role_ddl(
        OWNER_ROLE,
        owner_password,
        "schema owner; migrations, backup, restore, repair only",
    )
    role_ddl(
        RUNTIME_ROLE,
        app_password,
        "runtime; web and worker connect as this role",
    )

    if rotate == "owner" and not owner_password:
        raise SystemExit("--rotate owner needs GEREGE_OWNER_PASSWORD to be set")
    if rotate == "app" and not app_password:
        raise SystemExit("--rotate app needs GEREGE_APP_PASSWORD to be set")

    # --- schema-level -------------------------------------------------------
    plan.append(f"-- schema: owner may create, runtime may only use")
    plan.append(f"GRANT USAGE, CREATE ON SCHEMA {SCHEMA} TO {OWNER_ROLE};")
    plan.append(f"GRANT USAGE ON SCHEMA {SCHEMA} TO {RUNTIME_ROLE};")
    plan.append(
        f"-- PostgreSQL < 15 grants CREATE on public to PUBLIC; remove it so the "
        f"runtime cannot create objects even if it were re-granted nothing"
    )
    plan.append(f"REVOKE CREATE ON SCHEMA {SCHEMA} FROM PUBLIC;")

    # --- ownership ----------------------------------------------------------
    # Tables and sequences move to the owner role. Without this the bootstrap user
    # stays the owner, and "the app must not own tables" would be true only by
    # accident of the app not being the bootstrap user any more.
    for table in rels["tables"]:
        plan.append(f"ALTER TABLE {SCHEMA}.{table} OWNER TO {OWNER_ROLE};")
    for seq in rels["sequences"]:
        plan.append(f"ALTER SEQUENCE {SCHEMA}.{seq} OWNER TO {OWNER_ROLE};")
    for func in rels["functions"]:
        plan.append(f"ALTER FUNCTION {SCHEMA}.{func} OWNER TO {OWNER_ROLE};")

    # --- grants: converge from any prior state ------------------------------
    plan.extend(build_grant_plan(conn))
    return plan


def build_grant_plan(conn) -> List[str]:
    """Only the GRANT/REVOKE statements, for a caller that is already the owner.

    Split out from :func:`build_plan` because a restore needs it: replaying a dump
    recreates every table, and the schema's default privileges then grant `gerege_app`
    full CRUD — *including UPDATE and DELETE on audit_logs*, which would silently undo
    the whole point of this phase. Re-converging the grants needs only ownership, not
    CREATEROLE, so a restore running as ``gerege_owner`` can do it in-process.
    """
    plan: List[str] = []
    rels = _live_relations(conn)
    plan.append("-- revoke before granting: running twice converges")
    if rels["tables"]:
        joined = ", ".join(f"{SCHEMA}.{t}" for t in rels["tables"])
        plan.append(f"REVOKE ALL ON {joined} FROM {RUNTIME_ROLE};")
    if rels["sequences"]:
        joined = ", ".join(f"{SCHEMA}.{s}" for s in rels["sequences"])
        plan.append(f"REVOKE ALL ON {joined} FROM {RUNTIME_ROLE};")

    # audit_logs and any table the matrix does not name are handled explicitly below,
    # so a newly migrated table defaults to NO access rather than to full CRUD.
    unnamed = [t for t in rels["tables"] if t not in REQUIRED_TABLE_PRIVILEGES]
    for table in rels["tables"]:
        required = REQUIRED_TABLE_PRIVILEGES.get(table)
        if required is None:
            plan.append(
                f"-- {table}: not in the privilege matrix; no grant. If this table is new, "
                f"add it to core/db_privileges.REQUIRED_TABLE_PRIVILEGES."
            )
            continue
        privs = ", ".join(sorted(required))
        plan.append(f"GRANT {privs} ON {SCHEMA}.{table} TO {RUNTIME_ROLE};")
        forbidden = sorted(set(ALWAYS_FORBIDDEN_PRIVILEGES) - required)
        if forbidden:
            plan.append(
                f"REVOKE {', '.join(forbidden)} ON {SCHEMA}.{table} FROM {RUNTIME_ROLE};"
            )

    if rels["sequences"]:
        # USAGE is what `nextval()` requires for SERIAL inserts; SELECT on the sequence
        # is not needed by any call site (measured: see the E-05 report), so it is
        # withheld — an app that can read a sequence can enumerate insert volume.
        for seq in rels["sequences"]:
            plan.append(f"GRANT USAGE ON SEQUENCE {SCHEMA}.{seq} TO {RUNTIME_ROLE};")

    # alembic_version is a plain table, granted SELECT only: `current_revision()` reads
    # it, nothing writes it outside a migration (which runs as the owner).
    if "alembic_version" in rels["tables"]:
        plan.append(
            f"REVOKE ALL ON {SCHEMA}.alembic_version FROM {RUNTIME_ROLE};"
        )
        plan.append(f"GRANT SELECT ON {SCHEMA}.alembic_version TO {RUNTIME_ROLE};")

    # --- future objects -----------------------------------------------------
    # Grants on existing tables do not survive the next migration's CREATE TABLE. Default
    # privileges fix that; they are scoped FOR ROLE owner, which is the role migrations
    # run as, so the grant applies to what Alembic creates.
    plan.append(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {OWNER_ROLE} IN SCHEMA {SCHEMA} "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {RUNTIME_ROLE};"
    )
    plan.append(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {OWNER_ROLE} IN SCHEMA {SCHEMA} "
        f"GRANT USAGE ON SEQUENCES TO {RUNTIME_ROLE};"
    )
    plan.append(
        "-- audit_logs stays narrower than the default: the startup assertion refuses to "
        "run if UPDATE/DELETE reappear there, so a future CREATE TABLE cannot widen it silently"
    )
    return plan


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def _normalise_dsn(url: str) -> str:
    """Accept a SQLAlchemy URL as well as a libpq one.

    ``DATABASE_URL`` in this project is ``postgresql+psycopg2://…``; psycopg2 itself
    rejects that scheme ("invalid dsn"). Provisioning must accept either form because the
    `migrate` service supplies both kinds depending on which step runs.
    """
    for prefix in ("postgresql+psycopg2://", "postgresql+psycopg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix):]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


def _connect(url: str):
    import psycopg2

    return psycopg2.connect(_normalise_dsn(url))


def _admin_url(explicit: Optional[str]) -> str:
    """The maintenance DSN. Distinct from ``DATABASE_URL`` on purpose.

    ``DATABASE_URL`` is the *runtime* credential. If provisioning fell back to it, the
    script would run as ``gerege_app`` and could not create roles — and worse, on a
    half-migrated host it might succeed partially and leave a state that looks finished.
    """
    if explicit:
        return explicit
    for name in ("ADMIN_DATABASE_URL", "MIGRATION_DATABASE_URL", "DATABASE_URL"):
        value = os.getenv(name, "").strip()
        if name == "DATABASE_URL" and value:
            # Only acceptable when the account is already a provisioning account. The
            # `migrate` service connects as the owner to transfer ownership, and that
            # role can do it — what it cannot do is CREATE ROLE, so `_apply_statements`
            # decides whether this DSN is sufficient for the plan it was given.
            return value
        if value:
            return value
    host = os.getenv("POSTGRES_HOST", "127.0.0.1")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "gerege_crm")
    user = os.getenv("POSTGRES_ADMIN_USER") or os.getenv("POSTGRES_USER", "postgres")
    password = os.getenv("POSTGRES_ADMIN_PASSWORD") or os.getenv("POSTGRES_PASSWORD", "")
    if not password:
        raise SystemExit(
            "No admin DSN. Set ADMIN_DATABASE_URL, or POSTGRES_ADMIN_PASSWORD / "
            "POSTGRES_PASSWORD. The provisioning role must be able to CREATE ROLE."
        )
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def cmd_check(url: str, verify_only: bool = False) -> int:
    conn = _connect(url)
    try:
        rels = _live_relations(conn)
        print(f"schema '{SCHEMA}': {len(rels['tables'])} table(s), {len(rels['sequences'])} sequence(s)")
        print()
        role_state: Dict[str, bool] = {}
        for role in (OWNER_ROLE, RUNTIME_ROLE):
            exists = _role_exists(conn, role)
            role_state[role] = exists
            attrs = _query(
                conn,
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin "
                "FROM pg_roles WHERE rolname = %s",
                (role,),
            )
            if exists:
                s, d, c, r, b, l = attrs[0]
                print(
                    f"{role:<16} exists  superuser={s} createdb={d} createrole={c} "
                    f"replication={r} bypassrls={b} login={l}"
                )
            else:
                print(f"{role:<16} MISSING")

        # Ownership summary: which roles own objects in the schema?
        owners = _query(
            conn,
            """
            SELECT pg_get_userbyid(c.relowner), COUNT(*)
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = %s AND c.relkind IN ('r','p','S','v','m','f')
             GROUP BY 1 ORDER BY 2 DESC
            """,
            (SCHEMA,),
        )
        print("\nobjects by owner:")
        for owner, count in owners:
            print(f"  {owner:<24} {count}")

        problems: List[str] = []
        if not role_state.get(OWNER_ROLE):
            problems.append(f"{OWNER_ROLE} does not exist")
        if not role_state.get(RUNTIME_ROLE):
            problems.append(f"{RUNTIME_ROLE} does not exist")

        # Evaluate the runtime role by actually becoming it where possible, so the
        # report reflects inherited rights rather than the catalog entry alone.
        if role_state.get(RUNTIME_ROLE):
            report = _impersonation_report(conn, RUNTIME_ROLE)
            if report is not None:
                problems.extend(evaluate_runtime_privileges(report))
            else:
                print(
                    f"\n(cannot SET ROLE {RUNTIME_ROLE} from this session; "
                    "run --verify as that role for a definitive answer)"
                )

        print()
        if problems:
            print("NOT least-privileged:")
            for problem in problems:
                print(f"  - {problem}")
            print("\nRun: python scripts/provision_roles.py --apply")
            return 1 if verify_only else 0
        print("Runtime role holds least privilege.")
        return 0
    finally:
        conn.close()


def _impersonation_report(conn, role: str) -> Optional[Dict[str, Any]]:
    """Collect the privilege report *as* ``role`` would see it.

    ``SET ROLE`` then ``RESET ROLE`` on the same connection is the only way to ask
    ``has_table_privilege`` about inherited rights without opening a second session
    with a password the checking process may not have.
    """
    try:
        cur = conn.cursor()
        cur.execute(f"SET ROLE {role}")
        try:
            report = collect_runtime_privileges(conn)
        finally:
            cur.execute("RESET ROLE")
            cur.close()
        return report
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return None


def cmd_dry_run(url: str) -> int:
    conn = _connect(url)
    try:
        plan = build_plan(
            conn,
            owner_password=os.getenv("GEREGE_OWNER_PASSWORD") or None,
            app_password=os.getenv("GEREGE_APP_PASSWORD") or None,
            rotate=None,
            bootstrap_user=os.getenv("POSTGRES_USER", "postgres"),
        )
    finally:
        conn.close()
    # `--dry-run` must never print a password. The plan legitimately contains
    # `CREATE ROLE ... PASSWORD '<literal>'` when a password is supplied in the
    # environment, and a dry run is exactly the mode an operator runs in a terminal they
    # may be screen-sharing or pasting into a ticket. Redact the literal, keep the shape.
    import re as _re

    printed = 0
    for statement in plan:
        if statement.startswith("--"):
            print(statement)
            continue
        print(_re.sub(r"PASSWORD '(?:[^']|'')*'", "PASSWORD '********'", statement))
        printed += 1
    print(f"\n-- {printed} statement(s); nothing was executed")
    return 0


def cmd_apply(url: str, rotate: Optional[str], converge_only: bool = False) -> int:
    owner_password = os.getenv("GEREGE_OWNER_PASSWORD", "").strip() or None
    app_password = os.getenv("GEREGE_APP_PASSWORD", "").strip() or None

    generated: Dict[str, str] = {}
    if converge_only:
        # Grants only: no role DDL and no passwords, so this is safe with the owner
        # credential and cannot rotate a live password by accident.
        owner_password = app_password = None
    elif rotate in (None, "owner") and not owner_password:
        owner_password = _generate_password()
        generated[OWNER_ROLE] = owner_password
    if not converge_only and rotate in (None, "app") and not app_password:
        app_password = _generate_password()
        generated[RUNTIME_ROLE] = app_password

    conn = _connect(url)
    conn.autocommit = True
    try:
        if converge_only:
            plan = build_grant_plan(conn)
        else:
            plan = build_plan(
                conn,
                owner_password=owner_password,
                app_password=app_password,
                rotate=rotate,
                bootstrap_user=os.getenv("POSTGRES_USER", "postgres"),
            )
        executed = 0
        for statement in plan:
            if statement.startswith("--"):
                continue
            try:
                cur = conn.cursor()
                cur.execute(statement)
                cur.close()
                executed += 1
            except Exception as exc:
                # Report the statement *position* and the server's message, never the
                # statement text: a password statement must not reach an exception log.
                hint = ""
                if "permission denied" in str(exc) and "role" in str(exc).lower():
                    hint = (
                        "\nThis statement needs a role-provisioning account. Re-run with "
                        "ADMIN_DATABASE_URL pointing at a superuser (or a CREATEROLE role). "
                        "Transfers of ownership and grants do NOT need it — use --converge-only "
                        "plus a full --apply from the owner role."
                    )
                raise SystemExit(
                    f"statement {executed + 1} failed ({type(exc).__name__}): {exc}{hint}\n"
                    f"Nothing after it was applied. Re-run --apply; it converges."
                )
        print(f"Applied {executed} statement(s).")

        # Verify with the same evaluator the startup assertion uses, so a provisioning
        # run cannot report success on a database the application will refuse to boot on.
        report = _impersonation_report(conn, RUNTIME_ROLE)
        if report is None:
            print(
                f"\nWARNING: could not SET ROLE {RUNTIME_ROLE} to verify. "
                "Re-run from a superuser session."
            )
        else:
            violations = evaluate_runtime_privileges(report)
            if violations:
                print("\nProvisioning did not reach least privilege:")
                for violation in violations:
                    print(f"  - {violation}")
                return 1
            print(f"Verified: '{RUNTIME_ROLE}' holds least privilege "
                  f"({len(report['table_privileges'])} table(s) evaluated).")
    finally:
        conn.close()

    if generated:
        print("\n" + "=" * 68)
        print("GENERATED PASSWORDS - shown once, not stored, not logged")
        for role, password in generated.items():
            print(f"  {role}: {password}")
        print("Store these in your secret manager now. Re-run --apply --rotate <role>")
        print("to replace them; the old password stops working immediately.")
        print("=" * 68)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision gerege_owner / gerege_app (finding E-05).",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="read-only report (default)")
    group.add_argument("--verify", action="store_true", help="read-only; exit 1 if not least-privileged")
    group.add_argument("--dry-run", action="store_true", help="print SQL, execute nothing")
    group.add_argument("--apply", action="store_true", help="converge the database")
    parser.add_argument(
        "--rotate",
        choices=("app", "owner"),
        help="with --apply: replace one password and print it once",
    )
    parser.add_argument(
        "--converge-only",
        action="store_true",
        help=(
            "with --apply: only re-apply grants, do not create roles, move ownership or "
            "touch passwords. Safe as the owner role; needs no CREATEROLE. Used after a "
            "migration or a restore has recreated tables."
        ),
    )
    parser.add_argument("--admin-url", default=None, help="maintenance DSN (never logged)")
    args = parser.parse_args(argv)

    if args.rotate and not args.apply:
        parser.error("--rotate requires --apply")

    url = _admin_url(args.admin_url)
    if args.converge_only and not args.apply and not args.dry_run:
        parser.error("--converge-only requires --apply (or --dry-run)")
    if args.dry_run:
        return cmd_dry_run(url)
    if args.apply:
        return cmd_apply(url, args.rotate, converge_only=args.converge_only)
    return cmd_check(url, verify_only=args.verify)


if __name__ == "__main__":
    sys.exit(main())
