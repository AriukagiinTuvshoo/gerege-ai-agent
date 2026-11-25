"""
Stage E — E-02 Phase 10: cross-column login-identity uniqueness (R16).

Written after the Phase 9 audit reported that one normalized login identifier can
name more than one tenant. Phase 10 verified that against the implementation before
fixing it, and the classification in that report was too broad: the collision is
reachable only by an admin (`POST /api/pages` and `/api/pages/credentials` both
`require_admin`; `POST /api/knowledge` only re-saves an existing id), so it is a
privileged provisioning defect, not remote takeover. The defect itself is real and
this suite is about the fix.

Two findings are covered:

  R16a  a `client_username` equal to another row's `page_id` (or the reverse).
        The R10 unique index cannot see this: it covers one column.

  R16b  two `page_id`s differing only by case or surrounding whitespace. These are
        distinct PRIMARY KEYs and one login identifier, because the resolver
        compares `LOWER(TRIM(page_id))`. This was not in the Phase 9 report.

===============================================================================
WHY EVERY ENFORCEMENT TEST ASSERTS REJECTION
===============================================================================
The first implementation of the SQLite triggers used `INSERT OR IGNORE`. Every
collision was silently accepted, and the shape checks (`namespace_is_correct`,
`trigger_present`) still passed, because the table and the triggers were exactly
where they should be. A test that only asserted "the write succeeded" would have
called that green. So each test below asserts that the *second* write is refused,
on both columns, in both directions, and separately asserts that legitimate writes
still succeed — otherwise "reject everything" would pass.

The pre-fix outcome of every test here is recorded in its docstring. It was measured
on both engines before the fix (see the Phase 10 report), so these tests discriminate:
they fail on the pre-fix code rather than passing on both.
"""
import os
import threading

import pytest

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys  # noqa: E402
from core import login_identity as li  # noqa: E402

TEST_SECRET = "phase10-test-secret-0123456789abcdef0123456789"


def _require_postgres_or_sqlite():
    from core import db_engine

    return "postgresql" if db_engine.is_postgres() else "sqlite"


def engine_id() -> str:
    """Engine identity, recorded in every concurrency assertion message."""
    from core import db_engine

    if db_engine.is_postgres():
        try:
            conn = database.get_connection()
            cur = conn.cursor()
            cur.execute("SHOW server_version")
            version = cur.fetchone()[0]
            cur.execute("SHOW transaction_isolation")
            iso = cur.fetchone()[0]
            conn.close()
            return f"postgresql {version} (isolation {iso})"
        except Exception:
            return "postgresql"
    return f"sqlite {__import__('sqlite3').sqlite_version} (per-connection deferred)"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """
    A private database at head, so the namespace exists and is in force.

    Honours a configured PostgreSQL with `R10_REQUIRE_POSTGRES=1`, which turns the
    SQLite fallback into a hard failure instead of a silent downgrade — the same
    contract the Phase 8 fixture uses, so CI cannot report a PostgreSQL pass that
    actually ran on SQLite.
    """
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    require_pg = (os.getenv("R10_REQUIRE_POSTGRES") or "").strip() == "1"

    if db_url:
        monkeypatch.setenv("DATABASE_URL", db_url)
    else:
        if require_pg:
            pytest.fail(
                "R10_REQUIRE_POSTGRES=1 but DATABASE_URL is unset: these tests would run "
                "on SQLite and would not prove PostgreSQL behaviour."
            )
        monkeypatch.delenv("DATABASE_URL", raising=False)
        path = tmp_path / "p10.db"
        monkeypatch.setenv("DB_PATH", str(path))
        monkeypatch.setattr(database, "DB_PATH", str(path))

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()

    _repair_shared_state()
    database.init_db()

    from core import db_engine

    if require_pg and not db_engine.is_postgres():
        pytest.fail("R10_REQUIRE_POSTGRES=1 but the active engine is not PostgreSQL")

    _delete_all()
    return database


def _delete_all():
    conn = database.get_connection()
    try:
        conn.cursor().execute("DELETE FROM pages")
        conn.commit()
    finally:
        conn.close()


def _repair_shared_state():
    """
    Restore both invariants before `init_db()`, which refuses to boot without them.

    A previous run (or a crashed test) can leave the projection dropped, which makes
    `init_db()` impossible. Repair first so the suite is order-independent and safe to
    run repeatedly against the same database — which is what CI does.
    """
    from core import schema_manager
    from core import username_uniqueness as uniq

    conn = database.get_connection()
    try:
        if not uniq.index_is_correct(conn):
            try:
                conn.cursor().execute("DELETE FROM pages")
                conn.commit()
                conn.cursor().execute(uniq.create_index_sql(_require_postgres_or_sqlite()))
                conn.commit()
            except Exception:
                pass
    finally:
        conn.close()

    # Only meaningful if a schema exists at all: on a brand-new database `pages` is
    # absent and both invariants are legitimately unsatisfied until `init_db()` runs.
    conn = database.get_connection()
    try:
        has_pages = li.table_present(conn, "pages")
    except Exception:
        has_pages = False
    finally:
        conn.close()
    if not has_pages:
        return

    try:
        schema_manager.assert_security_invariants()
    except RuntimeError:
        # Rebuild the projection from `pages` — the only source of truth — the same way
        # the repair tool does, so a suite never continues without the invariant.
        from core import login_identity

        dialect = _require_postgres_or_sqlite()
        conn = database.get_connection()
        try:
            cur = conn.cursor()
            for stmt in login_identity.drop_triggers_sql(dialect):
                cur.execute(stmt)
            cur.execute(login_identity.drop_table_sql(dialect))
            conn.commit()
            if not login_identity.find_identifier_collisions(conn):
                cur.execute(login_identity.create_table_sql(dialect))
                cur.execute(login_identity.backfill_namespace_sql(dialect))
                for stmt in login_identity.create_triggers_sql(dialect):
                    cur.execute(stmt)
                conn.commit()
        finally:
            conn.close()


def _make_pages(page_ids):
    for page_id in page_ids:
        database.save_page(page_id=page_id, name=page_id, category="general")


def _claim(page_id, username, password="Pw-Phase10-1"):
    database.set_client_credentials(page_id=page_id, username=username, password=password)


# ===========================================================================
# R16a — username/page_id cross-column collision
# ===========================================================================


def test_1001_page_id_equal_to_existing_username_is_refused(db):
    """
    A new page whose id equals another tenant's login username must be refused.

    Pre-fix: ACCEPTED. `save_page` is a raw INSERT/UPDATE with no reverse guard, and the
    R10 index only looks at `client_username`, so nothing compared the two columns.
    """
    _make_pages(("p10-a",))
    _claim("p10-a", "taken_name")

    with pytest.raises(Exception) as excinfo:
        database.save_page(page_id="taken_name", name="x", category="general")
    assert li.is_identifier_violation(excinfo.value), (
        f"refused, but not by the namespace constraint: {type(excinfo.value).__name__}"
    )
    assert database.get_page("taken_name") is None, "the colliding page was created anyway"


def test_1002_page_id_equal_to_existing_username_ignoring_case(db):
    """
    The same, differing only by case and surrounding whitespace.

    Pre-fix: ACCEPTED. The resolver normalizes with `LOWER(TRIM(...))`, so these are one
    identifier; the primary key sees two.
    """
    _make_pages(("p10-b",))
    _claim("p10-b", "taken_case")

    with pytest.raises(Exception) as excinfo:
        database.save_page(page_id="  TAKEN_CASE  ".strip(), name="x", category="general")
    assert li.is_identifier_violation(excinfo.value)
    assert database.get_page("TAKEN_CASE") is None


def test_1003_username_equal_to_existing_page_id_is_refused(db):
    """
    The reverse direction: claiming a username that equals another tenant's page_id.

    Pre-fix: refused by the sequential guard in `set_client_credentials`, which is why
    Phase 9 saw only one direction. Kept because the database must refuse it too — the
    application check is a pre-SELECT and cannot survive concurrency.
    """
    _make_pages(("p10-c", "p10-c2"))

    # TWO independent refusals can fire here and either is acceptable: the sequential
    # guard in `set_client_credentials` (because `p10-c` already exists) and the database
    # constraint behind it. The application guard is the friendly message; the database
    # constraint is the one that survives concurrency (see test_1004 for the ordering
    # that defeats the guard). Asserting only the database error here would be asserting
    # the wrong layer -- and would break the moment the friendlier check runs first.
    with pytest.raises(Exception) as excinfo:
        _claim("p10-c2", "P10-C")
    assert isinstance(
        excinfo.value, database.CredentialConflictError
    ) or li.is_identifier_violation(excinfo.value), (
        f"refused for an unrelated reason: {type(excinfo.value).__name__}"
    )


def test_1004_username_equal_to_existing_page_id_reverse_order_is_refused(db):
    """
    The dangerous ordering: claim the username FIRST, then create the page it collides with.

    Pre-fix: ACCEPTED. The sequential guard compares against page_ids that exist *now*, so
    the reverse order slips through — this is the reachable path in production, and the
    reason a pre-SELECT is not a fix.
    """
    _make_pages(("p10-d",))
    _claim("p10-d", "future_page")  # projects nothing yet; no page with this id exists

    with pytest.raises(Exception) as excinfo:
        database.save_page(page_id="future_page", name="x", category="general")
    assert li.is_identifier_violation(excinfo.value)
    assert database.get_page("future_page") is None


# ===========================================================================
# R16b — page_id case/whitespace collision (not in the Phase 9 report)
# ===========================================================================


def test_1011_page_ids_differing_only_by_case_are_refused(db):
    """
    `Alice` and `alice` are distinct primary keys and ONE login identifier.

    Pre-fix: ACCEPTED, and measured — `Alice` and `alice` coexisted as two rows while the
    resolver returned only `Alice`, so `alice`'s own page_id + its own password did not
    authenticate. This finding is not in the Phase 9 report.
    """
    _make_pages(("Alice",))

    with pytest.raises(Exception) as excinfo:
        database.save_page(page_id="alice", name="x", category="general")
    assert li.is_identifier_violation(excinfo.value)
    assert database.get_page("alice") is None, "a shadowed duplicate page_id was created"


def test_1012_removing_and_recreating_a_page_in_a_new_case_is_refused(db):
    """
    Renaming a page by delete-then-recreate in different case must be refused too, because
    between the two steps another tenant could hold the identifier. Here the collision is
    direct: the old row still exists.
    """
    _make_pages(("p10-e",))
    with pytest.raises(Exception) as excinfo:
        database.save_page(page_id="P10-E", name="x", category="general")
    assert li.is_identifier_violation(excinfo.value)


# ===========================================================================
# The must-still-work half: a filter that rejects everything is not a fix
# ===========================================================================


def test_1021_distinct_identifiers_are_unaffected(db):
    _make_pages(("p10-f1", "p10-f2"))
    _claim("p10-f1", "user_one")
    _claim("p10-f2", "user_two")
    assert database.get_page("p10-f1") and database.get_page("p10-f2")


def test_1022_a_page_can_update_itself_without_self_colliding(db):
    """
    An UPDATE that keeps its own identifier must not collide with itself.

    This is a real trap: an UPDATE trigger that inserts the new identifier before deleting
    the old one deadlocks against the page's own unchanged row. The trigger deletes per
    page (`WHERE page_id = OLD.page_id`, then `= NEW.page_id`) for exactly this reason.
    """
    _make_pages(("p10-g",))
    _claim("p10-g", "keep_me")

    database.save_page(page_id="p10-g", name="renamed display name", category="general")
    _claim("p10-g", "keep_me")  # same username again

    row = database.get_page("p10-g")
    assert row["name"] == "renamed display name"


def test_1023_blank_usernames_contribute_no_identifier(db):
    """Many pages may leave `client_username` empty: absence is not a claim."""
    _make_pages(("p10-h1", "p10-h2", "p10-h3"))
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM page_login_namespace WHERE normalized_identifier = ''"
        )
        assert cur.fetchone()[0] == 0, "an empty identifier was projected"
    finally:
        conn.close()


def test_1024_deleting_a_page_releases_its_identifiers(db):
    _make_pages(("p10-i",))
    _claim("p10-i", "released_name")
    database.delete_page("p10-i")

    conn = database.get_connection()
    try:
        assert not li.find_identifier_collisions(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM page_login_namespace WHERE page_id = ?", ("p10-i",)
        )
        assert cur.fetchone()[0] == 0, "the deleted page's identifiers were not released"
    finally:
        conn.close()

    # ...and a different tenant may now take it.
    database.save_page(page_id="released_name", name="new", category="general")
    assert database.get_page("released_name") is not None


# ===========================================================================
# Concurrency — the reason this is a PRIMARY KEY and not a pre-SELECT
# ===========================================================================


def _race(claim_username, create_page, trials, label):
    """
    Run two opposite-column claims at the same instant, `trials` times.

    Returns the number of trials in which BOTH writes reported success. That number must be
    zero: it would mean two tenants now share one identifier.
    """
    both_won = 0
    for trial in range(trials):
        victim = f"p10-rc-v{trial}"
        attacker = f"p10-rc-a{trial}"
        for page_id in (victim, attacker):
            try:
                database.delete_page(page_id)
            except Exception:
                pass
        database.save_page(page_id=attacker, name="a", category="general")

        outcomes = {}
        barrier = threading.Barrier(2)

        def do_claim():
            barrier.wait(timeout=30)
            try:
                database.set_client_credentials(
                    page_id=attacker, username=victim, password="Pw-Attacker-1"
                )
                outcomes["claim"] = "OK"
            except Exception as exc:
                outcomes["claim"] = type(exc).__name__

        def do_create():
            barrier.wait(timeout=30)
            try:
                database.save_page(page_id=victim, name="v", category="general")
                outcomes["create"] = "OK"
            except Exception as exc:
                outcomes["create"] = type(exc).__name__

        threads = [threading.Thread(target=do_claim), threading.Thread(target=do_create)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        if outcomes.get("claim") == "OK" and outcomes.get("create") == "OK":
            both_won += 1

        conn = database.get_connection()
        try:
            assert not li.find_identifier_collisions(conn), (
                f"{label}: trial {trial} left a cross-column collision behind on "
                f"{engine_id()}; outcomes={outcomes}"
            )
        finally:
            conn.close()

        for page_id in (victim, attacker):
            try:
                database.delete_page(page_id)
            except Exception:
                pass

    return both_won


def test_1031_concurrent_opposite_column_claims_do_not_both_win(db):
    """
    Two connections, one claiming a username and one creating the matching page_id.

    Pre-fix: BOTH WON on every trial. The application guard is a SELECT before the write,
    so at this interleaving neither side sees the other; measured 12/12 on PostgreSQL 16
    and 8/12 on SQLite during Phase 9's reproduction of the same shape.
    """
    both_won = _race(None, None, trials=12, label="opposite-column")
    assert both_won == 0, (
        f"{both_won}/12 trials let both opposite-column claims succeed on {engine_id()}"
    )


def test_1032_concurrent_page_id_case_collision_does_not_both_win(db):
    """Two page_ids differing only by case, created concurrently."""
    both_won = 0
    for trial in range(12):
        lower = f"p10-cc-{trial}"
        upper = lower.upper()
        for page_id in (lower, upper):
            try:
                database.delete_page(page_id)
            except Exception:
                pass

        outcomes = {}
        barrier = threading.Barrier(2)

        def make(page_id):
            barrier.wait(timeout=30)
            try:
                database.save_page(page_id=page_id, name=page_id, category="general")
                outcomes[page_id] = "OK"
            except Exception as exc:
                outcomes[page_id] = type(exc).__name__

        threads = [
            threading.Thread(target=make, args=(lower,)),
            threading.Thread(target=make, args=(upper,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        if len([v for v in outcomes.values() if v == "OK"]) == 2:
            both_won += 1

        for page_id in (lower, upper):
            try:
                database.delete_page(page_id)
            except Exception:
                pass

    assert both_won == 0, f"{both_won}/12 concurrent case collisions both succeeded"


def test_1033_concurrent_identical_usernames_still_refused(db):
    """
    The R10 guarantee must survive: two tenants claiming one username concurrently.

    This is the Phase 8 property, re-asserted here because this change touches the same
    write paths — a regression in it would be invisible to tests that only look at
    cross-column behaviour.
    """
    both_won = 0
    for trial in range(12):
        first, second = f"p10-u1-{trial}", f"p10-u2-{trial}"
        for page_id in (first, second):
            try:
                database.delete_page(page_id)
            except Exception:
                pass
            database.save_page(page_id=page_id, name=page_id, category="general")

        outcomes = {}
        barrier = threading.Barrier(2)

        def claim(page_id):
            barrier.wait(timeout=30)
            try:
                database.set_client_credentials(
                    page_id=page_id, username="shared_race_name", password="Pw-Race-1"
                )
                outcomes[page_id] = "OK"
            except Exception as exc:
                outcomes[page_id] = type(exc).__name__

        threads = [
            threading.Thread(target=claim, args=(first,)),
            threading.Thread(target=claim, args=(second,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        if len([v for v in outcomes.values() if v == "OK"]) == 2:
            both_won += 1

        for page_id in (first, second):
            try:
                database.delete_page(page_id)
            except Exception:
                pass

    assert both_won == 0, f"{both_won}/12 concurrent username claims both succeeded"


# ===========================================================================
# The projection must never be trusted over `pages`
# ===========================================================================


def test_1041_projection_agrees_with_pages(db):
    _make_pages(("p10-j1", "p10-j2"))
    _claim("p10-j1", "proj_one")
    conn = database.get_connection()
    try:
        assert li.namespace_is_correct(conn), "the projection does not match `pages`"
        assert li.trigger_present(conn), "the triggers are missing"
    finally:
        conn.close()


def test_1042_collision_scan_is_read_only(db):
    _make_pages(("p10-k1", "p10-k2"))
    _claim("p10-k1", "readonly_probe")
    before = [dict(p) for p in database.get_all_pages()]
    conn = database.get_connection()
    try:
        li.find_identifier_collisions(conn)
        li.find_identifier_collisions(conn)
    finally:
        conn.close()
    after = [dict(p) for p in database.get_all_pages()]
    assert after == before


def test_1043_violation_matcher_is_narrow(db):
    """
    `is_identifier_violation` decides whether an admin request becomes a 409. A false
    positive would report an unrelated constraint failure as an identity conflict, so it
    must not match other unique constraints.
    """
    assert li.is_identifier_violation(
        Exception("UNIQUE constraint failed: page_login_namespace.normalized_identifier")
    )
    assert li.is_identifier_violation(
        Exception('duplicate key value violates unique constraint "page_login_namespace_pkey"')
    )
    assert not li.is_identifier_violation(Exception("UNIQUE constraint failed: pages.page_id"))
    assert not li.is_identifier_violation(
        Exception("UNIQUE constraint failed: uq_pages_client_username_norm")
    )
    assert not li.is_identifier_violation(ValueError("something else entirely"))


def test_1044_startup_refuses_a_missing_projection_or_triggers(db):
    """
    The guard must fail loudly on both halves, because a correct-looking table with no
    triggers is a stale snapshot that enforces nothing — the same trap as the R10 impostor
    index. Restored afterwards, with the restoration asserted.
    """
    from core.schema_manager import assert_security_invariants
    from _username_uniqueness_support import (
        restore_login_identity,
        suspend_login_identity,
    )

    dialect = _require_postgres_or_sqlite()
    assert_security_invariants()  # healthy baseline

    suspend_login_identity()
    try:
        with pytest.raises(RuntimeError):
            assert_security_invariants()
    finally:
        restore_login_identity(dialect)
    assert_security_invariants()


def test_1045_a_rejected_write_leaves_the_connection_usable(db):
    """
    A refused write must not poison the database for the next writer.

    HONESTY NOTE. This was originally written to pin a rollback I added to `save_page`,
    on the theory that SQLite leaves the write transaction open after a trigger aborts a
    statement and the connection is then closed holding the lock. Measurement showed
    `close()` releases that lock regardless, so the test PASSES on the pre-rollback code
    too — it does not discriminate, and it is not the reason the rollback exists. The
    rollback is defensive.

    The property is still worth pinning, because it is the property that would break if
    `save_page` ever stopped closing its connection on the error path (which is the real
    hazard: an *unclosed* connection blocks every later SQLite writer, measured). So this
    asserts the outcome, not the mechanism.
    """
    _make_pages(("p10-l",))
    _claim("p10-l", "lock_probe")

    for attempt in range(5):
        with pytest.raises(Exception):
            database.save_page(page_id="lock_probe", name="x", category="general")
        # Each rejection must leave the database writable.
        database.save_page(page_id=f"p10-after-reject-{attempt}", name="ok", category="general")
        assert database.get_page(f"p10-after-reject-{attempt}") is not None


def test_1046_an_unclosed_connection_is_what_actually_blocks_writers(db):
    """
    The mechanism behind the `database is locked` that appeared during development.

    An OPEN connection — even one that has only ever read — blocks every later writer on
    SQLite. That is a harness defect (a script forgetting `close()`), not a product bug,
    and it is pinned here so the next person does not misattribute it to the trigger or
    to `save_page`, as I initially did.
    """
    from core import db_engine

    if db_engine.is_postgres():
        pytest.skip("this is a SQLite locking property; PostgreSQL does not behave this way")

    _make_pages(("p10-m",))
    _claim("p10-m", "leak_probe")

    leaked = database.get_connection()
    try:
        # Refused through the namespace constraint, on a connection that is then left open.
        with pytest.raises(Exception):
            leaked.cursor().execute(
                "INSERT INTO pages (page_id, name, category) VALUES ('leak_probe', 'x', 'general')"
            )
        with pytest.raises(Exception) as excinfo:
            database.save_page(page_id="p10-while-leaked", name="o", category="general")
        assert "locked" in str(excinfo.value).lower(), (
            f"expected a lock error from the leaked connection, got {excinfo.value!r}"
        )
    finally:
        leaked.close()

    # Released: the writer works again.
    database.save_page(page_id="p10-after-leak", name="ok", category="general")
    assert database.get_page("p10-after-leak") is not None
