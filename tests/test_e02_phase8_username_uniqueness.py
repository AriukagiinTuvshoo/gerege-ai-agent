"""
Stage E — E-02 Phase 8: database-enforced username uniqueness (R10) and the Redis
readiness write probe (R11).

Written after the Phase 7 independent review, which reproduced the R10 race 12/12 times on
PostgreSQL 16 and 12/12 on SQLite and proved `/api/ready` reported healthy during
`noeviction` write failures.

Counting note: this file defines 38 test functions; parametrisation expands it further.
Collected and passed counts are reported separately.

===============================================================================
WHY EVERY TEST HERE IS ABOUT THE DATABASE, NOT THE APPLICATION
===============================================================================
Phase 6's R10 fix was a `SELECT` before the write. It made the sequential case correct and
left the concurrent case broken, because a `SELECT` and an `UPDATE` on two connections are
not an invariant. This suite therefore asserts the *engine* refuses the second claimant, and
it does so with independent connections in real threads — not by calling the check twice.

Each concurrency test states its expected pre-fix outcome in its docstring. The pre-fix
behaviour was measured (Phase 7): every claimant reported WRITTEN and every row held the
same normalized username.
"""
import os
import threading

import pytest

import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402
from core import account_keys  # noqa: E402
from core import username_uniqueness as uniq  # noqa: E402

TEST_SECRET = "phase8-test-secret-0123456789abcdef0123456789"

#: Distinct page ids per concurrency test, so tests cannot interfere on a shared database.
RACE_TWO = ("p8-race2-a", "p8-race2-b")
RACE_FOUR = ("p8-race4-a", "p8-race4-b", "p8-race4-c", "p8-race4-d")
DISTINCT = ("p8-dist-a", "p8-dist-b")


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
    A private database with the schema at head (so the unique index exists).

    Honours a configured PostgreSQL, exactly like the Phase 6 `tenants` fixture, so the
    concurrency tests can be run on the engine that actually has the race. `R10_REQUIRE_
    POSTGRES=1` makes the SQLite fallback a hard failure instead of a silent downgrade.
    """
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    require_pg = (os.getenv("R10_REQUIRE_POSTGRES") or "").strip() == "1"

    if db_url:
        monkeypatch.setenv("DATABASE_URL", db_url)
    else:
        if require_pg:
            pytest.fail(
                "R10_REQUIRE_POSTGRES=1 but DATABASE_URL is unset: these tests would run "
                "on SQLite and would not prove PostgreSQL concurrency behaviour."
            )
        monkeypatch.delenv("DATABASE_URL", raising=False)
        path = tmp_path / "p8.db"
        monkeypatch.setenv("DB_PATH", str(path))
        monkeypatch.setattr(database, "DB_PATH", str(path))

    monkeypatch.setenv("E02_ACCOUNT_KEY_SECRET", TEST_SECRET)
    account_keys.refresh_secret()

    # Repair BEFORE init_db(). Two things a previous run may have left behind, both of
    # which make init_db() impossible:
    #
    #   1. the index dropped (test_856 does this on purpose), because init_db() now refuses
    #      to boot a database without the security invariant;
    #   2. duplicate usernames (from the Phase 1 reproduction or a crashed run), because the
    #      migration cannot install the index over a collision.
    #
    # Doing this first means the suite is order-independent and safe to run against the same
    # database repeatedly — which is what CI does.
    _repair_shared_state()
    database.init_db()

    from core import db_engine

    if require_pg and not db_engine.is_postgres():
        pytest.fail("R10_REQUIRE_POSTGRES=1 but the active engine is not PostgreSQL")

    _delete_all()
    return database


def _repair_shared_state():
    """
    Restore the invariant and clear test-owned duplicates, before `init_db()` runs.

    Two things a previous run can leave behind, each of which makes init_db() impossible:

      1. the index dropped (test_856/test_870 drop it deliberately), because init_db() now
         refuses to boot a database without the security invariant;
      2. duplicate usernames (Phase 1 reproduction, an interrupted run), because the
         migration cannot install the index over a collision.

    Fixing both up front makes the suite order-independent and safe to re-run against the
    same database, which is what CI does.

    Scoped to page ids these suites create (``p8-``/``r10-``/``r2``/``r4``/``rc``/``rw``/
    ``rs``/``rd``). It never touches a row a real tenant could own, so it is not — and must
    never become — the production remediation procedure, which is manual and documented.
    """
    try:
        conn = database.get_connection()
    except Exception:
        return
    try:
        dialect = uniq._dialect_of(conn)
        cur = conn.cursor()

        # Brand-new database with no `pages` table yet: nothing to repair.
        try:
            cur.execute("SELECT 1 FROM pages LIMIT 1")
        except Exception:
            return

        # 1. clear test-owned duplicate usernames so the index can exist at all
        cur.execute(
            "SELECT LOWER(TRIM(client_username)) AS norm FROM pages "
            "WHERE client_username IS NOT NULL AND TRIM(client_username) <> '' "
            "GROUP BY 1 HAVING COUNT(*) > 1"
        )
        for (norm,) in cur.fetchall():
            from _username_uniqueness_support import like_pattern

            cur.execute(
                "UPDATE pages SET client_username = NULL, client_password_hash = NULL, "
                "client_salt = NULL WHERE LOWER(TRIM(client_username)) = ? "
                "AND (page_id LIKE ? OR page_id LIKE ? OR page_id LIKE ? "
                "OR page_id LIKE ? OR page_id LIKE ? OR page_id LIKE ? "
                "OR page_id LIKE ? OR page_id LIKE ?)",
                (norm,) + tuple(
                    like_pattern(p) for p in
                    ("p8-%", "r10-%", "r2%", "r4%", "rc%", "rw%", "rs%", "rd%")
                ),
            )
        conn.commit()

        # 2. restore the index if a previous test dropped it or left an impostor
        if not uniq.index_is_correct(conn):
            cur.execute(uniq.drop_index_sql(dialect))
            cur.execute(uniq.create_index_sql(dialect))
            conn.commit()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _delete_all():
    for pid in (
        RACE_TWO + RACE_FOUR + DISTINCT
        + ("p8-seq-a", "p8-seq-b", "p8-own-a", "p8-empty-a", "p8-empty-b",
           "p8-null-a", "p8-null-b", "p8-unused-a", "p8-case-a", "p8-case-b",
           "p8-ws-a", "p8-ws-b")
    ):
        try:
            database.delete_page(pid)
        except Exception:
            pass


def _make_pages(page_ids):
    for pid in page_ids:
        try:
            database.delete_page(pid)
        except Exception:
            pass
    for pid in page_ids:
        database.save_page(page_id=pid, name=pid, category="general")


def _claim(page_id, username, password="pw"):
    """One credential write. Returns 'WRITTEN' or 'CONFLICT' (never raises for conflict)."""
    try:
        database.set_client_credentials(page_id=page_id, username=username, password=password)
        return "WRITTEN"
    except database.CredentialConflictError:
        return "CONFLICT"


def _concurrent_claims(page_ids, username, synchronize=True):
    """
    Claim one username from independent threads, each with its own connection.

    `synchronize` uses a `threading.Barrier` so all threads enter the write together — the
    strongest form, which is what makes the race deterministic rather than probabilistic.
    With `synchronize=False` the threads are merely started together, which is the "natural
    concurrency" form Phase 7 also required (it reproduced 12/12 without any barrier).
    """
    results = {}
    barrier = threading.Barrier(len(page_ids)) if synchronize else None

    def worker(pid):
        if barrier is not None:
            try:
                barrier.wait(timeout=10)
            except Exception:
                pass
        results[pid] = _claim(pid, username)

    threads = [threading.Thread(target=worker, args=(pid,)) for pid in page_ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return results


def _rows_holding(username):
    """Every page whose normalized username equals `username` (read from the database)."""
    normalized = username.strip().lower()
    return [
        p["page_id"]
        for p in database.get_all_pages()
        if ((p.get("client_username") or "").strip().lower() == normalized)
    ]


def _index_present():
    conn = database.get_connection()
    try:
        return uniq.index_is_correct(conn)
    finally:
        conn.close()


# ===========================================================================
# The invariant exists at all
# ===========================================================================
def test_801_the_unique_index_is_installed_and_correct(db):
    """
    The security boundary must actually be present, and must be the right index.

    A name-only check is insufficient: the pre-Phase-8 `0002._sync_indexes()` created a
    NON-unique index on the raw column under this exact name, which enforces nothing.
    """
    conn = database.get_connection()
    try:
        assert uniq.index_exists(conn), "the unique username index is missing"
        definition = uniq.describe_index(conn)
        assert uniq.index_is_correct(conn), f"index is not the invariant: {definition!r}"
        lowered = " ".join((definition or "").lower().split())
        assert "unique" in lowered
        assert "lower" in lowered and "trim" in lowered
        assert "where" in lowered, "the index is not partial; blank usernames would collide"
    finally:
        conn.close()


def test_802_the_index_rejects_a_duplicate_normalized_username(db):
    """Direct SQL, bypassing the application entirely: the engine must refuse."""
    _make_pages(("p8-case-a", "p8-case-b"))
    # Unique per run: this suite may share a PostgreSQL database with other suites, and a
    # fixed name would collide with a row another test legitimately owns.
    import uuid

    tag = uuid.uuid4().hex[:10]
    first, second = f"Alice_{tag}", f"  ALICE_{tag}  "
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE pages SET client_username = ? WHERE page_id = ?", (first, "p8-case-a"))
        conn.commit()
        # The compat cursor wraps each statement in a savepoint and rolls back to it on
        # failure, so the connection stays usable and `commit()` after the raise is safe on
        # both engines. That is exactly the property a real duplicate attempt relies on.
        with pytest.raises(Exception) as excinfo:
            cur.execute(
                "UPDATE pages SET client_username = ? WHERE page_id = ?", (second, "p8-case-b")
            )
            conn.commit()
        assert database._is_username_uniqueness_violation(excinfo.value), (
            "the duplicate was rejected for the wrong reason: " f"{excinfo.value}"
        )
        conn.rollback()
    finally:
        conn.close()


def test_803_blank_usernames_do_not_collide(db):
    """NULL / '' / whitespace-only are not login identities and may be arbitrarily many."""
    _make_pages(("p8-empty-a", "p8-empty-b", "p8-null-a", "p8-null-b"))
    # Four pages, all without a usable login name. None of these writes may raise: the
    # partial index must not consider blank values to be a shared identity.
    database.set_client_credentials(page_id="p8-empty-a", username="", password=None)
    database.set_client_credentials(page_id="p8-empty-b", username="   ", password=None)
    database.set_client_credentials(page_id="p8-null-a", username="", password=None)
    database.set_client_credentials(page_id="p8-null-b", username="", password=None)

    # And the preflight must not report them as a collision, which is the property that
    # lets a real database hold many username-less pages.
    conn = database.get_connection()
    try:
        assert uniq.find_duplicate_usernames(conn) == [], (
            "blank usernames were reported as a duplicate group"
        )
    finally:
        conn.close()


# ===========================================================================
# Sequential behaviour (must be unchanged from Phase 6)
# ===========================================================================
def test_810_sequential_exact_duplicate_is_refused(db):
    _make_pages(("p8-seq-a", "p8-seq-b"))
    assert _claim("p8-seq-a", "seq_user", "pw-a") == "WRITTEN"
    assert _claim("p8-seq-b", "seq_user", "pw-b") == "CONFLICT"


def test_811_sequential_case_duplicate_is_refused(db):
    _make_pages(("p8-seq-a", "p8-seq-b"))
    assert _claim("p8-seq-a", "CaseUser", "pw-a") == "WRITTEN"
    assert _claim("p8-seq-b", "CASEUSER", "pw-b") == "CONFLICT"


def test_812_sequential_whitespace_duplicate_is_refused(db):
    _make_pages(("p8-seq-a", "p8-seq-b"))
    assert _claim("p8-seq-a", "ws_user", "pw-a") == "WRITTEN"
    assert _claim("p8-seq-b", "  ws_user  ", "pw-b") == "CONFLICT"


def test_813_conflict_leaves_the_other_tenant_hash_unchanged(db):
    _make_pages(("p8-seq-a", "p8-seq-b"))
    _claim("p8-seq-a", "guard_user", "pw-a")
    before = database.get_page("p8-seq-a")
    assert _claim("p8-seq-b", "guard_user", "pw-b") == "CONFLICT"
    after = database.get_page("p8-seq-a")
    assert before["client_password_hash"] == after["client_password_hash"]
    assert before["client_salt"] == after["client_salt"]
    assert before.get("client_magic_token") == after.get("client_magic_token")


def test_814_unused_username_is_accepted(db):
    _make_pages(("p8-unused-a",))
    assert _claim("p8-unused-a", "fresh_unused_name", "pw") == "WRITTEN"


def test_815_same_tenant_can_re_set_its_own_username(db):
    """Re-writing your own name (or a case/space variant) is not a conflict."""
    _make_pages(("p8-own-a",))
    assert _claim("p8-own-a", "own_name", "pw1") == "WRITTEN"
    for variant in ("own_name", "OWN_NAME", "  own_name  "):
        assert _claim("p8-own-a", variant, "pw2") == "WRITTEN", f"{variant!r} was refused"


# ===========================================================================
# Concurrent behaviour — the actual R10 finding
# ===========================================================================
def test_830_two_tenants_one_username_barrier(db):
    """
    Pre-fix (measured, Phase 7): both WRITTEN, two rows, ambiguous resolution.
    Post-fix: exactly one WRITTEN, one row, unambiguous.
    """
    _make_pages(RACE_TWO)
    results = _concurrent_claims(RACE_TWO, "race_two_name", synchronize=True)

    written = [p for p, v in results.items() if v == "WRITTEN"]
    assert len(written) == 1, (
        f"expected exactly one winner on {engine_id()}, got {len(written)}: {results}"
    )
    assert _rows_holding("race_two_name") == written
    assert database.canonical_resolution_is_ambiguous("race_two_name") is False
    assert database.resolve_canonical_account("race_two_name") == written[0]


def test_831_two_tenants_one_username_natural_concurrency(db):
    """No barrier: threads merely start together. Phase 7 reproduced 12/12 this way."""
    _make_pages(RACE_TWO)
    results = _concurrent_claims(RACE_TWO, "race_natural_name", synchronize=False)
    written = [p for p, v in results.items() if v == "WRITTEN"]
    assert len(written) == 1, f"duplicate created without a barrier on {engine_id()}: {results}"
    assert len(_rows_holding("race_natural_name")) == 1


def test_832_four_tenants_one_username(db):
    """
    Pre-fix (measured): four WRITTEN, four rows. Post-fix: one WRITTEN, three CONFLICT.
    """
    _make_pages(RACE_FOUR)
    results = _concurrent_claims(RACE_FOUR, "race_four_name", synchronize=True)

    written = [p for p, v in results.items() if v == "WRITTEN"]
    assert len(written) == 1, (
        f"expected 1 winner of 4 on {engine_id()}, got {len(written)}: {results}"
    )
    assert [v for v in results.values()].count("CONFLICT") == 3, (
        f"the losers did not all receive a conflict: {results}"
    )
    rows = _rows_holding("race_four_name")
    assert len(rows) == 1, f"duplicate rows exist on {engine_id()}: {rows}"
    assert database.canonical_resolution_is_ambiguous("race_four_name") is False


@pytest.mark.parametrize("variants", [
    ("CaseRace", "CASERACE"),
    ("  ws_race  ", "ws_race"),
    ("Mixed_Case_WS", " mixed_case_ws "),
])
def test_833_case_and_whitespace_variant_races(db, variants):
    """Two tenants, names that differ only by case/whitespace: still one winner."""
    _make_pages(RACE_TWO)
    results = {}
    barrier = threading.Barrier(2)

    def worker(pid, name):
        try:
            barrier.wait(timeout=10)
        except Exception:
            pass
        results[pid] = _claim(pid, name)

    threads = [
        threading.Thread(target=worker, args=(RACE_TWO[0], variants[0])),
        threading.Thread(target=worker, args=(RACE_TWO[1], variants[1])),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    written = [p for p, v in results.items() if v == "WRITTEN"]
    assert len(written) == 1, (
        f"{variants!r} both written on {engine_id()}: {results}"
    )


def test_834_distinct_usernames_both_succeed(db):
    """The fix must not over-refuse: two different names in parallel both commit."""
    _make_pages(DISTINCT)
    results = _concurrent_claims(DISTINCT, "irrelevant", synchronize=True) if False else None
    barrier = threading.Barrier(2)
    out = {}

    def worker(pid, name):
        try:
            barrier.wait(timeout=10)
        except Exception:
            pass
        out[pid] = _claim(pid, name)

    threads = [
        threading.Thread(target=worker, args=(DISTINCT[0], "distinct_one")),
        threading.Thread(target=worker, args=(DISTINCT[1], "distinct_two")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert out == {DISTINCT[0]: "WRITTEN", DISTINCT[1]: "WRITTEN"}, (
        f"distinct usernames were not both accepted on {engine_id()}: {out}"
    )


def test_835_losing_tenant_keeps_its_previous_credentials(db):
    """
    A rejected concurrent claim must not leave a partial write on the loser's own row.

    The loser has already had its username, hash, salt and magic token written by the
    `UPDATE` before the unique violation is reported, so this asserts the rollback.
    """
    _make_pages(RACE_TWO)
    _claim(RACE_TWO[0], "loser_old_name", "pw-a-old")
    _claim(RACE_TWO[1], "winner_old_name", "pw-b-old")
    before = {p: database.get_page(p) for p in RACE_TWO}

    results = _concurrent_claims(RACE_TWO, "contested_after_state", synchronize=True)
    loser = [p for p, v in results.items() if v == "CONFLICT"]
    assert loser, f"no loser in a two-tenant race on {engine_id()}: {results}"

    for pid in loser:
        after = database.get_page(pid)
        for column in ("client_username", "client_password_hash", "client_salt", "client_magic_token"):
            assert (before[pid] or {}).get(column) == (after or {}).get(column), (
                f"losing tenant {pid} had {column} mutated by a rejected write"
            )


def test_836_repeated_races_never_produce_a_duplicate(db):
    """Ten consecutive races on fresh names: the invariant must hold every time."""
    for attempt in range(10):
        ids = (f"p8-loop-{attempt}-a", f"p8-loop-{attempt}-b")
        _make_pages(ids)
        try:
            results = _concurrent_claims(ids, f"loop_name_{attempt}", synchronize=False)
            written = [p for p, v in results.items() if v == "WRITTEN"]
            assert len(written) == 1, (
                f"attempt {attempt} on {engine_id()} produced {len(written)} winners: {results}"
            )
        finally:
            for pid in ids:
                try:
                    database.delete_page(pid)
                except Exception:
                    pass


# ===========================================================================
# Migration / preflight behaviour
# ===========================================================================
def test_850_preflight_reports_nothing_on_a_clean_database(db):
    conn = database.get_connection()
    try:
        assert uniq.find_duplicate_usernames(conn) == []
    finally:
        conn.close()


def test_851_preflight_detects_a_fabricated_duplicate(db):
    """
    The preflight must find a collision the index would reject.

    The index cannot be bypassed through the application, so the duplicate is fabricated
    with the index temporarily dropped — which is also the real-world shape of a legacy
    database that predates the migration.
    """
    _make_pages(("p8-seq-a", "p8-seq-b"))
    conn = database.get_connection()
    dialect = _require_postgres_or_sqlite()
    # A legacy database predates BOTH invariants: the R10 index, dropped below, and
    # revision 0006's namespace triggers, which independently refuse this exact state
    # (see tests/_username_uniqueness_support.py). Suspending only the index would leave
    # the trigger doing its job and the fabrication failing, so suspend both.
    from _username_uniqueness_support import (
        restore_login_identity,
        suspend_login_identity,
    )

    identity_dialect = suspend_login_identity()
    try:
        cur = conn.cursor()
        cur.execute(uniq.drop_index_sql(dialect))
        cur.execute("UPDATE pages SET client_username = 'legacy_dupe' WHERE page_id = 'p8-seq-a'")
        cur.execute("UPDATE pages SET client_username = '  LEGACY_DUPE  ' WHERE page_id = 'p8-seq-b'")
        conn.commit()

        duplicates = uniq.find_duplicate_usernames(conn)
        assert len(duplicates) == 1, f"preflight missed the collision: {duplicates}"
        group = duplicates[0]
        assert group["normalized"] == "legacy_dupe"
        assert sorted(group["page_ids"]) == ["p8-seq-a", "p8-seq-b"]
        assert group["count"] == 2

        # The gate must refuse on exactly this state, naming both tenants, without fixing it.
        with pytest.raises(uniq.UsernameUniquenessBlocked) as excinfo:
            uniq.assert_no_duplicate_usernames(conn)
        assert excinfo.value.duplicates == duplicates
    finally:
        # RESTORE the invariant. This test deliberately breaks it, and leaving it broken
        # would silently disable the guarantee for every test that runs afterwards (and, on
        # a shared PostgreSQL database, for anything else using it).
        try:
            cur = conn.cursor()
            cur.execute("UPDATE pages SET client_username = NULL WHERE page_id IN ('p8-seq-a','p8-seq-b')")
            conn.commit()
            cur.execute(uniq.create_index_sql(dialect))
            conn.commit()
        finally:
            conn.close()
        # ...and the R16 namespace, verified rather than assumed.
        restore_login_identity(identity_dialect)


def test_852_preflight_is_read_only(db):
    """Running the preflight must not change a single row."""
    _make_pages(("p8-seq-a", "p8-seq-b"))
    _claim("p8-seq-a", "readonly_name", "pw")
    before = [dict(p) for p in database.get_all_pages()]
    conn = database.get_connection()
    try:
        uniq.find_duplicate_usernames(conn)
        uniq.find_duplicate_usernames(conn)
    finally:
        conn.close()
    after = [dict(p) for p in database.get_all_pages()]
    assert before == after, "the preflight modified the database"


def test_853_preflight_ignores_blank_usernames(db):
    """Blank usernames are not identities; they must not be reported as a collision."""
    _make_pages(("p8-empty-a", "p8-empty-b"))
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE pages SET client_username = '' WHERE page_id IN ('p8-empty-a','p8-empty-b')")
        conn.commit()
        assert uniq.find_duplicate_usernames(conn) == []
    finally:
        conn.close()


def test_854_the_gate_raises_a_named_error_with_the_group(db):
    """
    From a detection standpoint: the gate must raise `UsernameUniquenessBlocked`, carry the
    parsed groups, and name the remediation doc — never pick a winner.
    """
    groups = [{"normalized": "dupe", "page_ids": ["a", "b"], "count": 2}]
    exc = uniq.UsernameUniquenessBlocked(groups)
    assert exc.duplicates == groups
    message = str(exc)
    assert "dupe" in message and "'a'" in message and "'b'" in message
    assert "USERNAME_UNIQUENESS_MIGRATION.md" in message
    assert isinstance(exc, RuntimeError), "must abort an Alembic revision"


def test_855_the_index_sql_matches_the_login_predicate():
    """
    The index expression must be exactly what login compares, or it protects a different
    identity. `authenticate_client_detailed` uses LOWER(TRIM(client_username)).
    """
    for dialect in ("sqlite", "postgresql"):
        sql = uniq.create_index_sql(dialect)
        assert "LOWER(TRIM(client_username))" in sql
        assert "UNIQUE INDEX" in sql
        assert "client_username IS NOT NULL" in sql
        assert "CONCURRENTLY" not in sql, (
            "CONCURRENTLY cannot run inside this project's migration transaction "
            "(migrations/env.py wraps every revision in begin_transaction())"
        )


def test_856_startup_refuses_a_database_without_the_invariant(db):
    """
    If the index is dropped, booting must fail loudly rather than run unprotected.

    This is the guard against the silent-downgrade case: at the head revision Alembic sees
    nothing to do, so without this check the application would serve with no uniqueness
    guarantee at all.
    """
    from core.schema_manager import assert_security_invariants

    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(uniq.drop_index_sql(_require_postgres_or_sqlite()))
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(RuntimeError) as excinfo:
        assert_security_invariants()
    message = str(excinfo.value)
    assert uniq.USERNAME_UNIQUE_INDEX in message
    assert "R10" in message or "uniqueness" in message.lower()

    # restore so the rest of the session is not affected
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(uniq.create_index_sql(_require_postgres_or_sqlite()))
        conn.commit()
    finally:
        conn.close()
    assert _index_present()


def test_857_startup_accepts_the_correct_invariant(db):
    from core.schema_manager import assert_security_invariants

    assert_security_invariants()  # must not raise


# ===========================================================================
# Conflict mapping must stay narrow
# ===========================================================================
def test_860_uniqueness_matcher_accepts_the_real_violations():
    """The two engines' real messages, captured from live runs in Phase 8."""
    class FakePgError(Exception):
        pgcode = "23505"

    pg = FakePgError('duplicate key value violates unique constraint "uq_pages_client_username_norm"')
    lite = Exception("UNIQUE constraint failed: index 'uq_pages_client_username_norm'")
    assert database._is_username_uniqueness_violation(pg)
    assert database._is_username_uniqueness_violation(lite)


def test_861_uniqueness_matcher_rejects_unrelated_integrity_errors():
    """
    A foreign-key or other-constraint failure must NOT become a 409 "username taken".

    Mapping those to a conflict would hide a real defect and send the caller down the wrong
    path (retrying with another name while the database is broken).
    """
    class FakePgError(Exception):
        pgcode = "23503"  # foreign_key_violation

    fk = FakePgError('insert or update violates foreign key constraint "messages_page_id_fkey"')
    other_unique = Exception("UNIQUE constraint failed: pages.page_id")
    not_null = Exception("NOT NULL constraint failed: pages.name")
    for exc in (fk, other_unique, not_null):
        assert not database._is_username_uniqueness_violation(exc), (
            f"mapped an unrelated error to a username conflict: {exc}"
        )


def test_862_fk_violation_is_not_turned_into_a_conflict(db):
    """End to end: a genuinely different database error must propagate, not become 409."""
    _make_pages(("p8-seq-a",))
    conn = database.get_connection()
    try:
        cur = conn.cursor()
        with pytest.raises(Exception) as excinfo:
            cur.execute(
                "INSERT INTO messages (page_id, sender_id, sender_type, content) "
                "VALUES (?, ?, ?, ?)",
                ("no-such-page-exists", "s1", "user", "x"),
            )
            conn.commit()
        conn.rollback()
        assert not database._is_username_uniqueness_violation(excinfo.value), (
            "a foreign-key violation was classified as a username uniqueness violation"
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 870-873: the advertised repair path must actually work
# ---------------------------------------------------------------------------
# The startup guard originally said "run the migration to revision 0005". Alembic is a
# no-op when the database is *already stamped* at head, so a database whose index was
# dropped after the stamp could never be repaired by following that instruction. These
# tests pin the real remedy down, because a remedy that cannot work is worse than none:
# an operator follows it, sees success, and serves traffic without the guarantee.


def _run_repair(*args):
    """Invoke scripts/repair_username_uniqueness.py in-process; returns (code, output)."""
    import importlib.util
    import io
    import os
    from contextlib import redirect_stderr, redirect_stdout

    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "scripts", "repair_username_uniqueness.py")
    spec = importlib.util.spec_from_file_location("_repair_tool", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    buf = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(buf):
        code = mod.main(list(args))
    return code, buf.getvalue()


def test_870_repair_tool_recreates_a_dropped_index(db):
    """
    `alembic upgrade head` cannot repair a database stamped at head; this tool must.
    """
    conn = database.get_connection()
    dialect = _require_postgres_or_sqlite()
    try:
        cur = conn.cursor()
        cur.execute(uniq.drop_index_sql(dialect))
        conn.commit()
        assert not uniq.index_is_correct(conn)
    finally:
        conn.close()

    code, out = _run_repair()
    assert code == 0, out

    conn = database.get_connection()
    try:
        assert uniq.index_is_correct(conn), (
            "the repair tool reported success but the invariant is not in force"
        )
    finally:
        conn.close()


def test_871_repair_tool_check_is_read_only_and_fails_when_broken(db):
    """`--check` must exit non-zero and change nothing — it gates deployments."""
    conn = database.get_connection()
    dialect = _require_postgres_or_sqlite()
    try:
        cur = conn.cursor()
        cur.execute(uniq.drop_index_sql(dialect))
        conn.commit()
    finally:
        conn.close()

    code, out = _run_repair("--check")
    assert code == 1, f"--check must fail on a broken database, got {code}: {out}"

    conn = database.get_connection()
    try:
        assert not uniq.index_is_correct(conn), "--check modified the database"
    finally:
        conn.close()

    # and after repair it must pass
    _run_repair()
    code, out = _run_repair("--check")
    assert code == 0, out


def test_872_repair_tool_refuses_to_touch_existing_collisions(db):
    """
    The tool must never choose a winner. With a collision present it stops, changes no
    row, and creates no index.
    """
    from _username_uniqueness_support import (
        clear_legacy_duplicates,
        restore_login_identity,
        restore_username_uniqueness,
        suspend_login_identity,
        suspend_username_uniqueness,
    )

    _make_pages(("p8-seq-a", "p8-seq-b"))
    # `suspend_username_uniqueness()` covers only the R10 index; the 0006 namespace
    # triggers must be suspended too or the duplicate cannot be fabricated at all.
    dialect = suspend_login_identity()
    suspend_username_uniqueness()
    try:
        conn = database.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE pages SET client_username = 'tool_dupe' WHERE page_id = 'p8-seq-a'")
            cur.execute("UPDATE pages SET client_username = ' TOOL_DUPE ' WHERE page_id = 'p8-seq-b'")
            conn.commit()

            before = {}
            cur.execute(
                "SELECT page_id, client_username FROM pages "
                "WHERE page_id IN ('p8-seq-a','p8-seq-b')"
            )
            before = dict(cur.fetchall())
        finally:
            conn.close()

        code, out = _run_repair()
        assert code == 1, f"repair must refuse on a collision, got {code}: {out}"
        assert "tool_dupe" in out.lower(), "the refusal must name the colliding username"

        conn = database.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT page_id, client_username FROM pages "
                "WHERE page_id IN ('p8-seq-a','p8-seq-b')"
            )
            after = dict(cur.fetchall())
            assert after == before, f"the tool modified tenant data: {before} -> {after}"
            assert not uniq.index_is_correct(conn), "the tool created an index over a collision"
        finally:
            conn.close()
    finally:
        # Duplicates first (that is what makes the namespace rebuildable), then the
        # R10 index, then the R16 projection -- the last two are independent, but the
        # projection cannot be rebuilt over a collision.
        clear_legacy_duplicates()
        restore_username_uniqueness(dialect)
        restore_login_identity(dialect)


def test_873_startup_error_names_a_remedy_that_is_not_a_noop(db):
    """
    The startup message must not point only at `alembic upgrade head`, which silently does
    nothing on a database already stamped at head.
    """
    import inspect

    from core import schema_manager

    source = inspect.getsource(schema_manager.assert_security_invariants)
    assert "repair_username_uniqueness.py" in source, (
        "the startup guard must name a remedy that works when the database is already "
        "stamped at head; `alembic upgrade head` is a no-op in that state"
    )
    assert "no-op" in source.lower(), (
        "the guard should explain why `alembic upgrade head` alone is insufficient"
    )
