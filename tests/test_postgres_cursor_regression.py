"""
Focused regression tests for PostgresCompatCursor / PostgresCompatConnection.
Covers all 10 PostgreSQL cursor semantics scenarios:
1. SELECT followed by fetchone()
2. SELECT followed by fetchall()
3. SELECT with parameters
4. INSERT ... RETURNING
5. DDL statement with no result set
6. UPDATE statement with no result set
7. Failed statement followed by valid SELECT
8. Unique constraint failure and rollback
9. Multiple sequential SELECT statements
10. Connection reuse after statement failure
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core import db_engine


def _run_cursor_suite(conn, is_pg: bool) -> None:
    tbl = f"pg_cursor_reg_{uuid.uuid4().hex[:8]}"
    cur = conn.cursor()

    try:
        # 5. DDL statement with no result set
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {tbl} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                val INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        assert cur.fetchone() is None
        assert cur.fetchall() == []

        # 4. INSERT ... RETURNING (both explicit RETURNING and _SERIAL_ID_TABLES/lastrowid)
        if is_pg:
            # Drop and recreate with SERIAL for real PG RETURNING id test
            cur.execute(f"DROP TABLE IF EXISTS {tbl}")
            cur.execute(
                f"""
                CREATE TABLE {tbl} (
                    id SERIAL PRIMARY KEY,
                    code TEXT UNIQUE NOT NULL,
                    val INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            cur.execute(
                f"INSERT INTO {tbl} (code, val) VALUES (?, ?) RETURNING id, code",
                ("ALPHA", 10),
            )
            ret = cur.fetchone()
            assert ret is not None
            assert ret["id"] >= 1
            assert ret["code"] == "ALPHA"
        else:
            cur.execute(f"INSERT INTO {tbl} (code, val) VALUES (?, ?)", ("ALPHA", 10))
            assert cur.lastrowid >= 1

        cur.execute(f"INSERT INTO {tbl} (code, val) VALUES (?, ?)", ("BETA", 20))
        assert cur.fetchone() is None
        assert cur.fetchall() == []

        # 1. SELECT followed by fetchone()
        cur.execute(f"SELECT id, code, val FROM {tbl} WHERE code = 'ALPHA'")
        row1 = cur.fetchone()
        assert row1 is not None
        assert row1["code"] == "ALPHA"
        assert row1["val"] == 10

        # 2. SELECT followed by fetchall()
        cur.execute(f"SELECT id, code, val FROM {tbl} ORDER BY id ASC")
        rows = cur.fetchall()
        assert len(rows) == 2
        assert [r["code"] for r in rows] == ["ALPHA", "BETA"]

        # 3. SELECT with parameters
        cur.execute(f"SELECT code, val FROM {tbl} WHERE val >= ? AND code = ?", (15, "BETA"))
        row_p = cur.fetchone()
        assert row_p is not None
        assert row_p["code"] == "BETA"
        assert row_p["val"] == 20

        # 6. UPDATE statement with no result set
        cur.execute(f"UPDATE {tbl} SET val = ? WHERE code = ?", (99, "ALPHA"))
        assert cur.rowcount == 1
        assert cur.fetchone() is None
        assert cur.fetchall() == []

        # 7. Failed statement followed by valid SELECT
        failed = False
        try:
            cur.execute(f"SELECT * FROM nonexistent_table_{uuid.uuid4().hex[:8]}")
        except Exception:
            failed = True
        assert failed is True

        cur.execute(f"SELECT val FROM {tbl} WHERE code = ?", ("ALPHA",))
        after_fail = cur.fetchone()
        assert after_fail is not None
        assert after_fail["val"] == 99

        # 8. Unique constraint failure and rollback
        dup_failed = False
        try:
            cur.execute(f"INSERT INTO {tbl} (code, val) VALUES (?, ?)", ("ALPHA", 777))
        except Exception:
            dup_failed = True
        assert dup_failed is True

        cur.execute(f"SELECT COUNT(*) AS cnt FROM {tbl}")
        cnt_row = cur.fetchone()
        assert cnt_row is not None
        assert cnt_row["cnt"] == 2

        # 9. Multiple sequential SELECT statements
        cur.execute(f"SELECT code FROM {tbl} WHERE code = ?", ("ALPHA",))
        r_a = cur.fetchone()
        cur.execute(f"SELECT code FROM {tbl} WHERE code = ?", ("BETA",))
        r_b = cur.fetchone()
        cur.execute(f"SELECT code FROM {tbl} ORDER BY code ASC")
        r_all = cur.fetchall()
        assert r_a["code"] == "ALPHA"
        assert r_b["code"] == "BETA"
        assert [r["code"] for r in r_all] == ["ALPHA", "BETA"]

        conn.commit()
    finally:
        try:
            cur.execute(f"DROP TABLE IF EXISTS {tbl}")
            conn.commit()
        except Exception:
            conn.rollback()
        cur.close()


def test_postgres_cursor_semantics():
    is_pg = db_engine.is_postgres()
    conn = db_engine.get_db_connection()
    try:
        _run_cursor_suite(conn, is_pg=is_pg)
    finally:
        conn.close()

    # 10. Connection reuse after statement failure
    conn2 = db_engine.get_db_connection()
    try:
        cur2 = conn2.cursor()
        raised = False
        try:
            cur2.execute("SELECT * FROM definitely_missing_table_xyz")
        except Exception:
            raised = True
        assert raised is True

        cur2.execute("SELECT 42 AS answer")
        ans = cur2.fetchone()
        assert ans is not None
        assert ans["answer"] == 42
        cur2.close()
        conn2.commit()
    finally:
        conn2.close()


def test_control_cursor_preserves_result_set_in_compat_layer():
    """
    Deterministic unit test verifying that PostgresCompatCursor uses a separate
    control cursor for SAVEPOINT/RELEASE SAVEPOINT so RELEASE SAVEPOINT never
    clobbers the statement cursor's result set.
    """
    class _SimRawCursor:
        def __init__(self, conn_obj):
            self.connection = conn_obj
            self.description = None
            self.rowcount = -1
            self._rows = []
            self.closed = False

        def execute(self, sql, params=()):
            self.connection.history.append((id(self), sql.strip().split()[0].upper()))
            up = sql.strip().upper()
            if up.startswith(("SAVEPOINT", "RELEASE", "ROLLBACK")):
                # Simulate psycopg2 clearing description/rows on control statements
                self.description = None
                self._rows = []
                self.rowcount = -1
            elif up.startswith("SELECT"):
                self.description = [("id",), ("name",)]
                self._rows = [(1, "Gerege")]
                self.rowcount = 1
            else:
                self.description = None
                self._rows = []
                self.rowcount = 1

        def fetchone(self):
            return self._rows.pop(0) if self._rows else None

        def fetchall(self):
            out = list(self._rows)
            self._rows = []
            return out

        def close(self):
            self.closed = True

    class _SimRawConn:
        def __init__(self):
            self.history = []
            self.cursors = []

        def cursor(self):
            c = _SimRawCursor(self)
            self.cursors.append(c)
            return c

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    sim_conn = _SimRawConn()
    compat_conn = db_engine.PostgresCompatConnection(sim_conn)
    cur = compat_conn.cursor()
    cur.execute("SELECT id, name FROM pages WHERE page_id = ?", ("p1",))
    row = cur.fetchone()
    assert row is not None
    assert row["id"] == 1
    assert row["name"] == "Gerege"
    # Verify control cursors were closed and distinct from statement cursor
    ctrl_cursors = [c for c in sim_conn.cursors if c is not cur._cur]
    assert len(ctrl_cursors) == 2
    assert all(c.closed for c in ctrl_cursors)


if __name__ == "__main__":
    test_control_cursor_preserves_result_set_in_compat_layer()
    test_postgres_cursor_semantics()
    print("[PASS] PostgreSQL cursor regression suite (all 10 scenarios + control cursor isolation)")
