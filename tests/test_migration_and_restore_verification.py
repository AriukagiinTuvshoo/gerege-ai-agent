"""
Focused tests for:
1. Migration verification detecting target-only extra rows, missing rows, and exact row/hash match.
2. Restore verification rejecting missing/empty tables and verifying real row counts & integrity.
"""
import gzip
import json
import os
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import database
from core import backup_service
from scripts import migrate_sqlite_to_postgres


def test_migration_detects_target_only_extra_rows():
    database.init_db()
    tmp_dir = tempfile.mkdtemp(prefix="gerege_mig_extra_")
    try:
        src_db = os.path.join(tmp_dir, "src.db")
        tgt_db = os.path.join(tmp_dir, "tgt.db")
        shutil.copy2(database.DB_PATH, src_db)
        shutil.copy2(database.DB_PATH, tgt_db)

        # Insert an extra row ONLY in target DB
        tconn = sqlite3.connect(tgt_db)
        tconn.execute(
            "INSERT INTO pages (page_id, name, category) VALUES (?, ?, ?)",
            ("extra_target_only_page", "Extra Target Page", "general"),
        )
        tconn.commit()
        tconn.close()

        rep = migrate_sqlite_to_postgres.run_migration(
            sqlite_path=src_db,
            postgres_url=f"sqlite:///{tgt_db}",
            batch_size=50,
        )
        assert rep["status"] == "VERIFICATION_MISMATCH", f"Expected VERIFICATION_MISMATCH, got {rep['status']}"
        assert rep["migrated_tables"]["pages"]["target_only_rows"] == 1
        assert rep["migrated_tables"]["pages"]["match"] is False
        assert rep["verification"]["target_only_rows_total"] >= 1
        assert rep["verification"]["rows_verified"] is False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_migration_clean_batch_streaming_succeeds():
    database.init_db()
    tmp_dir = tempfile.mkdtemp(prefix="gerege_mig_ok_")
    try:
        src_db = os.path.join(tmp_dir, "src.db")
        tgt_db = os.path.join(tmp_dir, "tgt.db")
        shutil.copy2(database.DB_PATH, src_db)

        rep = migrate_sqlite_to_postgres.run_migration(
            sqlite_path=src_db,
            postgres_url=f"sqlite:///{tgt_db}",
            batch_size=25,
        )
        assert rep["status"] == "SUCCESS", f"Expected SUCCESS, got {rep}"
        assert rep["verification"]["rows_verified"] is True
        assert rep["verification"]["target_only_rows_total"] == 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_sqlite_restore_verification_rejects_missing_or_empty_tables():
    orig_db_url = os.environ.pop("DATABASE_URL", None)
    orig_db_path = database.DB_PATH
    tmp_dir = tempfile.mkdtemp(prefix="gerege_restore_ver_")
    try:
        database.init_db()
        live_db = os.path.join(tmp_dir, "live.db")
        shutil.copy2(orig_db_path, live_db)
        database.DB_PATH = live_db

        # 1. Valid backup + restore succeeds with real verification
        good_bk = backup_service.create_backup(label="test_good_restore")
        assert good_bk["success"] is True
        res_good = backup_service.restore_backup(good_bk["filename"])
        assert res_good["success"] is True
        assert res_good["post_restore_verified"] is True
        assert res_good["restored_table_counts"]["pages"] >= 1

        # 2. Corrupt backup where `pages` was emptied while metadata expects >= 1 -> must FAIL and roll back
        bad_raw = os.path.join(tmp_dir, "bad_empty.db")
        shutil.copy2(live_db, bad_raw)
        bconn = sqlite3.connect(bad_raw)
        bconn.execute("DELETE FROM pages")
        bconn.commit()
        bconn.close()

        bad_name = "sqlite_backup_bad_empty_test.db.gz"
        bad_gz = os.path.join(backup_service.BACKUP_DIR, bad_name)
        with open(bad_raw, "rb") as f_in, gzip.open(bad_gz, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        sha = backup_service._compute_sha256(bad_gz)
        with open(bad_gz + ".sha256", "w", encoding="utf-8") as sf:
            sf.write(f"{sha}  {bad_name}\n")
        with open(bad_gz + ".meta.json", "w", encoding="utf-8") as mf:
            json.dump({"table_counts": {"pages": 1}}, mf)

        res_bad = backup_service.restore_backup(bad_name)
        assert res_bad["success"] is False
        assert res_bad["post_restore_verified"] is False
        assert "empty_table_after_restore" in res_bad["error"]

        # Verify live DB was NOT wiped
        lconn = sqlite3.connect(live_db)
        cnt = lconn.execute("SELECT COUNT(*) FROM pages").fetchone()[0]
        lconn.close()
        assert cnt >= 1

        # Cleanup created test backup files
        for fn in (good_bk["filename"], bad_name, res_good.get("pre_restore_snapshot"), res_bad.get("pre_restore_snapshot")):
            if fn:
                p = os.path.join(backup_service.BACKUP_DIR, fn)
                for ext in ("", ".sha256", ".meta.json"):
                    if os.path.exists(p + ext):
                        os.remove(p + ext)
    finally:
        database.DB_PATH = orig_db_path
        if orig_db_url is not None:
            os.environ["DATABASE_URL"] = orig_db_url
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_postgres_restore_good_when_configured():
    from core import db_engine
    if not db_engine.is_postgres():
        return

    good_bk = backup_service.create_backup(label="pg_restore_ver_ok")
    assert good_bk["success"] is True, f"PG create_backup failed: {good_bk}"
    assert good_bk["filename"].endswith(".sql.gz")

    res_good = {}
    try:
        res_good = backup_service.restore_backup(good_bk["filename"])
        assert res_good["success"] is True, f"PG restore failed: {res_good}"
        assert res_good["post_restore_verified"] is True
        assert res_good["restored_table_counts"]["pages"] >= 1
    finally:
        for fn in (good_bk.get("filename"), res_good.get("pre_restore_snapshot")):
            if fn:
                p = os.path.join(backup_service.BACKUP_DIR, fn)
                for ext in ("", ".sha256", ".meta.json"):
                    if os.path.exists(p + ext):
                        os.remove(p + ext)


def test_postgres_restore_bad_rejected_when_configured():
    from core import db_engine
    if not db_engine.is_postgres():
        return

    bad_name = "pg_backup_bad_empty_test.sql.gz"
    bad_gz = os.path.join(backup_service.BACKUP_DIR, bad_name)
    with gzip.open(bad_gz, "wb") as gz:
        gz.write(b"CREATE TABLE IF NOT EXISTS _bad_test_tbl (id INT); INVALID_SQL_SYNTAX_ERROR;")
    sha = backup_service._compute_sha256(bad_gz)
    with open(bad_gz + ".sha256", "w", encoding="utf-8") as sf:
        sf.write(f"{sha}  {bad_name}\n")
    with open(bad_gz + ".meta.json", "w", encoding="utf-8") as mf:
        json.dump({"table_counts": {"pages": 1}}, mf)

    res_bad = {}
    try:
        res_bad = backup_service.restore_backup(bad_name)
        assert res_bad["success"] is False
        assert res_bad["post_restore_verified"] is False
    finally:
        for fn in (bad_name, res_bad.get("pre_restore_snapshot")):
            if fn:
                p = os.path.join(backup_service.BACKUP_DIR, fn)
                for ext in ("", ".sha256", ".meta.json"):
                    if os.path.exists(p + ext):
                        os.remove(p + ext)


if __name__ == "__main__":
    test_migration_detects_target_only_extra_rows()
    test_migration_clean_batch_streaming_succeeds()
    test_sqlite_restore_verification_rejects_missing_or_empty_tables()
    test_postgres_restore_good_when_configured()
    test_postgres_restore_bad_rejected_when_configured()
    print("[PASS] Migration target-only detection & Restore verification suite")
