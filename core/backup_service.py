import os
import gzip
import shutil
import sqlite3
import hashlib
import subprocess
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

import database
from core.db_engine import is_postgres, get_database_url

logger = logging.getLogger("core.backup_service")

BACKUP_DIR = os.getenv("BACKUP_DIR", "backups")


def _compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_backup(label: str = "manual") -> Dict[str, Any]:
    """
    Өгөгдлийн сангийн бүрэн нөөцлөлт (Backup) үүсгэж, gzip шахалт болон SHA-256 checksum хадгалах.
    SQLite үед online backup API (`sqlite3.Connection.backup`), PostgreSQL үед `pg_dump` ашиглана.
    """
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_label = "".join(c for c in label if c.isalnum() or c in ("_", "-")) or "backup"

    if is_postgres():
        filename = f"pg_backup_{safe_label}_{ts}.sql.gz"
        dest_path = os.path.join(BACKUP_DIR, filename)
        pg_url = get_database_url().replace("postgresql+psycopg2://", "postgresql://")
        try:
            proc = subprocess.run(
                ["pg_dump", pg_url],
                capture_output=True,
                check=True,
                timeout=120,
            )
            with gzip.open(dest_path, "wb") as gz:
                gz.write(proc.stdout)
        except Exception as e:
            logger.error(f"PostgreSQL pg_dump failed: {e}")
            return {"success": False, "error": str(e)}
    else:
        filename = f"sqlite_backup_{safe_label}_{ts}.db.gz"
        raw_temp = os.path.join(BACKUP_DIR, f".tmp_{ts}.db")
        dest_path = os.path.join(BACKUP_DIR, filename)
        try:
            src_conn = sqlite3.connect(database.DB_PATH)
            dst_conn = sqlite3.connect(raw_temp)
            with dst_conn:
                src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()

            with open(raw_temp, "rb") as f_in, gzip.open(dest_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        finally:
            if os.path.exists(raw_temp):
                os.remove(raw_temp)

    sha256_hex = _compute_sha256(dest_path)
    with open(dest_path + ".sha256", "w", encoding="utf-8") as sf:
        sf.write(f"{sha256_hex}  {filename}\n")

    size_bytes = os.path.getsize(dest_path)
    return {
        "success": True,
        "filename": filename,
        "path": dest_path,
        "size_bytes": size_bytes,
        "sha256": sha256_hex,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def list_backups() -> List[Dict[str, Any]]:
    """Хадгалагдсан backup файлуудын жагсаалтыг буцаах"""
    if not os.path.exists(BACKUP_DIR):
        return []
    items: List[Dict[str, Any]] = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not (fname.endswith(".db.gz") or fname.endswith(".sql.gz")):
            continue
        fpath = os.path.join(BACKUP_DIR, fname)
        sha_path = fpath + ".sha256"
        sha_val = ""
        if os.path.exists(sha_path):
            try:
                sha_val = open(sha_path, "r", encoding="utf-8").read().split()[0]
            except Exception:
                sha_val = ""
        items.append({
            "filename": fname,
            "size_bytes": os.path.getsize(fpath),
            "sha256": sha_val,
            "modified_at": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return items


def verify_backup(filename: str) -> Dict[str, Any]:
    """Backup файлын SHA-256 бүрэн бүтэн байдал болон SQLite integrity_check шалгах"""
    clean_name = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, clean_name)
    if not os.path.exists(fpath):
        return {"valid": False, "error": "Backup file not found"}

    actual_sha = _compute_sha256(fpath)
    sha_path = fpath + ".sha256"
    if os.path.exists(sha_path):
        expected_sha = open(sha_path, "r", encoding="utf-8").read().split()[0]
        if actual_sha != expected_sha:
            return {"valid": False, "error": "SHA-256 checksum mismatch"}

    if clean_name.endswith(".db.gz"):
        tmp_check = os.path.join(BACKUP_DIR, f".verify_{clean_name}.db")
        try:
            with gzip.open(fpath, "rb") as f_in, open(tmp_check, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            conn = sqlite3.connect(tmp_check)
            cur = conn.cursor()
            cur.execute("PRAGMA integrity_check")
            res = cur.fetchone()
            conn.close()
            if not res or res[0] != "ok":
                return {"valid": False, "error": f"SQLite integrity check failed: {res}"}
        finally:
            if os.path.exists(tmp_check):
                os.remove(tmp_check)

    return {"valid": True, "filename": clean_name, "sha256": actual_sha}


def restore_backup(filename: str) -> Dict[str, Any]:
    """
    Backup файлаас өгөгдлийн санг аюулгүй сэргээх (Recovery):
    1. Эхлээд файлын бүрэн бүтэн байдлыг (verify_backup) шалгана
    2. Одоогийн баазыг `pre_restore` нэрээр автоматаар нөөцөлнө
    3. Баазыг атомик байдлаар сэргээнэ
    """
    check = verify_backup(filename)
    if not check.get("valid"):
        return {"success": False, "error": check.get("error", "Invalid backup")}

    clean_name = os.path.basename(filename)
    fpath = os.path.join(BACKUP_DIR, clean_name)

    # Pre-restore safety snapshot
    pre_snap = create_backup(label="pre_restore")

    if clean_name.endswith(".db.gz"):
        tmp_restore = os.path.join(BACKUP_DIR, f".restore_{clean_name}.db")
        try:
            with gzip.open(fpath, "rb") as f_in, open(tmp_restore, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            src_conn = sqlite3.connect(tmp_restore)
            dst_conn = sqlite3.connect(database.DB_PATH)
            with dst_conn:
                src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()
        finally:
            if os.path.exists(tmp_restore):
                os.remove(tmp_restore)

        return {
            "success": True,
            "restored_from": clean_name,
            "pre_restore_snapshot": pre_snap.get("filename"),
        }

    return {"success": False, "error": "Unsupported backup format for automatic restore"}
