import sqlite3
import csv
import json
import os
import io
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from core.db_engine import get_db_connection, get_sqlite_db_path, verify_schema_drift

logger = logging.getLogger("database")

#: The SQLite file this process writes to, resolved once at import time.
#:
#: Resolution: ``DB_PATH`` environment variable, else the repository default. Doing
#: this at import (instead of inside `get_connection`) is what keeps the module
#: attribute and the connection factory in agreement — callers that read
#: ``database.DB_PATH`` (backup/restore, the SQLite→PostgreSQL migrator, tests) then
#: observe the same file the application actually uses.
_DEFAULT_DB_PATH = get_sqlite_db_path(None)
DB_PATH = _DEFAULT_DB_PATH
CSV_PATH = os.path.join(os.path.dirname(__file__), "leads.csv")
DEFAULT_PAGE_ID = "100799479495809"
DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ADMIN2026")


def resolved_sqlite_path() -> str:
    """The SQLite path the application is using right now.

    Single authority: `database.DB_PATH` is initialised from the environment at
    import, and may be rebound at runtime (tests, tooling). `core.schema_manager`
    consults this function so migrations always target the same file the repositories
    read and write — the split-brain that silently sent `init_db()`'s seed to
    `leads.db` while the app read a configured path.
    """
    return DB_PATH


def get_connection():
    """Нэгдсэн Authoritative Database Connection (PostgreSQL эсвэл SQLite WAL)"""
    return get_db_connection(sqlite_path=resolved_sqlite_path())


def mask_secret(secret: Optional[str], show_start: int = 6, show_end: int = 4) -> str:
    """Нууц токен болон түлхүүрүүдийг UI дээр ил задгай харагдахаас сэргийлж далдлах"""
    if not secret:
        return ""
    s = secret.strip()
    if len(s) <= (show_start + show_end):
        return "********"
    return f"{s[:show_start]}••••••••{s[-show_end:]}"

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """PBKDF2 HMAC-SHA256 криптограф хэш үүсгэх"""
    if not salt:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return pw_hash, salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Нууц үгийг шалгах"""
    if not password or not stored_hash or not salt:
        return False
    calculated = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return hmac_equal(calculated, stored_hash)

def hmac_equal(a: str, b: str) -> bool:
    """Timing attack хамгаалалттай харьцуулалт"""
    return secrets.compare_digest(a, b)


#: Dummy credential for the unknown-account path (E-02 Phase 4).
#:
#: Generated once per process, so no fixed value can be recognised, and it is never stored
#: anywhere — nothing can authenticate against it.
_DUMMY_HASH, _DUMMY_SALT = hash_password(secrets.token_hex(32))


def dummy_password_verify(password: Optional[str]) -> bool:
    """
    Spend the same work as `verify_password` when there is no account to verify against.

    Why this exists: `authenticate_client_detailed` returns as soon as the account lookup
    misses, so an unknown username answered in ~6 ms while a known one took ~38 ms
    (measured, `docs/audit/evidence/e02_phase4_before.txt`). That 6x gap is a practical
    enumeration oracle — it tells an attacker which tenant names are real without ever
    needing a valid password.

    This runs the *same* PBKDF2-HMAC-SHA256 at the same iteration count as a real
    verification, against a throwaway credential, so both paths cost the same. It is a real
    verification rather than a `sleep` on purpose: a sleep has to be tuned to a cost that
    changes with hardware and configuration, while this tracks the real cost automatically.
    """
    verify_password(password or "", _DUMMY_HASH, _DUMMY_SALT)
    return False

def init_db():
    """Bring the database to the current schema, then seed first-run data.

    **The schema is no longer defined here.** `init_db()` used to execute ~350 lines
    of hand-written `CREATE TABLE` DDL plus an `ALTER TABLE ... ADD COLUMN` loop
    wrapped in bare `except: pass`. That was a second, independent schema definition
    next to `migrations/versions/0001_*.py`, and the two disagreed on every timestamp
    (`VARCHAR(64)` vs `TIMESTAMP`) and on ~91 string widths — so the database shape
    depended on how it happened to be created (findings P1-02 / P2-01).

    Now `core/models.py` + Alembic are the only authority:

      * an empty database is created by running the migrations (this function does it),
      * an existing database is upgraded in place, with data preserved,
      * the schema is guaranteed to be at `head` on return, or the call raises.

    Everything below is *data*, not structure: the default tenant row, its magic
    token, and a one-off cleanup of legacy URL-shaped `page_id` values.
    """
    from core.schema_manager import ensure_schema

    report = ensure_schema()
    logger.info(
        "Schema ready: %s (%s -> %s)",
        "upgraded" if report["upgraded"] else "already at head",
        report["from"] or "<empty>",
        report["to"],
    )

    conn = get_connection()
    cursor = conn.cursor()

    # Анхны Tuvshok хуудсыг автоматаар бүртгэж үүсгэх
    cursor.execute("SELECT page_id FROM pages WHERE page_id = ?", (DEFAULT_PAGE_ID,))
    row = cursor.fetchone()
    if not row:
        knowledge_file = os.path.join(os.path.dirname(__file__), "knowledge.json")
        k_json = "{}"
        if os.path.exists(knowledge_file):
            try:
                with open(knowledge_file, "r", encoding="utf-8") as f:
                    k_json = f.read()
            except Exception:
                pass
        
        page_token = os.getenv("META_PAGE_ACCESS_TOKEN", "").strip()
        magic = secrets.token_urlsafe(24)
        cursor.execute("""
            INSERT INTO pages (
                page_id, name, category, page_access_token, verify_token, is_active, 
                knowledge_json, client_username, client_magic_token, monthly_token_limit, tokens_used
            )
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, 200000, 0)
        """, (
            DEFAULT_PAGE_ID,
            "Tuvshok Кино & Драма Суваг",
            "entertainment",
            page_token,
            "agent_verify_secret_token_123",
            k_json,
            "tuvshok",
            magic
        ))
    else:
        # Magic token байхгүй бол нөхөх
        cursor.execute("SELECT client_magic_token FROM pages WHERE page_id = ?", (DEFAULT_PAGE_ID,))
        m_row = cursor.fetchone()
        if not m_row or not m_row[0]:
            cursor.execute("UPDATE pages SET client_magic_token = ? WHERE page_id = ?", (secrets.token_urlsafe(24), DEFAULT_PAGE_ID))

    # URL маягийн буруу page_id-тай (жишээ нь https://...) хуудсуудыг цэвэрлэх
    try:
        cursor.execute("SELECT page_id FROM pages WHERE page_id LIKE '%/%'")
        for (old_id,) in cursor.fetchall():
            new_id = sanitize_page_id(old_id)
            if new_id and new_id != old_id:
                cursor.execute("UPDATE OR IGNORE pages SET page_id = ? WHERE page_id = ?", (new_id, old_id))
                cursor.execute("UPDATE OR IGNORE registrations SET page_id = ? WHERE page_id = ?", (new_id, old_id))
                cursor.execute("UPDATE OR IGNORE messages SET page_id = ? WHERE page_id = ?", (new_id, old_id))
                # E-01: `UPDATE OR IGNORE` silently skips a row when the rewritten
                # (page_id, sender_id) already exists, which would leave that customer's
                # session behind on the old page_id. Report instead of silently dropping.
                cursor.execute("SELECT COUNT(*) FROM session_states WHERE page_id = ?", (old_id,))
                pending = cursor.fetchone()[0]
                cursor.execute("UPDATE OR IGNORE session_states SET page_id = ? WHERE page_id = ?", (new_id, old_id))
                cursor.execute("SELECT COUNT(*) FROM session_states WHERE page_id = ?", (old_id,))
                left = cursor.fetchone()[0]
                if left:
                    logger.warning(
                        f"page_id sanitisation left {left} of {pending} session rows on {old_id!r}: "
                        f"the rewritten identity already exists on {new_id!r}. Review manually."
                    )
    except Exception as e:
        logger.error(f"Migration page_id sanitization error: {e}")

    conn.commit()
    conn.commit()
    conn.close()

# ----------------- AUTHENTICATION & RBAC SESSIONS -----------------
def create_session(role: str, page_id: Optional[str] = None, hours: int = 72, ip_address: Optional[str] = None) -> str:
    """Шинэ нэвтрэлтийн сесс үүсгэх"""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=hours)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sessions (session_token, role, page_id, revoked, ip_address, expires_at)
        VALUES (?, ?, ?, 0, ?, ?)
    """, (token, role, page_id, ip_address, expires_at.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return token

def get_session(token: str) -> Optional[Dict[str, Any]]:
    """Сесс хүчинтэй эсэхийг шалгах (Хугацаа дууссан эсвэл цуцлагдсан бол None буцаана)"""
    if not token:
        return None
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT session_token, role, page_id, revoked, created_at, expires_at
        FROM sessions
        WHERE session_token = ?
          AND COALESCE(revoked, 0) = 0
          AND datetime(expires_at) > datetime('now')
    """, (token,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def revoke_session(token: str) -> bool:
    """Сессийг хүчингүй болгох (Revocation audit trail хадгална)"""
    if not token:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE sessions
        SET revoked = 1, revoked_at = ?
        WHERE session_token = ?
    """, (now_str, token))
    changed = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return changed

def revoke_all_page_sessions(page_id: str) -> int:
    """Тухайн салбарын бүх идэвхтэй сессийг хүчингүй болгох (Нууц үг солих эсвэл салбар устгах үед)"""
    if not page_id:
        return 0
    conn = get_connection()
    cursor = conn.cursor()
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE sessions
        SET revoked = 1, revoked_at = ?
        WHERE page_id = ? AND COALESCE(revoked, 0) = 0
    """, (now_str, str(page_id)))
    count = cursor.rowcount
    conn.commit()
    conn.close()
    return count

def delete_session(token: str):
    """Гарах (Logout — сессийг revoke хийнэ)"""
    revoke_session(token)

def authenticate_admin(password: str) -> bool:
    """Супер Админы нууц үгийг шалгах (Production болон ADMIN_PASSWORD тохируулсан үед анхдагч нууц үгийг бүрэн хаана)"""
    env_pw = os.getenv("ADMIN_PASSWORD", "").strip()
    p = (password or "").strip()
    if not p:
        return False
    if env_pw:
        return secrets.compare_digest(p, env_pw)
    # Production эсвэл STRICT_SECURITY горимд ADMIN_PASSWORD тохируулаагүй бол fail-closed (False) буцаана
    if (
        os.getenv("ENV", "").strip().lower() in ("production", "prod")
        or os.getenv("STRICT_SECURITY", "").strip().lower() in ("1", "true", "yes")
        or os.getenv("DISABLE_DEFAULT_ADMIN_PASSWORD", "").strip().lower() in ("1", "true", "yes")
    ):
        return False
    return secrets.compare_digest(p, DEFAULT_ADMIN_PASSWORD) or secrets.compare_digest(p.lower(), DEFAULT_ADMIN_PASSWORD.lower())


def _lock_already_held_exceptions() -> tuple:
    """
    Exception types raised when the `notification_locks` primary key rejects a duplicate.

    SQLite raises `sqlite3.IntegrityError`; psycopg2 raises `errors.UniqueViolation`
    (which is *not* a subclass of the DB-API `IntegrityError` alias). Both are matched so
    the duplicate path behaves identically on the two dialects. Resolved lazily so
    psycopg2 stays an optional import on SQLite-only deployments.
    """
    types: list[type] = [sqlite3.IntegrityError]
    try:
        from sqlalchemy.exc import IntegrityError as SAIntegrityError

        types.append(SAIntegrityError)
    except Exception:  # pragma: no cover - sqlalchemy is a hard dependency in practice
        pass
    try:
        import psycopg2.errors

        types.append(psycopg2.errors.UniqueViolation)
    except Exception:
        pass
    return tuple(types)


_LOCK_ALREADY_HELD = _lock_already_held_exceptions()


def claim_notification_lock(
    idempotency_key: str,
    channel: str = "any",
    ttl_seconds: Optional[int] = None,
    page_id: Optional[str] = None,
) -> bool:
    """
    Давхар мэдэгдэл болон хуваарьт ажил давхардахаас сэргийлэх атомик түгжээ.
    Хэрэв `ttl_seconds` өгөгдсөн бөгөөд өмнөх түгжээний хугацаа дууссан бол шинэчилж түгжинэ.
    """
    if not idempotency_key:
        return True
    key_clean = idempotency_key.strip()
    now_utc = datetime.utcnow()
    now_str = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    exp_str = (now_utc + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%d %H:%M:%S") if ttl_seconds else None

    conn = get_connection()
    cursor = conn.cursor()
    try:
        if ttl_seconds:
            cursor.execute(
                "DELETE FROM notification_locks WHERE idempotency_key = ? AND expires_at IS NOT NULL AND expires_at < ?",
                (key_clean, now_str),
            )
        cursor.execute(
            "INSERT INTO notification_locks (idempotency_key, channel, expires_at) VALUES (?, ?, ?)",
            (key_clean, channel, exp_str),
        )
        conn.commit()
        return True
    except _LOCK_ALREADY_HELD:
        # The primary key rejected the insert: another caller already holds the lock.
        # This is the *expected* duplicate path, not an error.
        conn.rollback()
        return False
    except Exception as exc:
        # Anything else (connection lost, schema missing, disk full) must not be reported
        # as "already claimed" — that would silently drop a notification the caller
        # believed was handled. Surface it so the caller can decide, and log loudly.
        conn.rollback()
        logger.error(f"claim_notification_lock failed for {key_clean!r}: {exc}")
        raise
    finally:
        conn.close()


def record_audit_log(
    action: str,
    page_id: Optional[str] = None,
    actor_role: Optional[str] = None,
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> int:
    """Аюулгүй байдал, эрхийн өөрчлөлт болон AI Tool дуудлагын аудит лог бичих"""
    conn = get_connection()
    cursor = conn.cursor()
    details_str = json.dumps(details or {}, ensure_ascii=False)
    cursor.execute(
        """
        INSERT INTO audit_logs (page_id, actor_role, actor_id, action, resource_type, resource_id, details_json, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (page_id, actor_role, actor_id, action, resource_type, str(resource_id) if resource_id is not None else None, details_str, ip_address),
    )
    log_id = cursor.lastrowid or 0
    conn.commit()
    conn.close()
    return log_id


def list_audit_logs(page_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if page_id:
        cursor.execute("SELECT * FROM audit_logs WHERE page_id = ? ORDER BY id DESC LIMIT ?", (str(page_id), limit))
    else:
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def delete_customer_data(page_id: str, sender_id: Optional[str] = None, phone: Optional[str] = None) -> Dict[str, int]:
    """Хэрэглэгчийн хувийн мэдээлэл ба санах ойг устгах (Privacy Policy 'Бүртгэл устгах' эрх)"""
    conn = get_connection()
    cursor = conn.cursor()
    deleted = {"registrations": 0, "memories": 0, "messages": 0}
    if sender_id:
        cursor.execute("DELETE FROM user_memories WHERE page_id = ? AND user_id = ?", (str(page_id), str(sender_id)))
        deleted["memories"] += max(0, cursor.rowcount)
        cursor.execute("DELETE FROM registrations WHERE page_id = ? AND sender_id = ?", (str(page_id), str(sender_id)))
        deleted["registrations"] += max(0, cursor.rowcount)
        cursor.execute("DELETE FROM session_states WHERE page_id = ? AND sender_id = ?", (str(page_id), str(sender_id)))
    if phone:
        cursor.execute("DELETE FROM registrations WHERE page_id = ? AND phone = ?", (str(page_id), str(phone)))
        deleted["registrations"] += max(0, cursor.rowcount)
        cursor.execute("DELETE FROM user_memories WHERE page_id = ? AND phone = ?", (str(page_id), str(phone)))
        deleted["memories"] += max(0, cursor.rowcount)
    conn.commit()
    conn.close()
    return deleted


def get_lead_by_id(lead_id: int) -> Optional[Dict[str, Any]]:
    """Бүртгэлийг ID-аар нь авч салбарын харьяаллыг (page_id) шалгах"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM registrations WHERE id = ?", (lead_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_appointment_by_id(appointment_id: int) -> Optional[Dict[str, Any]]:
    """Цаг захиалгыг ID-аар нь авч салбарын харьяаллыг (page_id) шалгах"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments WHERE id = ?", (appointment_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def sanitize_page_id(page_id: str) -> str:
    """URL эсвэл буруу форматаар орж ирсэн хуудасны ID-г найдвартай цэвэрлэх"""
    p = str(page_id or "").strip()
    if "/" in p:
        parts = [s for s in p.rstrip("/").split("/") if s]
        if parts:
            p = parts[-1]
    import re
    cleaned = re.sub(r'[^a-zA-Z0-9_\-]', '_', p).strip('_')
    return cleaned or ("page_" + secrets.token_hex(4))

def authenticate_client_detailed(identifier: str, password: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Харилцагчийн нэвтрэлтийг нарийвчлан шалгаж, тодорхой алдааны тайлбар буцаах"""
    if not identifier:
        return None, "Байгууллагын нэвтрэх нэр эсвэл шууд холбоос оруулна уу."
    ident = identifier.strip()
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. 1-товчлуурт Magic Token-оор шалгах
    cursor.execute("SELECT * FROM pages WHERE client_magic_token = ? AND is_active = 1", (ident,))
    row = cursor.fetchone()
    if row:
        conn.close()
        return dict(row), None

    # 2. Username эсвэл Page ID-аар хайх (Case-insensitive)
    cursor.execute("""
        SELECT * FROM pages 
        WHERE (LOWER(TRIM(client_username)) = LOWER(?) OR LOWER(TRIM(page_id)) = LOWER(?)) 
          AND is_active = 1
    """, (ident, ident))
    row = cursor.fetchone()
    if not row:
        conn.close()
        # E-02 Phase 4: no account means no password to check, which would return in ~6 ms
        # instead of ~38 ms and disclose which tenant names exist. Spend the same work on a
        # throwaway credential first.
        dummy_password_verify(password)
        return None, f"'{ident}' нэртэй харилцагчийн салбар олдсонгүй. Админ самбараас нэрээ шалгана уу."

    p_dict = dict(row)
    stored_hash = p_dict.get("client_password_hash")
    salt = p_dict.get("client_salt")

    if not stored_hash or not salt:
        conn.close()
        # Same equalisation: this branch is only reachable for a REAL account, so without it
        # "exists but unconfigured" would answer faster than "exists with a password".
        dummy_password_verify(password)
        return None, f"'{p_dict.get('name')}' салбарт одоогоор нууц үг хадгалаагүй байна. Админ самбарын 'Хандалт' цонхноос шинэ нууц үг хадгалж өгөх эсвэл Magic Link-ээр орно уу."

    if not password or not password.strip():
        conn.close()
        # verify_password() also returns early on an empty password, so equalise here too.
        dummy_password_verify(password)
        return None, "Нууц үгээ оруулна уу."

    if verify_password(password.strip(), stored_hash, salt):
        conn.close()
        return p_dict, None
    else:
        conn.close()
        return None, "Нууц үг буруу байна! Нүдний дүрс 👁️ дээр даран нууц үгээ шалгана уу."

def authenticate_client(identifier: str, password: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Харилцагчийн нэвтрэлтийг шалгах"""
    client, _ = authenticate_client_detailed(identifier, password)
    return client

def set_client_credentials(page_id: str, username: str, password: Optional[str] = None) -> Dict[str, str]:
    """Харилцагчийн нэвтрэх нэр, нууц үг, шууд орох Magic холбоос шинэчлэх"""
    conn = get_connection()
    cursor = conn.cursor()
    
    magic_token = secrets.token_urlsafe(24)
    u_clean = username.strip()
    p_clean = page_id.strip()
    clean_pid = sanitize_page_id(p_clean)
    
    if password:
        pw_hash, salt = hash_password(password.strip())
        cursor.execute("""
            UPDATE pages 
            SET client_username = ?, client_password_hash = ?, client_salt = ?, client_magic_token = ?
            WHERE page_id = ? OR page_id = ? OR LOWER(client_username) = LOWER(?)
        """, (u_clean, pw_hash, salt, magic_token, p_clean, clean_pid, u_clean))
    else:
        cursor.execute("""
            UPDATE pages 
            SET client_username = ?, client_magic_token = ?
            WHERE page_id = ? OR page_id = ? OR LOWER(client_username) = LOWER(?)
        """, (u_clean, magic_token, p_clean, clean_pid, u_clean))

    conn.commit()
    conn.close()
    try:
        revoke_all_page_sessions(p_clean)
        if clean_pid != p_clean:
            revoke_all_page_sessions(clean_pid)
    except Exception:
        pass
    return {"username": u_clean, "magic_token": magic_token}

def update_page_google_sheets(page_id: str, sheets_url: str) -> bool:
    """Хуудасны Google Sheets холбоосыг шинэчлэх"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE pages 
        SET google_sheets_url = ?
        WHERE page_id = ?
    """, (sheets_url.strip(), page_id))
    conn.commit()
    conn.close()
    return True

def update_page_gemini_key(page_id: str, gemini_key: str, monthly_limit: Optional[int] = None) -> bool:
    """Харилцагчийн хувийн Gemini API түлхүүр болон лимитийг шинэчлэх"""
    conn = get_connection()
    cursor = conn.cursor()
    if monthly_limit is not None:
        cursor.execute("""
            UPDATE pages 
            SET gemini_api_key = ?, monthly_token_limit = ?
            WHERE page_id = ?
        """, (gemini_key.strip(), monthly_limit, page_id))
    else:
        cursor.execute("""
            UPDATE pages 
            SET gemini_api_key = ?
            WHERE page_id = ?
        """, (gemini_key.strip(), page_id))
    conn.commit()
    conn.close()
    return True

def increment_page_tokens(page_id: str, tokens: int) -> int:
    """Токен ашиглалтыг нэмэгдүүлж тооцох"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE pages 
        SET tokens_used = COALESCE(tokens_used, 0) + ?
        WHERE page_id = ?
    """, (tokens, page_id))
    cursor.execute("SELECT tokens_used, monthly_token_limit FROM pages WHERE page_id = ?", (page_id,))
    row = cursor.fetchone()
    conn.commit()
    conn.close()
    return row[0] if row else 0

# ----------------- PAGES / TENANTS CRUD -----------------
def _sanitize_page_secrets(d: Dict[str, Any], include_magic_token: bool = False) -> Dict[str, Any]:
    """Нууц токенуудыг зөвхөн masked хэлбэрээр үлдээж, жинхэнэ утгуудыг dict-ээс бүрэн устгах"""
    d["has_custom_gemini_key"] = bool(d.get("gemini_api_key"))
    d["has_password"] = bool(d.get("client_password_hash"))
    d["has_page_token"] = bool(d.get("page_access_token"))
    d["has_qpay"] = bool(d.get("qpay_username") and d.get("qpay_password"))
    d["has_bot_token"] = bool(d.get("telegram_bot_token"))
    d["page_access_token_masked"] = mask_secret(d.get("page_access_token"), 6, 4)
    d["gemini_api_key_masked"] = mask_secret(d.get("gemini_api_key"), 4, 4)
    d["qpay_password_masked"] = mask_secret(d.get("qpay_password"), 2, 2)
    d["telegram_bot_token_masked"] = mask_secret(d.get("telegram_bot_token"), 6, 4)
    # Жинхэнэ нууц түлхүүрүүдийг устгах (API-аар хэзээ ч задрахгүй)
    d.pop("page_access_token", None)
    d.pop("gemini_api_key", None)
    d.pop("qpay_password", None)
    d.pop("telegram_bot_token", None)
    d.pop("client_password_hash", None)
    d.pop("client_salt", None)
    if not include_magic_token:
        d.pop("client_magic_token", None)
    return d

def get_all_pages(mask_secrets: bool = True, include_magic_token: bool = False) -> List[Dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pages ORDER BY created_at ASC")
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        d = dict(r)
        d["has_custom_gemini_key"] = bool(d.get("gemini_api_key"))
        d["has_password"] = bool(d.get("client_password_hash"))
        if mask_secrets:
            _sanitize_page_secrets(d, include_magic_token=include_magic_token)
        result.append(d)
    return result

def get_page(page_id: str, mask_secrets: bool = False, include_magic_token: bool = False) -> Optional[Dict]:
    if not page_id:
        return None
    p_id = str(page_id).strip()
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pages WHERE page_id = ? OR LOWER(client_username) = LOWER(?)", (p_id, p_id))
    row = cursor.fetchone()
    if not row and "/" in p_id:
        clean_id = sanitize_page_id(p_id)
        cursor.execute("SELECT * FROM pages WHERE page_id = ?", (clean_id,))
        row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["has_custom_gemini_key"] = bool(d.get("gemini_api_key"))
    d["has_password"] = bool(d.get("client_password_hash"))
    if mask_secrets:
        _sanitize_page_secrets(d, include_magic_token=include_magic_token)
    return d

def save_page(
    page_id: str,
    name: str,
    category: str = "general",
    page_access_token: str = "",
    verify_token: str = "agent_verify_secret_token_123",
    knowledge_json: str = "{}",
    gemini_api_key: str = "",
    monthly_token_limit: int = 100000,
    is_active: int = 1
) -> bool:
    clean_id = sanitize_page_id(page_id)
    if "•" in (page_access_token or "") or "****" in (page_access_token or ""):
        page_access_token = ""
    if "•" in (gemini_api_key or "") or "****" in (gemini_api_key or ""):
        gemini_api_key = ""
    conn = get_connection()
    cursor = conn.cursor()
    magic = secrets.token_urlsafe(24)
    cursor.execute("""
        INSERT INTO pages (
            page_id, name, category, page_access_token, verify_token, is_active, 
            knowledge_json, gemini_api_key, monthly_token_limit, client_magic_token
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(page_id) DO UPDATE SET
            name = excluded.name,
            category = excluded.category,
            page_access_token = COALESCE(NULLIF(excluded.page_access_token, ''), pages.page_access_token),
            verify_token = excluded.verify_token,
            is_active = excluded.is_active,
            knowledge_json = excluded.knowledge_json,
            gemini_api_key = COALESCE(NULLIF(excluded.gemini_api_key, ''), pages.gemini_api_key),
            monthly_token_limit = COALESCE(excluded.monthly_token_limit, pages.monthly_token_limit)
    """, (clean_id, name, category, page_access_token, verify_token, is_active, knowledge_json, gemini_api_key, monthly_token_limit, magic))
    conn.commit()
    conn.close()
    return True

def delete_page(page_id: str) -> bool:
    """
    Delete a tenant and everything that belongs to it.

    The child rows are removed by the database, not by this function: every tenant-scoped
    table has ``page_id ... ON DELETE CASCADE`` (P1-06, revision `0003_foreign_keys`), so
    deleting the `pages` row is the whole operation. This used to walk a hand-maintained
    list of twelve table names, and that list had already drifted — it never deleted
    `comment_automations`, `tracked_links`, `audit_logs` or `task_jobs`, so deleting a
    tenant stranded those rows permanently.

    `audit_logs` is deliberately *not* deleted: its foreign key is `ON DELETE SET NULL`,
    so the audit trail outlives the tenant it describes.
    """
    if page_id == DEFAULT_PAGE_ID:
        return False  # Үндсэн хуудсыг устгахгүй
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM pages WHERE page_id = ?", (page_id,))
    conn.commit()
    conn.close()
    return True

# ----------------- LEADS CRUD -----------------
def save_registration(
    name: str,
    phone: str,
    service: str = "",
    channel: str = "web",
    sender_id: str = "",
    notes: str = "",
    status: str = "шинэ",
    page_id: str = DEFAULT_PAGE_ID
) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO registrations (page_id, name, phone, service, channel, sender_id, status, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (page_id, name, phone, service, channel, sender_id, status, notes))
    reg_id = cursor.lastrowid

    if sender_id:
        display_name = name if name and name != "Баримт баталгаажсан" else None
        # E-01: tenant-scoped. The old `page_id = COALESCE(?, page_id)` always took the
        # NEW page_id, which reassigned the row to the most recent tenant.
        cursor.execute("""
            INSERT INTO session_states (sender_id, page_id, channel, customer_name, customer_phone, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(page_id, sender_id) DO UPDATE SET
                customer_name = COALESCE(?, session_states.customer_name, ?),
                customer_phone = COALESCE(?, session_states.customer_phone),
                updated_at = CURRENT_TIMESTAMP
        """, (sender_id, page_id, channel, display_name or name, phone, display_name, name, phone))

    conn.commit()
    conn.close()
    sync_to_csv()
    return reg_id

def update_lead_status(lead_id: int, status: str, notes: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    if notes is not None:
        cursor.execute("UPDATE registrations SET status = ?, notes = ? WHERE id = ?", (status, notes, lead_id))
    else:
        cursor.execute("UPDATE registrations SET status = ? WHERE id = ?", (status, lead_id))
    conn.commit()
    conn.close()
    sync_to_csv()

def get_all_registrations(page_id: Optional[str] = None) -> List[Dict]:
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if page_id:
        cursor.execute("SELECT * FROM registrations WHERE page_id = ? ORDER BY created_at DESC", (page_id,))
    else:
        cursor.execute("SELECT * FROM registrations ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def sync_to_csv(page_id: Optional[str] = None) -> str:
    """Бүртгэлүүдийг CSV файл болон текст болгон экспортлох (Google Sheets & Excel UTF-8-BOM дэмжлэгтэй)"""
    rows = get_all_registrations(page_id=page_id)
    pages_map = {p["page_id"]: p["name"] for p in get_all_pages(mask_secrets=False)}
    
    output = io.StringIO()
    writer = csv.writer(output)
    # Толгой мөр (Cyrillic Mongolian - Excel болон Google Sheets дээр шууд гоё уншигдана)
    writer.writerow(["Бүртгэлийн №", "Огноо", "Хуудас / Салбар", "Харилцагчийн Нэр", "Утасны Дугаар", "Үйлчилгээ / Бүтээгдэхүүн", "Чатны Суваг", "Төлөв", "Тэмдэглэл"])
    
    for r in rows:
        p_name = pages_map.get(r.get("page_id", ""), r.get("page_id", ""))
        raw_notes = (r.get("notes") or "").strip()
        # Олон мөр бүхий урт текстийг нэг мөр болгон цэвэрлэж хүснэгт эвдрэхээс 100% сэргийлэх
        clean_notes = " | ".join([line.strip() for line in raw_notes.splitlines() if line.strip()])

        writer.writerow([
            r.get("id", ""),
            r.get("created_at", ""),
            p_name,
            r.get("name", ""),
            str(r.get("phone", "")),
            r.get("service", ""),
            r.get("channel", "web"),
            r.get("status", "шинэ"),
            clean_notes
        ])
    
    csv_content = output.getvalue()
    
    # Файлд хадгалах
    try:
        with open(CSV_PATH, mode="w", newline="", encoding="utf-8-sig") as f:
            f.write(csv_content)
    except Exception as e:
        logger.error(f"CSV sync error: {e}")
        
    return csv_content

def generate_excel(page_id: Optional[str] = None) -> io.BytesIO:
    """Бүртгэлүүдийг өндөр дизайнтай, жинхэнэ Microsoft Excel (.xlsx) файл болгон бэлтгэх"""
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Бүртгэлүүд"
        ws.views.sheetView[0].showGridLines = True

        # Толгой мөр
        headers = [
            "Бүртгэлийн №",
            "Огноо, цаг",
            "Хуудас / Салбар",
            "Харилцагчийн Нэр",
            "Утасны Дугаар",
            "Үйлчилгээ / Бүтээгдэхүүн",
            "Чатны Суваг",
            "Төлөв",
            "Тэмдэглэл / Баримтын Мэдээлэл"
        ]
        ws.append(headers)

        header_font = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
        header_align = Alignment(horizontal="center", vertical="center")
        thin_border = Border(
            left=Side(style="thin", color="CBD5E1"),
            right=Side(style="thin", color="CBD5E1"),
            top=Side(style="thin", color="CBD5E1"),
            bottom=Side(style="thin", color="CBD5E1")
        )

        ws.row_dimensions[1].height = 28
        for col_idx in range(1, len(headers) + 1):
            cell = ws.cell(row=1, column=col_idx)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align
            cell.border = thin_border

        rows = get_all_registrations(page_id=page_id)
        pages_map = {p["page_id"]: p["name"] for p in get_all_pages(mask_secrets=False)}

        data_font = Font(name="Segoe UI", size=10, color="0F172A")
        alt_fill = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
        center_align = Alignment(horizontal="center", vertical="center")
        left_align = Alignment(horizontal="left", vertical="center")

        for idx, r in enumerate(rows, start=2):
            ws.row_dimensions[idx].height = 22
            p_name = pages_map.get(r.get("page_id", ""), r.get("page_id", ""))
            
            raw_notes = (r.get("notes") or "").strip()
            clean_notes = " | ".join([line.strip() for line in raw_notes.splitlines() if line.strip()])

            phone_val = str(r.get("phone") or "")

            row_values = [
                r.get("id", ""),
                r.get("created_at", ""),
                p_name,
                r.get("name", ""),
                phone_val,
                r.get("service", ""),
                r.get("channel", "web"),
                r.get("status", "шинэ"),
                clean_notes
            ]
            ws.append(row_values)

            is_even = (idx % 2 == 0)
            for col_idx in range(1, len(row_values) + 1):
                cell = ws.cell(row=idx, column=col_idx)
                cell.font = data_font
                cell.border = thin_border
                if is_even:
                    cell.fill = alt_fill

                if col_idx in (1, 2, 7, 8):
                    cell.alignment = center_align
                else:
                    cell.alignment = left_align

                # Утасны дугаарыг text форматтай болгох (Scientific notation 5.96E+15 болон 0 хасагдахаас сэргийлэх)
                if col_idx == 5:
                    cell.number_format = "@"

        # Баганын өргөнийг автоматаар тохируулах
        for col in ws.columns:
            max_len = 0
            col_letter = get_column_letter(col[0].column)
            for cell in col:
                val_str = str(cell.value or "")
                if len(val_str) > max_len:
                    max_len = len(val_str)
            ws.column_dimensions[col_letter].width = max(12, min(max_len + 4, 60))

        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        return output
    except Exception as e:
        logger.error(f"Excel generation error: {e}")
        # Fallback to CSV as bytes
        csv_str = sync_to_csv(page_id=page_id)
        return io.BytesIO(csv_str.encode("utf-8-sig"))

# ----------------- MESSAGES & SESSIONS -----------------
def log_message(sender_id: str, channel: str, sender_type: str, content: str, page_id: str = DEFAULT_PAGE_ID):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (page_id, sender_id, channel, sender_type, content)
        VALUES (?, ?, ?, ?, ?)
    """, (page_id, sender_id, channel, sender_type, content))
    
    # E-01: the session identity is (page_id, sender_id). Conflict target and update are
    # both tenant-scoped, so one tenant's traffic can never move or overwrite another's row.
    cursor.execute("""
        INSERT INTO session_states (sender_id, page_id, channel, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(page_id, sender_id) DO UPDATE SET
            updated_at = CURRENT_TIMESTAMP
    """, (sender_id, page_id, channel))

    conn.commit()
    conn.close()

def save_chat_message(page_id: str, sender_id: str, channel: str, sender_type: str, content: str):
    return log_message(sender_id=sender_id, channel=channel, sender_type=sender_type, content=content, page_id=page_id)

def get_conversation_history(sender_id: str, limit: int = 50, page_id: Optional[str] = None) -> List[Dict]:
    """
    Conversation history for one customer.

    E-01: `page_id` is required in practice — without it this returns every tenant's
    messages for that sender. It stays keyword-optional only so old call sites fail loudly
    (they are audited) rather than silently; all in-repo callers pass it.
    """
    if not page_id:
        raise ValueError("get_conversation_history requires page_id (tenant scope, E-01)")
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM messages
        WHERE sender_id = ? AND page_id = ?
        ORDER BY created_at ASC
        LIMIT ?
    """, (sender_id, str(page_id), limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_active_sessions(page_id: Optional[str] = None) -> List[Dict]:
    """
    Active sessions, tenant-scoped.

    E-01: the correlated subqueries used to filter on `sender_id` alone, so each row's
    `last_message`, `last_sender_type` and `message_count` were computed across EVERY
    tenant that had ever seen that sender — a count and content leak even when the outer
    query was scoped. Every subquery now repeats `page_id`.
    """
    if not page_id:
        raise ValueError("get_active_sessions requires page_id (tenant scope, E-01)")
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT s.sender_id, s.page_id, s.channel, s.is_human_takeover, s.customer_name, s.customer_phone, s.updated_at,
               (SELECT content FROM messages WHERE sender_id = s.sender_id AND page_id = s.page_id ORDER BY id DESC LIMIT 1) as last_message,
               (SELECT sender_type FROM messages WHERE sender_id = s.sender_id AND page_id = s.page_id ORDER BY id DESC LIMIT 1) as last_sender_type,
               (SELECT COUNT(*) FROM messages WHERE sender_id = s.sender_id AND page_id = s.page_id) as message_count
        FROM session_states s
        WHERE s.page_id = ?
        ORDER BY s.updated_at DESC
    """, (str(page_id),))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def session_belongs_to_page(sender_id: str, page_id: Optional[str] = None) -> bool:
    """
    True when THIS tenant has a session row for that sender.

    E-01: the positive tenancy check for takeover/send. Deliberately a row-existence test
    rather than "does any tenant know this sender" — the latter is the leak we removed.
    """
    if not page_id:
        raise ValueError("session_belongs_to_page requires page_id (tenant scope, E-01)")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM session_states WHERE sender_id = ? AND page_id = ? LIMIT 1",
        (str(sender_id), str(page_id)),
    )
    row = cursor.fetchone()
    conn.close()
    return bool(row)


def set_human_takeover(sender_id: str, is_takeover: bool, page_id: Optional[str] = None):
    """E-01: takeover state belongs to one tenant's session, never to the sender globally."""
    if not page_id:
        raise ValueError("set_human_takeover requires page_id (tenant scope, E-01)")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE session_states
        SET is_human_takeover = ?
        WHERE sender_id = ? AND page_id = ?
    """, (1 if is_takeover else 0, str(sender_id), str(page_id)))
    conn.commit()
    conn.close()

def is_session_human_takeover(sender_id: str, page_id: Optional[str] = None) -> bool:
    """E-01: another tenant's takeover must not silence this tenant's bot."""
    if not page_id:
        raise ValueError("is_session_human_takeover requires page_id (tenant scope, E-01)")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT is_human_takeover FROM session_states WHERE sender_id = ? AND page_id = ?",
        (str(sender_id), str(page_id)),
    )
    row = cursor.fetchone()
    conn.close()
    return bool(row and row[0] == 1)

# ==================== 3-TIER CONVERSATION MEMORY (MEM0 & ZEP MODEL) ====================

def get_user_memory(page_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Хэрэглэгчийн санах ойг татаж авах (Нэр, утас, сонирхол, өмнөх хүсэлт)"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT page_id, user_id, customer_name, phone, interests, notes, last_topic, updated_at
        FROM user_memories
        WHERE page_id = ? AND user_id = ?
    """, (str(page_id), str(user_id)))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def upsert_user_memory(
    page_id: str,
    user_id: str,
    customer_name: Optional[str] = None,
    phone: Optional[str] = None,
    interests: Optional[str] = None,
    notes: Optional[str] = None,
    last_topic: Optional[str] = None
):
    """Хэрэглэгчийн санах ойг үүсгэх эсвэл шинэчлэх (Idempotent update)"""
    if not page_id or not user_id:
        return
    conn = get_connection()
    cursor = conn.cursor()
    
    # Өмнөх мэдээлэл байгаа эсэхийг шалгах
    cursor.execute("SELECT customer_name, phone, interests, notes, last_topic FROM user_memories WHERE page_id = ? AND user_id = ?", (str(page_id), str(user_id)))
    existing = cursor.fetchone()
    
    if existing:
        new_name = customer_name if customer_name else existing[0]
        new_phone = phone if phone else existing[1]
        
        # Сонирхол нэмэгдсэн бол залгах
        old_interests = existing[2] or ""
        if interests and interests not in old_interests:
            new_interests = f"{old_interests}, {interests}".strip(", ")
        else:
            new_interests = interests or old_interests
            
        new_notes = notes if notes else existing[3]
        new_topic = last_topic if last_topic else existing[4]
        
        cursor.execute("""
            UPDATE user_memories
            SET customer_name = ?, phone = ?, interests = ?, notes = ?, last_topic = ?, updated_at = CURRENT_TIMESTAMP
            WHERE page_id = ? AND user_id = ?
        """, (new_name, new_phone, new_interests, new_notes, new_topic, str(page_id), str(user_id)))
    else:
        cursor.execute("""
            INSERT INTO user_memories (page_id, user_id, customer_name, phone, interests, notes, last_topic)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (str(page_id), str(user_id), customer_name, phone, interests, notes, last_topic))
        
    conn.commit()
    conn.close()

# -------------------------------------------------------------
# 6. ФИНТЕК & ТӨЛБӨРИЙН УДИРДЛАГА (QPAY v2, DEEP LINKS, E-BARIMT)
# -------------------------------------------------------------
def create_invoice(
    page_id: str,
    amount: int,
    description: str = "Үйлчилгээний төлбөр",
    sender_id: Optional[str] = None,
    channel: str = "web",
    qr_text: str = "",
    qr_image_url: str = "",
    deep_links: Optional[List[Dict[str, Any]]] = None,
    invoice_id: Optional[str] = None,
    currency: str = "MNT",
    qpay_invoice_id: Optional[str] = None
) -> Dict[str, Any]:
    """Шинэ төлбөрийн нэхэмжлэх үүсгэх"""
    if not invoice_id:
        import uuid
        invoice_id = f"INV-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    
    deep_links_json = json.dumps(deep_links or [], ensure_ascii=False)
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO invoices (
            invoice_id, page_id, sender_id, channel, amount, currency, description,
            status, qr_text, qr_image_url, deep_links_json, qpay_invoice_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?)
    """, (
        invoice_id, str(page_id), sender_id, channel, int(amount), str(currency or "MNT"), description,
        qr_text, qr_image_url, deep_links_json, qpay_invoice_id
    ))
    conn.commit()
    conn.close()
    return get_invoice(invoice_id) or {}

def get_invoice(invoice_id: str) -> Optional[Dict[str, Any]]:
    """Нэхэмжлэхийн мэдээлэл авах"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM invoices WHERE invoice_id = ?", (invoice_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["deep_links"] = json.loads(d.get("deep_links_json") or "[]")
    except Exception:
        d["deep_links"] = []
    return d

def mark_invoice_paid(
    invoice_id: str,
    ebarimt_lottery: str = "",
    ebarimt_qr: str = "",
    provider_payment_id: Optional[str] = None,
    callback_verified: int = 0
) -> Optional[Dict[str, Any]]:
    """Нэхэмжлэхийг төлөгдсөн төлөвт оруулах ба И-Баримт олгох"""
    conn = get_connection()
    cursor = conn.cursor()
    paid_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE invoices
        SET status = 'PAID',
            paid_at = ?,
            ebarimt_lottery = ?,
            ebarimt_qr = ?,
            provider_payment_id = COALESCE(?, provider_payment_id),
            callback_verified = CASE WHEN ? > 0 THEN ? ELSE COALESCE(callback_verified, 0) END
        WHERE invoice_id = ?
    """, (
        paid_at,
        ebarimt_lottery,
        ebarimt_qr,
        provider_payment_id,
        int(callback_verified),
        int(callback_verified),
        invoice_id,
    ))
    conn.commit()
    conn.close()
    return get_invoice(invoice_id)

def list_invoices(page_id: Optional[str] = None, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Нэхэмжлэхүүдийн жагсаалт авах"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM invoices"
    params = []
    conditions = []
    if page_id:
        conditions.append("page_id = ?")
        params.append(str(page_id))
    if status:
        conditions.append("status = ?")
        params.append(status)
        
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    
    res = []
    for r in rows:
        d = dict(r)
        try:
            d["deep_links"] = json.loads(d.get("deep_links_json") or "[]")
        except Exception:
            d["deep_links"] = []
        res.append(d)
    return res

def day_range_bounds(date_str: Optional[str] = None) -> Tuple[str, str]:
    """
    Тухайн өдрийн [эхлэл, дараагийн өдрийн эхлэл) хязгаарыг буцаана.

    P1-03 (B-04): `col LIKE '2026-11-16%'` нь зөвхөн TEXT баганад ажиллана. Хүснэгтийн
    `created_at` нь жинхэнэ `TIMESTAMP` үед PostgreSQL
    `operator does not exist: timestamp without time zone ~~ unknown` алдаа шиддэг.
    Хязгаарын харьцуулалт нь TEXT (ISO-8601) болон TIMESTAMP хоёр дээр ижил ажиллана.
    """
    if date_str:
        try:
            start_dt = datetime.strptime(str(date_str)[:10], "%Y-%m-%d")
        except ValueError:
            start_dt = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        start_dt = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    end_dt = start_dt + timedelta(days=1)
    return (
        start_dt.strftime("%Y-%m-%d %H:%M:%S"),
        end_dt.strftime("%Y-%m-%d %H:%M:%S"),
    )


def get_fintech_summary(page_id: Optional[str] = None) -> Dict[str, Any]:
    """Финтек хяналтын самбарын тоон үзүүлэлтүүд (KPIs)"""
    conn = get_connection()
    cursor = conn.cursor()
    
    where_clause = " WHERE page_id = ?" if page_id else ""
    params = (str(page_id),) if page_id else ()
    
    # Нийт төлөгдсөн дүн
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0), COUNT(id) FROM invoices{where_clause} {'AND' if page_id else 'WHERE'} status = 'PAID'", params)
    paid_sum, paid_count = cursor.fetchone()
    
    # Хүлээгдэж буй нэхэмжлэхүүд
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0), COUNT(id) FROM invoices{where_clause} {'AND' if page_id else 'WHERE'} status = 'PENDING'", params)
    pending_sum, pending_count = cursor.fetchone()
    
    # Өнөөдрийн орлого (P1-03: LIKE биш, хязгаарын харьцуулалт)
    day_start, day_end = day_range_bounds()
    today_params = (
        (str(page_id), day_start, day_end) if page_id else (day_start, day_end)
    )
    today_where = (
        " WHERE page_id = ? AND status = 'PAID' AND paid_at >= ? AND paid_at < ?"
        if page_id
        else " WHERE status = 'PAID' AND paid_at >= ? AND paid_at < ?"
    )
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0), COUNT(id) FROM invoices{today_where}", today_params)
    today_sum, today_count = cursor.fetchone()

    conn.close()
    return {
        "total_revenue": int(paid_sum or 0),
        "paid_count": int(paid_count or 0),
        "pending_revenue": int(pending_sum or 0),
        "pending_count": int(pending_count or 0),
        "today_revenue": int(today_sum or 0),
        "today_count": int(today_count or 0)
    }

def update_page_qpay_settings(page_id: str, username: str, password: str, invoice_code: str, ebarimt_enabled: int = 1) -> bool:
    """Хуудасны QPay тохиргоог хадгалах"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE pages
        SET qpay_username = ?, qpay_password = ?, qpay_invoice_code = ?, ebarimt_enabled = ?
        WHERE page_id = ?
    """, (username.strip(), password.strip(), invoice_code.strip(), int(ebarimt_enabled), str(page_id)))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return success

# -------------------------------------------------------------
# 7. КАРГО ТЭЭВЭР БА АГУУЛАХЫН БҮРТГЭЛ (CARGO MANAGEMENT)
# -------------------------------------------------------------
def upsert_cargo_package(
    page_id: str,
    tracking_code: str,
    customer_name: Optional[str] = None,
    customer_phone: Optional[str] = None,
    weight_kg: float = 0.0,
    price_amount: int = 0,
    status: str = "REGISTERED",
    warehouse_location: str = "УБ Агуулах",
    notes: Optional[str] = None,
    sender_id: Optional[str] = None,
    channel: str = "web"
) -> Dict[str, Any]:
    """Карго ачааны бүртгэл үүсгэх эсвэл шинэчлэх (Idempotent Upsert)"""
    tracking_clean = tracking_code.strip().upper()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO cargo_packages (
            page_id, tracking_code, customer_name, customer_phone,
            weight_kg, price_amount, status, warehouse_location, notes,
            sender_id, channel
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(page_id, tracking_code) DO UPDATE SET
            customer_name = COALESCE(excluded.customer_name, cargo_packages.customer_name),
            customer_phone = COALESCE(excluded.customer_phone, cargo_packages.customer_phone),
            weight_kg = CASE WHEN excluded.weight_kg > 0 THEN excluded.weight_kg ELSE cargo_packages.weight_kg END,
            price_amount = CASE WHEN excluded.price_amount > 0 THEN excluded.price_amount ELSE cargo_packages.price_amount END,
            warehouse_location = excluded.warehouse_location,
            notes = COALESCE(excluded.notes, cargo_packages.notes)
    """, (
        str(page_id), tracking_clean, customer_name, customer_phone,
        float(weight_kg or 0.0), int(price_amount or 0), status,
        warehouse_location, notes, sender_id, channel
    ))
    conn.commit()
    conn.close()
    return get_cargo_package(page_id, tracking_clean) or {}

def get_cargo_package(page_id: str, tracking_code: str) -> Optional[Dict[str, Any]]:
    """Нэг карго ачааг кодоор хайх"""
    tracking_clean = tracking_code.strip().upper()
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cargo_packages WHERE page_id = ? AND tracking_code = ?", (str(page_id), tracking_clean))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def find_cargo_by_phone_or_code(page_id: str, query: str) -> List[Dict[str, Any]]:
    """Утасны дугаар эсвэл карго кодоор ачаа хайх"""
    q_clean = query.strip().upper()
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM cargo_packages
        WHERE page_id = ? AND (
            tracking_code LIKE ? OR
            customer_phone LIKE ? OR
            customer_name LIKE ?
        )
        ORDER BY id DESC LIMIT 10
    """, (str(page_id), f"%{q_clean}%", f"%{q_clean}%", f"%{q_clean}%"))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def scan_arrive_package(
    page_id: str,
    tracking_code: str,
    location: str = "УБ Агуулах",
    weight_kg: Optional[float] = None,
    price_amount: Optional[int] = None,
    invoice_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Агуулахын ажилтан баркод уншуулахад:
    1. Төлөвийг 'ARRIVED_UB' болгох
    2. Байршил болон ирсэн огноог бүртгэх
    """
    tracking_clean = tracking_code.strip().upper()
    arrived_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Хэрэв өмнө нь бүртгэлгүй байсан ч баркод уншуулсан бол шууд шинээр үүсгэнэ
    cursor.execute("SELECT id FROM cargo_packages WHERE page_id = ? AND tracking_code = ?", (str(page_id), tracking_clean))
    existing = cursor.fetchone()
    if not existing:
        cursor.execute("""
            INSERT INTO cargo_packages (
                page_id, tracking_code, status, warehouse_location,
                weight_kg, price_amount, arrived_at, invoice_id
            )
            VALUES (?, ?, 'ARRIVED_UB', ?, ?, ?, ?, ?)
        """, (
            str(page_id), tracking_clean, location,
            float(weight_kg or 0.0), int(price_amount or 0), arrived_at, invoice_id
        ))
    else:
        cursor.execute("""
            UPDATE cargo_packages
            SET status = 'ARRIVED_UB',
                warehouse_location = ?,
                arrived_at = ?,
                weight_kg = COALESCE(?, weight_kg),
                price_amount = COALESCE(?, price_amount),
                invoice_id = COALESCE(?, invoice_id)
            WHERE page_id = ? AND tracking_code = ?
        """, (
            location, arrived_at, weight_kg, price_amount, invoice_id,
            str(page_id), tracking_clean
        ))
        
    conn.commit()
    conn.close()
    return get_cargo_package(page_id, tracking_clean) or {}

def mark_cargo_delivered(page_id: str, tracking_code: str) -> Optional[Dict[str, Any]]:
    """Ачааг олгосон төлөвт оруулах"""
    tracking_clean = tracking_code.strip().upper()
    delivered_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE cargo_packages
        SET status = 'DELIVERED', delivered_at = ?
        WHERE page_id = ? AND tracking_code = ?
    """, (delivered_at, str(page_id), tracking_clean))
    conn.commit()
    conn.close()
    return get_cargo_package(page_id, tracking_clean)

def list_cargo_packages(page_id: str, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Карго ачаануудын жагсаалт"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    query = "SELECT * FROM cargo_packages WHERE page_id = ?"
    params = [str(page_id)]
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_cargo_summary(page_id: str) -> Dict[str, Any]:
    """Карго хяналтын самбарын үзүүлэлтүүд"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Нийт ачаа
    cursor.execute("SELECT COUNT(id) FROM cargo_packages WHERE page_id = ?", (str(page_id),))
    total_count = cursor.fetchone()[0] or 0
    
    # УБ-т ирсэн
    cursor.execute("SELECT COUNT(id) FROM cargo_packages WHERE page_id = ? AND status = 'ARRIVED_UB'", (str(page_id),))
    arrived_count = cursor.fetchone()[0] or 0
    
    # Олгогдсон
    cursor.execute("SELECT COUNT(id) FROM cargo_packages WHERE page_id = ? AND status = 'DELIVERED'", (str(page_id),))
    delivered_count = cursor.fetchone()[0] or 0
    
    # Төлбөр хүлээгдэж буй
    cursor.execute("SELECT COUNT(id), COALESCE(SUM(price_amount), 0) FROM cargo_packages WHERE page_id = ? AND status = 'ARRIVED_UB' AND price_amount > 0", (str(page_id),))
    pending_pay_count, pending_pay_sum = cursor.fetchone()

    conn.close()
    return {
        "total_packages": int(total_count),
        "arrived_packages": int(arrived_count),
        "delivered_packages": int(delivered_count),
        "pending_payment_count": int(pending_pay_count or 0),
        "pending_payment_amount": int(pending_pay_sum or 0)
    }

# -------------------------------------------------------------
# 8. ӨГЛӨӨНИЙ ЭЗНИЙ ТАЙЛАН & TELEGRAM ТОХИРГОО
# -------------------------------------------------------------
def update_page_telegram_settings(
    page_id: str,
    bot_token: str,
    manager_chat_id: str,
    report_time: str = "08:30",
    report_enabled: int = 1
) -> bool:
    """Хуудасны Telegram эзний тохиргоог хадгалах"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE pages
        SET telegram_bot_token = ?, telegram_manager_chat_id = ?,
            daily_report_time = ?, daily_report_enabled = ?
        WHERE page_id = ?
    """, (bot_token.strip(), manager_chat_id.strip(), report_time.strip(), int(report_enabled), str(page_id)))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return success

def get_daily_executive_metrics(page_id: Optional[str] = None, date_str: Optional[str] = None) -> Dict[str, Any]:
    """Өчигдрийн эсвэл өнөөдрийн гүйцэтгэлийн нэгдсэн тайлангийн тоонууд"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if not date_str:
        date_str = datetime.now().strftime("%Y-%m-%d")

    # P1-03 (B-04): range predicates work on both TEXT (ISO-8601) and TIMESTAMP columns.
    day_start, day_end = day_range_bounds(date_str)
    p_cond = " AND page_id = ?" if page_id else ""
    p_params = [day_start, day_end, str(page_id)] if page_id else [day_start, day_end]

    # 1. Шинэ харилцагч / Leads
    cursor.execute(
        f"SELECT COUNT(id) FROM registrations WHERE created_at >= ? AND created_at < ?{p_cond}",
        tuple(p_params),
    )
    leads_count = cursor.fetchone()[0] or 0

    # 2. Чат харилцан ярианууд
    cursor.execute(
        f"SELECT COUNT(DISTINCT sender_id) FROM messages WHERE created_at >= ? AND created_at < ?{p_cond}",
        tuple(p_params),
    )
    chats_count = cursor.fetchone()[0] or 0

    # 3. Карго ачаанууд (ирсэн)
    cursor.execute(
        f"SELECT COUNT(id) FROM cargo_packages WHERE arrived_at >= ? AND arrived_at < ?{p_cond}",
        tuple(p_params),
    )
    cargo_arrived = cursor.fetchone()[0] or 0

    # 4. QPay төлбөрүүд
    cursor.execute(
        f"SELECT COUNT(id), COALESCE(SUM(amount), 0) FROM invoices "
        f"WHERE status = 'PAID' AND paid_at >= ? AND paid_at < ?{p_cond}",
        tuple(p_params),
    )
    paid_count, paid_amount = cursor.fetchone()
    
    # 5. Хүлээгдэж буй карго ачаа (төлөгдөөгүй)
    pending_p_cond = " WHERE page_id = ?" if page_id else ""
    pending_params = (str(page_id),) if page_id else ()
    cursor.execute(f"SELECT COUNT(id), COALESCE(SUM(price_amount), 0) FROM cargo_packages{pending_p_cond} {'AND' if page_id else 'WHERE'} status = 'ARRIVED_UB' AND price_amount > 0", pending_params)
    pending_cargo_count, pending_cargo_amount = cursor.fetchone()
    
    # 6. Эскалаци / Хүнтэй ярих хүсэлт гаргасан
    cursor.execute("SELECT COUNT(sender_id) FROM session_states WHERE is_human_takeover = 1" + (" AND page_id = ?" if page_id else ""), ((str(page_id),) if page_id else ()))
    escalated_count = cursor.fetchone()[0] or 0
    
    conn.close()
    return {
        "date": date_str,
        "leads_count": int(leads_count),
        "chats_count": int(chats_count),
        "cargo_arrived": int(cargo_arrived),
        "paid_count": int(paid_count or 0),
        "paid_amount": int(paid_amount or 0),
        "pending_cargo_count": int(pending_cargo_count or 0),
        "pending_cargo_amount": int(pending_cargo_amount or 0),
        "escalated_count": int(escalated_count or 0)
    }

# -------------------------------------------------------------
# 9. АВТОМАТ МАРКЕТИНГ & ХАРИЛЦАГЧИЙГ СЭРГЭЭХ САН (RETENTION & BROADCAST)
# -------------------------------------------------------------
def get_automated_rules(page_id: str) -> List[Dict[str, Any]]:
    """Хуудасны автомат сэргээлтийн дүрмүүд (байхгүй бол анхны утгуудыг үүсгэнэ)"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    default_rules = [
        (
            page_id,
            "abandoned_chat",
            2,
            "Сайн байна уу? Танд үйлчилгээ болон үнийн мэдээлэл сонгоход тусламж хэрэгтэй юу? Та манай чатаар хүссэн асуултаа лавлаарай 😊",
            1
        ),
        (
            page_id,
            "cargo_pickup",
            48,
            "Сайн байна уу? Таны ачаа агуулахад бэлэн ирсэн байгаа шүү. Та ирж авахдаа чатаар олголтын кодоо хэлээрэй 📦",
            1
        ),
        (
            page_id,
            "retention_followup",
            600,
            "Сайн байна уу? Манайхаар үйлчлүүлснээс хойш сар орчим болжээ. Танд давтан үйлчилгээ эсвэл шинэ урамшууллын мэдээлэл хэрэгтэй бол бидэнд мэдэгдээрэй ✨",
            1
        )
    ]

    for p, r_type, delay, msg, active in default_rules:
        cursor.execute("""
            INSERT OR IGNORE INTO automated_rules (page_id, rule_type, delay_hours, message_template, is_active)
            VALUES (?, ?, ?, ?, ?)
        """, (str(p), r_type, delay, msg, active))
    conn.commit()

    cursor.execute("SELECT * FROM automated_rules WHERE page_id = ? ORDER BY id ASC", (str(page_id),))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def update_automated_rule(page_id: str, rule_type: str, delay_hours: int, message_template: str, is_active: bool) -> bool:
    """Сэргээх дүрмийг шинэчлэх"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO automated_rules (page_id, rule_type, delay_hours, message_template, is_active)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(page_id, rule_type) DO UPDATE SET
            delay_hours = excluded.delay_hours,
            message_template = excluded.message_template,
            is_active = excluded.is_active
    """, (str(page_id), rule_type, int(delay_hours), message_template.strip(), 1 if is_active else 0))
    conn.commit()
    conn.close()
    return True

def record_sent_followup(page_id: str, rule_type: str, sender_id: str, channel: str = "web") -> bool:
    """Илгээсэн сэргээх зурвасыг бүртгэх (давхардахаас сэргийлэх)"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR IGNORE INTO sent_followups (page_id, rule_type, sender_id, channel)
            VALUES (?, ?, ?, ?)
        """, (str(page_id), rule_type, str(sender_id), channel))
        conn.commit()
        success = cursor.rowcount > 0
    except Exception:
        success = False
    finally:
        conn.close()
    return success

def is_followup_sent(page_id: str, rule_type: str, sender_id: str) -> bool:
    """Өмнө нь энэ харилцагч руу энэ дүрмээр зурвас очсон эсэх"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id FROM sent_followups
        WHERE page_id = ? AND rule_type = ? AND sender_id = ?
    """, (str(page_id), rule_type, str(sender_id)))
    row = cursor.fetchone()
    conn.close()
    return bool(row)

def get_abandoned_chat_candidates(page_id: str, delay_hours: int = 2) -> List[Dict[str, Any]]:
    """Хаягдсан чат илрүүлэгч"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    threshold_iso = (datetime.now() - timedelta(hours=delay_hours)).strftime("%Y-%m-%d %H:%M:%S")
    max_threshold_iso = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

    # P1-07 (B-12): `GROUP BY m.sender_id` while selecting m.channel / m.content /
    # m.created_at is invalid SQL. SQLite silently returns an arbitrary row; PostgreSQL
    # raises `GroupingError: column "m.channel" must appear in the GROUP BY clause`.
    # Effect on production: abandoned-chat detection raised on every worker tick, so
    # `run_worker_tick` aborted before retention reminders were dispatched.
    #
    # Portable fix: pick the *latest* message per sender explicitly. `m2.id` breaks ties
    # deterministically, and the correlated aggregate works on SQLite, PostgreSQL and
    # MySQL (no window functions required).
    cursor.execute("""
        SELECT m.sender_id, m.channel, m.content, m.created_at
        FROM messages m
        WHERE m.page_id = ?
          AND m.sender_type = 'user'
          AND m.created_at <= ?
          AND m.created_at >= ?
          AND m.sender_id NOT IN (
              SELECT DISTINCT sender_id FROM registrations WHERE page_id = ? AND sender_id IS NOT NULL
          )
          AND m.sender_id NOT IN (
              SELECT sender_id FROM sent_followups WHERE page_id = ? AND rule_type = 'abandoned_chat'
          )
          AND NOT EXISTS (
              SELECT 1 FROM messages m2
              WHERE m2.page_id = m.page_id
                AND m2.sender_id = m.sender_id
                AND m2.sender_type = 'user'
                AND (
                    m2.created_at > m.created_at
                    OR (m2.created_at = m.created_at AND m2.id > m.id)
                )
          )
        ORDER BY m.created_at DESC
        LIMIT 50
    """, (str(page_id), threshold_iso, max_threshold_iso, str(page_id), str(page_id)))

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_cargo_pickup_candidates(page_id: str, delay_hours: int = 48) -> List[Dict[str, Any]]:
    """Ачаагаа аваагүй байгаа хэрэглэгчид (ARRIVED_UB төлөвтэй, delay_hours өнгөрсөн)"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    threshold_iso = (datetime.now() - timedelta(hours=delay_hours)).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT c.*
        FROM cargo_packages c
        WHERE c.page_id = ?
          AND c.status = 'ARRIVED_UB'
          AND c.arrived_at <= ?
          AND c.sender_id IS NOT NULL
          AND c.sender_id != ''
          AND c.sender_id NOT IN (
              SELECT sender_id FROM sent_followups WHERE page_id = ? AND rule_type = 'cargo_pickup'
          )
        LIMIT 50
    """, (str(page_id), threshold_iso, str(page_id)))

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_retention_candidates(page_id: str, delay_days: int = 25) -> List[Dict[str, Any]]:
    """25+ хоногийн өмнө бүртгэл үүссэн харилцагчид (хумс будалт, давтан үйлчилгээ)"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    threshold_iso = (datetime.now() - timedelta(days=delay_days)).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT r.*
        FROM registrations r
        WHERE r.page_id = ?
          AND r.created_at <= ?
          AND r.sender_id IS NOT NULL
          AND r.sender_id != ''
          AND r.sender_id NOT IN (
              SELECT sender_id FROM sent_followups WHERE page_id = ? AND rule_type = 'retention_followup'
          )
        LIMIT 50
    """, (str(page_id), threshold_iso, str(page_id)))

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_broadcast_audience(page_id: str, segment: str = "all") -> List[Dict[str, Any]]:
    """1-Click Broadcast илгээх зорилтот харилцагчид"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if segment == "leads_only":
        cursor.execute("""
            SELECT DISTINCT sender_id, channel, name, phone
            FROM registrations
            WHERE page_id = ? AND sender_id IS NOT NULL AND sender_id != ''
        """, (str(page_id),))
    elif segment == "unregistered":
        cursor.execute("""
            SELECT DISTINCT sender_id, channel, '' as name, '' as phone
            FROM messages
            WHERE page_id = ? AND sender_type = 'user' AND sender_id NOT IN (
                SELECT DISTINCT sender_id FROM registrations WHERE page_id = ? AND sender_id IS NOT NULL
            )
        """, (str(page_id), str(page_id)))
    else:  # all
        cursor.execute("""
            SELECT DISTINCT sender_id, channel, '' as name, '' as phone
            FROM messages
            WHERE page_id = ? AND sender_type = 'user'
        """, (str(page_id),))

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def create_marketing_campaign(
    page_id: str,
    title: str,
    message: str,
    target_segment: str = "all",
    channel: str = "all",
    sent_count: int = 0
) -> Dict[str, Any]:
    """1-Click Broadcast кампэйн үүсгэж хадгалах"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO marketing_campaigns (page_id, title, message, target_segment, channel, status, sent_count)
        VALUES (?, ?, ?, ?, ?, 'COMPLETED', ?)
    """, (str(page_id), title.strip(), message.strip(), target_segment, channel, sent_count))
    c_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {
        "id": c_id,
        "page_id": page_id,
        "title": title,
        "sent_count": sent_count,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
    }

def list_marketing_campaigns(page_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Өмнөх маркетинг кампэйнуудын жагсаалт"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM marketing_campaigns
        WHERE page_id = ?
        ORDER BY id DESC LIMIT ?
    """, (str(page_id), limit))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_marketing_summary(page_id: str) -> Dict[str, Any]:
    """Маркетингийн хураангуй тооцоолол"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(id) FROM marketing_campaigns WHERE page_id = ?", (str(page_id),))
    total_campaigns = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COALESCE(SUM(sent_count), 0) FROM marketing_campaigns WHERE page_id = ?", (str(page_id),))
    total_broadcast_sent = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(id) FROM sent_followups WHERE page_id = ?", (str(page_id),))
    total_followups_sent = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(DISTINCT sender_id) FROM messages WHERE page_id = ? AND sender_type = 'user'", (str(page_id),))
    total_audience = cursor.fetchone()[0] or 0

    conn.close()
    return {
        "total_campaigns": int(total_campaigns),
        "total_broadcast_sent": int(total_broadcast_sent),
        "total_followups_sent": int(total_followups_sent),
        "total_audience": int(total_audience)
    }

# -------------------------------------------------------------
# 10. ЦАГ ЗАХИАЛГА & ХУАНЛИЙН САН (APPOINTMENTS & CALENDAR)
# -------------------------------------------------------------
def is_slot_available(page_id: str, appointment_date: str, appointment_time: str, service_name: Optional[str] = None) -> bool:
    """Тухайн өдөр болон цагт сул цаг байгаа эсэх"""
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT id FROM appointments WHERE page_id = ? AND appointment_date = ? AND appointment_time = ? AND status != 'CANCELLED'"
    params = [str(page_id), appointment_date.strip(), appointment_time.strip()]
    if service_name:
        query += " AND service_name = ?"
        params.append(service_name.strip())
    cursor.execute(query, tuple(params))
    row = cursor.fetchone()
    conn.close()
    return row is None

def create_appointment(
    page_id: str,
    customer_name: str,
    customer_phone: str,
    service_name: str,
    appointment_date: str,
    appointment_time: str,
    sender_id: Optional[str] = None,
    channel: str = "web",
    notes: str = ""
) -> Optional[Dict[str, Any]]:
    """Шинэ цаг захиалга үүсгэх (хэрэв сул бол)"""
    if not is_slot_available(page_id, appointment_date, appointment_time, service_name):
        return None
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO appointments (
            page_id, customer_name, customer_phone, service_name,
            appointment_date, appointment_time, sender_id, channel, notes, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'CONFIRMED')
    """, (
        str(page_id), customer_name.strip(), customer_phone.strip(), service_name.strip(),
        appointment_date.strip(), appointment_time.strip(), sender_id, channel, notes.strip()
    ))
    a_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Сэжимд давхар хадгалах
    save_registration(
        name=customer_name,
        phone=customer_phone,
        service=f"{service_name} ({appointment_date} {appointment_time})",
        channel=channel,
        page_id=page_id,
        sender_id=sender_id,
        notes=f"Цаг захиалга #{a_id}: {notes}"
    )

    return get_appointment(a_id)

def get_appointment(appointment_id: int) -> Optional[Dict[str, Any]]:
    """Цаг захиалгын мэдээлэл авах"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM appointments WHERE id = ?", (int(appointment_id),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def list_appointments(
    page_id: str,
    date_str: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """Цаг захиалгуудын жагсаалт"""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    conditions = ["page_id = ?"]
    params = [str(page_id)]
    if date_str:
        conditions.append("appointment_date = ?")
        params.append(date_str)
    if status:
        conditions.append("status = ?")
        params.append(status)
    query = f"SELECT * FROM appointments WHERE {' AND '.join(conditions)} ORDER BY appointment_date ASC, appointment_time ASC LIMIT ?"
    params.append(limit)
    cursor.execute(query, tuple(params))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def update_appointment_status(appointment_id: int, status: str) -> bool:
    """Цаг захиалгын төлөв өөрчлөх ('CONFIRMED', 'COMPLETED', 'CANCELLED')"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE appointments SET status = ? WHERE id = ?", (status, int(appointment_id)))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return success

def get_pending_appointment_reminders(hours_ahead: int = 2) -> List[Dict[str, Any]]:
    """
    2 цагийн өмнө сануулах шаардлагатай цаг захиалгууд:
    (Өнөөдрийн огноо, цаг нь одоогоос <= 2 цагийн дараа эхлэх, reminder_sent = 0, status = 'CONFIRMED')
    """
    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    current_time_str = now.strftime("%H:%M")
    two_hours_later_str = (now + timedelta(hours=hours_ahead)).strftime("%H:%M")

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM appointments
        WHERE appointment_date = ?
          AND appointment_time >= ?
          AND appointment_time <= ?
          AND reminder_sent = 0
          AND status = 'CONFIRMED'
    """, (today_str, current_time_str, two_hours_later_str))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def mark_appointment_reminder_sent(appointment_id: int) -> bool:
    """Сануулга илгээгдсэнийг тэмдэглэх"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE appointments SET reminder_sent = 1 WHERE id = ?", (int(appointment_id),))
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return success

def get_appointments_summary(page_id: str) -> Dict[str, Any]:
    """Цаг захиалгын самбарын хураангуй тооцоолол"""
    today_str = datetime.now().strftime("%Y-%m-%d")
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(id) FROM appointments WHERE page_id = ? AND appointment_date = ? AND status = 'CONFIRMED'", (str(page_id), today_str))
    today_confirmed = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(id) FROM appointments WHERE page_id = ? AND status = 'CONFIRMED'", (str(page_id),))
    total_upcoming = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(id) FROM appointments WHERE page_id = ? AND status = 'COMPLETED'", (str(page_id),))
    total_completed = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(id) FROM appointments WHERE page_id = ?", (str(page_id),))
    total_all = cursor.fetchone()[0] or 0

    conn.close()
    return {
        "today_confirmed": int(today_confirmed),
        "total_upcoming": int(total_upcoming),
        "total_completed": int(total_completed),
        "total_all": int(total_all)
    }

# -------------------------------------------------------------
# 10. COMMENT-TO-DM AUTOMATIONS, TRACKED LINKS & ROI ANALYTICS
# -------------------------------------------------------------

def create_comment_automation(
    page_id: str,
    name: str,
    dm_message_text: str,
    post_id: str = "*",
    keyword_pattern: str = "*",
    public_reply_text: str = "Танд чат руу дэлгэрэнгүй мэдээлэл илгээлээ! ✅",
    cta_button_text: str = "",
    cta_url: str = "",
    is_active: int = 1,
) -> Dict[str, Any]:
    """Сэтгэгдлээс шууд DM рүү хариулах автоматжуулалт үүсгэх"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO comment_automations
                (page_id, name, post_id, keyword_pattern, public_reply_text, dm_message_text, cta_button_text, cta_url, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(page_id or DEFAULT_PAGE_ID),
                str(name).strip(),
                str(post_id or "*").strip() or "*",
                str(keyword_pattern or "*").strip() or "*",
                str(public_reply_text or "").strip(),
                str(dm_message_text).strip(),
                str(cta_button_text or "").strip(),
                str(cta_url or "").strip(),
                1 if is_active else 0,
            ),
        )
        new_id = cursor.lastrowid
        conn.commit()
        cursor.execute("SELECT * FROM comment_automations WHERE id = ?", (new_id,))
        row = cursor.fetchone()
        return dict(row) if row else {"id": new_id, "page_id": page_id, "name": name}
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def list_comment_automations(page_id: Optional[str] = None, active_only: bool = False) -> List[Dict[str, Any]]:
    """Тухайн салбарын Comment-to-DM автоматжуулалтын жагсаалт"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        conds = []
        params: List[Any] = []
        if page_id:
            conds.append("page_id = ?")
            params.append(str(page_id))
        if active_only:
            conds.append("is_active = 1")
        where_sql = (" WHERE " + " AND ".join(conds)) if conds else ""
        cursor.execute(f"SELECT * FROM comment_automations{where_sql} ORDER BY id DESC", tuple(params))
        return [dict(r) for r in cursor.fetchall()]
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def get_comment_automation(automation_id: int) -> Optional[Dict[str, Any]]:
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM comment_automations WHERE id = ?", (int(automation_id),))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def toggle_comment_automation(automation_id: int, page_id: Optional[str] = None, is_active: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Автоматжуулалтыг 1 товшилтоор ON/OFF болгох (Tenant-safe)"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if page_id:
            cursor.execute("SELECT * FROM comment_automations WHERE id = ? AND page_id = ?", (int(automation_id), str(page_id)))
        else:
            cursor.execute("SELECT * FROM comment_automations WHERE id = ?", (int(automation_id),))
        row = cursor.fetchone()
        if not row:
            return None
        current = dict(row)
        new_state = (1 if is_active else 0) if is_active is not None else (0 if current.get("is_active") else 1)
        cursor.execute("UPDATE comment_automations SET is_active = ? WHERE id = ?", (new_state, int(automation_id)))
        conn.commit()
        current["is_active"] = new_state
        return current
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def delete_comment_automation(automation_id: int, page_id: Optional[str] = None) -> bool:
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        if page_id:
            cursor.execute("DELETE FROM comment_automations WHERE id = ? AND page_id = ?", (int(automation_id), str(page_id)))
        else:
            cursor.execute("DELETE FROM comment_automations WHERE id = ?", (int(automation_id),))
        deleted = (cursor.rowcount or 0) > 0
        conn.commit()
        return deleted
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def increment_comment_automation_trigger(automation_id: int) -> None:
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE comment_automations SET trigger_count = COALESCE(trigger_count, 0) + 1 WHERE id = ?",
            (int(automation_id),),
        )
        conn.commit()
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def create_tracked_link(
    page_id: str,
    target_url: str,
    title: str = "",
    automation_id: Optional[int] = None,
    code: Optional[str] = None,
) -> Dict[str, Any]:
    """CTR хяналттай богино холбоос (/r/{code}) үүсгэх"""
    short_code = (code or secrets.token_urlsafe(6)).replace("-", "").replace("_", "")[:10]
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO tracked_links (code, page_id, automation_id, title, target_url, clicks_count)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (short_code, str(page_id or DEFAULT_PAGE_ID), automation_id, str(title or "").strip(), str(target_url).strip()),
        )
        new_id = cursor.lastrowid
        conn.commit()
        cursor.execute("SELECT * FROM tracked_links WHERE id = ?", (new_id,))
        row = cursor.fetchone()
        return dict(row) if row else {"id": new_id, "code": short_code, "target_url": target_url}
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def resolve_and_increment_tracked_link(code: str) -> Optional[Dict[str, Any]]:
    """Богино холбоосыг олж, дарсан тоог атомикаар +1 нэмэгдүүлэх"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tracked_links WHERE code = ?", (str(code).strip(),))
        row = cursor.fetchone()
        if not row:
            return None
        link_data = dict(row)
        cursor.execute("UPDATE tracked_links SET clicks_count = COALESCE(clicks_count, 0) + 1 WHERE id = ?", (link_data["id"],))
        conn.commit()
        link_data["clicks_count"] = int(link_data.get("clicks_count") or 0) + 1
        return link_data
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def list_tracked_links(page_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = None
    cursor = None
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if page_id:
            cursor.execute("SELECT * FROM tracked_links WHERE page_id = ? ORDER BY id DESC", (str(page_id),))
        else:
            cursor.execute("SELECT * FROM tracked_links ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def get_roi_analytics(page_id: Optional[str] = None, seconds_per_reply: float = 30.0, hourly_wage_mnt: int = 15000) -> Dict[str, Any]:
    """
    noflow-аас санаа авсан ROI & Хэмнэсэн Цагийн Аналитик:
    - Нийт харилцсан хүн (unique_contacts)
    - Ботын илгээсэн мессеж (bot_messages)
    - Хариулсан сэтгэгдэл (comment_replies)
    - Холбоос дарсан тоо (link_clicks)
    - Хэмнэсэн цаг ба төгрөгийн хэмнэлт (estimated_hours_saved, estimated_cost_saved_mnt)
    - Төлбөрийн хөрвүүлэлт (invoices_created, invoices_paid, paid_revenue_mnt)
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        p_where = " WHERE page_id = ?" if page_id else ""
        p_params = (str(page_id),) if page_id else ()

        cursor.execute(f"SELECT COUNT(DISTINCT sender_id) FROM messages{p_where}", p_params)
        unique_contacts = int(cursor.fetchone()[0] or 0)

        msg_bot_where = " WHERE page_id = ? AND sender_type = 'bot'" if page_id else " WHERE sender_type = 'bot'"
        cursor.execute(f"SELECT COUNT(id) FROM messages{msg_bot_where}", p_params)
        bot_messages = int(cursor.fetchone()[0] or 0)

        cursor.execute(f"SELECT COALESCE(SUM(trigger_count), 0), COUNT(id) FROM comment_automations{p_where}", p_params)
        ca_row = cursor.fetchone()
        comment_replies = int(ca_row[0] or 0)
        automations_total = int(ca_row[1] or 0)

        active_where = " WHERE page_id = ? AND is_active = 1" if page_id else " WHERE is_active = 1"
        cursor.execute(f"SELECT COUNT(id) FROM comment_automations{active_where}", p_params)
        automations_active = int(cursor.fetchone()[0] or 0)

        cursor.execute(f"SELECT COALESCE(SUM(clicks_count), 0) FROM tracked_links{p_where}", p_params)
        link_clicks = int(cursor.fetchone()[0] or 0)

        cursor.execute(f"SELECT COUNT(id) FROM invoices{p_where}", p_params)
        invoices_created = int(cursor.fetchone()[0] or 0)

        paid_where = " WHERE page_id = ? AND status = 'PAID'" if page_id else " WHERE status = 'PAID'"
        cursor.execute(f"SELECT COUNT(id), COALESCE(SUM(amount), 0) FROM invoices{paid_where}", p_params)
        paid_row = cursor.fetchone()
        invoices_paid = int(paid_row[0] or 0)
        paid_revenue_mnt = int(paid_row[1] or 0)

        total_interactions = bot_messages + comment_replies
        hours_saved = round((total_interactions * seconds_per_reply) / 3600.0, 1)
        cost_saved_mnt = int(round(hours_saved * hourly_wage_mnt))
        payment_conversion_pct = round((invoices_paid / invoices_created) * 100.0, 1) if invoices_created > 0 else 0.0

        return {
            "page_id": page_id,
            "unique_contacts": unique_contacts,
            "bot_messages": bot_messages,
            "comment_replies": comment_replies,
            "total_interactions": total_interactions,
            "link_clicks": link_clicks,
            "automations_total": automations_total,
            "automations_active": automations_active,
            "estimated_hours_saved": hours_saved,
            "estimated_cost_saved_mnt": cost_saved_mnt,
            "seconds_per_reply_assumption": seconds_per_reply,
            "invoices_created": invoices_created,
            "invoices_paid": invoices_paid,
            "paid_revenue_mnt": paid_revenue_mnt,
            "payment_conversion_pct": payment_conversion_pct,
        }
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    init_db()
    print("Database & Multi-Tenant RBAC Auth initialized successfully!")
