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

logger = logging.getLogger("database")

DB_PATH = os.path.join(os.path.dirname(__file__), "leads.db")
CSV_PATH = os.path.join(os.path.dirname(__file__), "leads.csv")
DEFAULT_PAGE_ID = "100799479495809"
DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin2026")

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

def init_db():
    """Өгөгдлийн санг үүсгэх / шинэчлэх (Multi-Tenant Agency & RBAC Auth Support)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 0. Олон Хуудас / Харилцагчийн хүснэгт (Tenants / Pages)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pages (
            page_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT DEFAULT 'general',
            page_access_token TEXT,
            verify_token TEXT DEFAULT 'agent_verify_secret_token_123',
            is_active INTEGER DEFAULT 1,
            knowledge_json TEXT,
            gemini_api_key TEXT DEFAULT '',
            client_username TEXT,
            client_password_hash TEXT,
            client_salt TEXT,
            client_magic_token TEXT,
            monthly_token_limit INTEGER DEFAULT 100000,
            tokens_used INTEGER DEFAULT 0,
            google_sheets_url TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 1. Бүртгэгдсэн харилцагчид (Leads)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT DEFAULT '100799479495809',
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            service TEXT,
            channel TEXT DEFAULT 'web',
            sender_id TEXT,
            status TEXT DEFAULT 'шинэ',
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Харилцан ярианы түүх (Chatwoot загвар - Unified Messages)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT DEFAULT '100799479495809',
            sender_id TEXT NOT NULL,
            channel TEXT DEFAULT 'web',
            sender_type TEXT NOT NULL, -- 'user', 'bot', 'agent' (human)
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Хэрэглэгчийн төлөв (Human takeover status)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS session_states (
            sender_id TEXT PRIMARY KEY,
            page_id TEXT DEFAULT '100799479495809',
            channel TEXT DEFAULT 'web',
            is_human_takeover INTEGER DEFAULT 0, -- 1 бол AI түр зогсоно
            customer_name TEXT,
            customer_phone TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 4. Нэвтрэлтийн сессүүд (RBAC Sessions)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_token TEXT PRIMARY KEY,
            role TEXT NOT NULL, -- 'admin' or 'client'
            page_id TEXT,       -- NULL for admin, specific page_id for client
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )
    """)

    # Багануудыг аюулгүй нэмэх (Migration check)
    tables_to_migrate = [
        ("registrations", "page_id", "TEXT DEFAULT '100799479495809'"),
        ("messages", "page_id", "TEXT DEFAULT '100799479495809'"),
        ("session_states", "page_id", "TEXT DEFAULT '100799479495809'"),
        ("pages", "gemini_api_key", "TEXT DEFAULT ''"),
        ("pages", "client_username", "TEXT"),
        ("pages", "client_password_hash", "TEXT"),
        ("pages", "client_salt", "TEXT"),
        ("pages", "client_magic_token", "TEXT"),
        ("pages", "monthly_token_limit", "INTEGER DEFAULT 100000"),
        ("pages", "tokens_used", "INTEGER DEFAULT 0")
    ]
    for table, col, col_def in tables_to_migrate:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
        except sqlite3.OperationalError:
            pass

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

    conn.commit()
    conn.close()

# ----------------- AUTHENTICATION & RBAC SESSIONS -----------------
def create_session(role: str, page_id: Optional[str] = None, hours: int = 72) -> str:
    """Шинэ нэвтрэлтийн сесс үүсгэх"""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=hours)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO sessions (session_token, role, page_id, expires_at)
        VALUES (?, ?, ?, ?)
    """, (token, role, page_id, expires_at.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return token

def get_session(token: str) -> Optional[Dict[str, Any]]:
    """Сесс хүчинтэй эсэхийг шалгах"""
    if not token:
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT session_token, role, page_id, created_at, expires_at
        FROM sessions
        WHERE session_token = ? AND datetime(expires_at) > datetime('now')
    """, (token,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_session(token: str):
    """Гарах (Logout)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE session_token = ?", (token,))
    conn.commit()
    conn.close()

def authenticate_admin(password: str) -> bool:
    """Супер Админы нууц үгийг шалгах"""
    expected = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD).strip()
    return secrets.compare_digest(password.strip(), expected)

def authenticate_client(identifier: str, password: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Харилцагчийн нэвтрэлтийг шалгах (Username/Password эсвэл Magic Link Token)"""
    if not identifier:
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. 1-товчлуурт Magic Token-оор шалгах
    cursor.execute("SELECT * FROM pages WHERE client_magic_token = ? AND is_active = 1", (identifier.strip(),))
    row = cursor.fetchone()
    if row:
        conn.close()
        return dict(row)

    # 2. Username + Password-оор шалгах
    if password:
        cursor.execute("SELECT * FROM pages WHERE (client_username = ? OR page_id = ?) AND is_active = 1", (identifier.strip(), identifier.strip()))
        row = cursor.fetchone()
        if row:
            p_dict = dict(row)
            stored_hash = p_dict.get("client_password_hash")
            salt = p_dict.get("client_salt")
            if stored_hash and salt and verify_password(password, stored_hash, salt):
                conn.close()
                return p_dict

    conn.close()
    return None

def set_client_credentials(page_id: str, username: str, password: Optional[str] = None) -> Dict[str, str]:
    """Харилцагчийн нэвтрэх нэр, нууц үг, шууд орох Magic холбоос шинэчлэх"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    magic_token = secrets.token_urlsafe(24)
    if password:
        pw_hash, salt = hash_password(password)
        cursor.execute("""
            UPDATE pages 
            SET client_username = ?, client_password_hash = ?, client_salt = ?, client_magic_token = ?
            WHERE page_id = ?
        """, (username.strip(), pw_hash, salt, magic_token, page_id))
    else:
        cursor.execute("""
            UPDATE pages 
            SET client_username = ?, client_magic_token = ?
            WHERE page_id = ?
        """, (username.strip(), magic_token, page_id))

    conn.commit()
    conn.close()
    return {"username": username, "magic_token": magic_token}

def update_page_google_sheets(page_id: str, sheets_url: str) -> bool:
    """Хуудасны Google Sheets холбоосыг шинэчлэх"""
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
def get_all_pages(mask_secrets: bool = True) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pages ORDER BY created_at ASC")
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        d = dict(r)
        d["has_custom_gemini_key"] = bool(d.get("gemini_api_key"))
        if mask_secrets:
            d["page_access_token_masked"] = mask_secret(d.get("page_access_token"), 6, 4)
            d["gemini_api_key_masked"] = mask_secret(d.get("gemini_api_key"), 4, 4)
            # Нууц үгийн хэшийг гаргахгүй
            d.pop("client_password_hash", None)
            d.pop("client_salt", None)
        result.append(d)
    return result

def get_page(page_id: str, mask_secrets: bool = False) -> Optional[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pages WHERE page_id = ?", (page_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["has_custom_gemini_key"] = bool(d.get("gemini_api_key"))
    if mask_secrets:
        d["page_access_token_masked"] = mask_secret(d.get("page_access_token"), 6, 4)
        d["gemini_api_key_masked"] = mask_secret(d.get("gemini_api_key"), 4, 4)
        d.pop("client_password_hash", None)
        d.pop("client_salt", None)
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
    conn = sqlite3.connect(DB_PATH)
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
    """, (page_id, name, category, page_access_token, verify_token, is_active, knowledge_json, gemini_api_key, monthly_token_limit, magic))
    conn.commit()
    conn.close()
    return True

def delete_page(page_id: str) -> bool:
    if page_id == DEFAULT_PAGE_ID:
        return False  # Үндсэн хуудсыг устгахгүй
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM pages WHERE page_id = ?", (page_id,))
    cursor.execute("DELETE FROM registrations WHERE page_id = ?", (page_id,))
    cursor.execute("DELETE FROM messages WHERE page_id = ?", (page_id,))
    cursor.execute("DELETE FROM session_states WHERE page_id = ?", (page_id,))
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO registrations (page_id, name, phone, service, channel, sender_id, status, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (page_id, name, phone, service, channel, sender_id, status, notes))
    reg_id = cursor.lastrowid

    if sender_id:
        display_name = name if name and name != "Баримт баталгаажсан" else None
        cursor.execute("""
            INSERT INTO session_states (sender_id, page_id, channel, customer_name, customer_phone, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(sender_id) DO UPDATE SET
                page_id = COALESCE(?, session_states.page_id),
                customer_name = COALESCE(?, session_states.customer_name, ?),
                customer_phone = COALESCE(?, session_states.customer_phone),
                updated_at = CURRENT_TIMESTAMP
        """, (sender_id, page_id, channel, display_name or name, phone, page_id, display_name, name, phone))

    conn.commit()
    conn.close()
    sync_to_csv()
    return reg_id

def update_lead_status(lead_id: int, status: str, notes: Optional[str] = None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if notes is not None:
        cursor.execute("UPDATE registrations SET status = ?, notes = ? WHERE id = ?", (status, notes, lead_id))
    else:
        cursor.execute("UPDATE registrations SET status = ? WHERE id = ?", (status, lead_id))
    conn.commit()
    conn.close()
    sync_to_csv()

def get_all_registrations(page_id: Optional[str] = None) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
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
    fieldnames = ["id", "created_at", "page_name", "name", "phone", "service", "channel", "status", "notes"]
    
    pages_map = {p["page_id"]: p["name"] for p in get_all_pages(mask_secrets=False)}
    
    output = io.StringIO()
    writer = csv.writer(output)
    # Толгой мөр (Cyrillic Mongolian - Excel болон Google Sheets дээр шууд гоё уншигдана)
    writer.writerow(["Бүртгэлийн №", "Огноо", "Хуудас / Салбар", "Харилцагчийн Нэр", "Утасны Дугаар", "Үйлчилгээ / Бүтээгдэхүүн", "Чатны Суваг", "Төлөв", "Тэмдэглэл"])
    
    for r in rows:
        p_name = pages_map.get(r.get("page_id", ""), r.get("page_id", ""))
        writer.writerow([
            r.get("id", ""),
            r.get("created_at", ""),
            p_name,
            r.get("name", ""),
            r.get("phone", ""),
            r.get("service", ""),
            r.get("channel", "web"),
            r.get("status", "шинэ"),
            r.get("notes", "")
        ])
    
    csv_content = output.getvalue()
    
    # Файлд хадгалах
    try:
        with open(CSV_PATH, mode="w", newline="", encoding="utf-8-sig") as f:
            f.write(csv_content)
    except Exception as e:
        logger.error(f"CSV sync error: {e}")
        
    return csv_content

# ----------------- MESSAGES & SESSIONS -----------------
def log_message(sender_id: str, channel: str, sender_type: str, content: str, page_id: str = DEFAULT_PAGE_ID):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO messages (page_id, sender_id, channel, sender_type, content)
        VALUES (?, ?, ?, ?, ?)
    """, (page_id, sender_id, channel, sender_type, content))
    
    cursor.execute("""
        INSERT INTO session_states (sender_id, page_id, channel, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(sender_id) DO UPDATE SET 
            page_id = COALESCE(?, session_states.page_id),
            updated_at = CURRENT_TIMESTAMP
    """, (sender_id, page_id, channel, page_id))

    conn.commit()
    conn.close()

def get_conversation_history(sender_id: str, limit: int = 50) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM messages 
        WHERE sender_id = ? 
        ORDER BY created_at ASC 
        LIMIT ?
    """, (sender_id, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_active_sessions(page_id: Optional[str] = None) -> List[Dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if page_id:
        cursor.execute("""
            SELECT s.sender_id, s.page_id, s.channel, s.is_human_takeover, s.customer_name, s.customer_phone, s.updated_at,
                   (SELECT content FROM messages WHERE sender_id = s.sender_id ORDER BY id DESC LIMIT 1) as last_message,
                   (SELECT sender_type FROM messages WHERE sender_id = s.sender_id ORDER BY id DESC LIMIT 1) as last_sender_type,
                   (SELECT COUNT(*) FROM messages WHERE sender_id = s.sender_id) as message_count
            FROM session_states s
            WHERE s.page_id = ?
            ORDER BY s.updated_at DESC
        """, (page_id,))
    else:
        cursor.execute("""
            SELECT s.sender_id, s.page_id, s.channel, s.is_human_takeover, s.customer_name, s.customer_phone, s.updated_at,
                   (SELECT content FROM messages WHERE sender_id = s.sender_id ORDER BY id DESC LIMIT 1) as last_message,
                   (SELECT sender_type FROM messages WHERE sender_id = s.sender_id ORDER BY id DESC LIMIT 1) as last_sender_type,
                   (SELECT COUNT(*) FROM messages WHERE sender_id = s.sender_id) as message_count
            FROM session_states s
            ORDER BY s.updated_at DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def set_human_takeover(sender_id: str, is_takeover: bool):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE session_states 
        SET is_human_takeover = ? 
        WHERE sender_id = ?
    """, (1 if is_takeover else 0, sender_id))
    conn.commit()
    conn.close()

def is_session_human_takeover(sender_id: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT is_human_takeover FROM session_states WHERE sender_id = ?", (sender_id,))
    row = cursor.fetchone()
    conn.close()
    return bool(row and row[0] == 1)

if __name__ == "__main__":
    init_db()
    print("Database & Multi-Tenant RBAC Auth initialized successfully!")
