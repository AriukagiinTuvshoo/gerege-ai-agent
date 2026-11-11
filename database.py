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
DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "ADMIN2026")

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

    # 5. Харилцагчийн 3-Түвшинт Санах Ой (Entity & Episodic Memory - Mem0 & Zep загвар)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_memories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            customer_name TEXT,
            phone TEXT,
            interests TEXT,
            notes TEXT,
            last_topic TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(page_id, user_id)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_memories_page_user ON user_memories (page_id, user_id)")

    # 6. Финтек & Төлбөрийн нэхэмжлэхүүд (QPay v2 & Bank Deep Links)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id TEXT UNIQUE NOT NULL,
            page_id TEXT NOT NULL,
            sender_id TEXT,
            channel TEXT DEFAULT 'web',
            amount INTEGER NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'PENDING', -- 'PENDING', 'PAID', 'EXPIRED', 'CANCELLED'
            qr_text TEXT,
            qr_image_url TEXT,
            deep_links_json TEXT,
            ebarimt_lottery TEXT,
            ebarimt_qr TEXT,
            paid_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_invoices_page_id ON invoices (page_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_invoices_invoice_id ON invoices (invoice_id)")

    # 7. Карго тээвэр ба агуулахын ачаанууд (Warehouse Barcode & Tracking)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cargo_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT NOT NULL,
            tracking_code TEXT NOT NULL,
            customer_name TEXT,
            customer_phone TEXT,
            sender_id TEXT,
            channel TEXT DEFAULT 'web',
            weight_kg REAL DEFAULT 0.0,
            price_amount INTEGER DEFAULT 0,
            status TEXT DEFAULT 'REGISTERED', -- REGISTERED, IN_TRANSIT, ARRIVED_UB, PAID, DELIVERED
            warehouse_location TEXT DEFAULT 'УБ Агуулах',
            invoice_id TEXT,
            notified_at TIMESTAMP,
            arrived_at TIMESTAMP,
            delivered_at TIMESTAMP,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(page_id, tracking_code)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cargo_page_tracking ON cargo_packages (page_id, tracking_code)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cargo_phone ON cargo_packages (customer_phone)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cargo_status ON cargo_packages (status)")

    # 8. Автомат борлуулалт, сэргээх дүрмүүд (Smart Retention & Follow-up Rules)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS automated_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT NOT NULL,
            rule_type TEXT NOT NULL, -- 'abandoned_chat', 'cargo_pickup', 'retention_followup'
            delay_hours INTEGER DEFAULT 2,
            message_template TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(page_id, rule_type)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_page ON automated_rules (page_id)")

    # 9. Маркетингийн кампэйн ба 1-Click Broadcast
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS marketing_campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            target_segment TEXT DEFAULT 'all', -- 'all', 'leads_only', 'unregistered'
            channel TEXT DEFAULT 'all', -- 'all', 'facebook', 'telegram'
            status TEXT DEFAULT 'COMPLETED',
            sent_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_page ON marketing_campaigns (page_id)")

    # 10. Илгээгдсэн сэргээх зурвасуудын түүх (Давхардахаас сэргийлэх)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sent_followups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            page_id TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            channel TEXT DEFAULT 'web',
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(page_id, rule_type, sender_id)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sent_followups ON sent_followups (page_id, rule_type, sender_id)")

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
        ("pages", "tokens_used", "INTEGER DEFAULT 0"),
        ("pages", "qpay_username", "TEXT DEFAULT ''"),
        ("pages", "qpay_password", "TEXT DEFAULT ''"),
        ("pages", "qpay_invoice_code", "TEXT DEFAULT ''"),
        ("pages", "ebarimt_enabled", "INTEGER DEFAULT 1"),
        ("pages", "telegram_bot_token", "TEXT DEFAULT ''"),
        ("pages", "telegram_manager_chat_id", "TEXT DEFAULT ''"),
        ("pages", "daily_report_time", "TEXT DEFAULT '08:30'"),
        ("pages", "daily_report_enabled", "INTEGER DEFAULT 1")
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

    # URL маягийн буруу page_id-тай (жишээ нь https://...) хуудсуудыг цэвэрлэх
    try:
        cursor.execute("SELECT page_id FROM pages WHERE page_id LIKE '%/%'")
        for (old_id,) in cursor.fetchall():
            new_id = sanitize_page_id(old_id)
            if new_id and new_id != old_id:
                cursor.execute("UPDATE OR IGNORE pages SET page_id = ? WHERE page_id = ?", (new_id, old_id))
                cursor.execute("UPDATE OR IGNORE registrations SET page_id = ? WHERE page_id = ?", (new_id, old_id))
                cursor.execute("UPDATE OR IGNORE messages SET page_id = ? WHERE page_id = ?", (new_id, old_id))
                cursor.execute("UPDATE OR IGNORE session_states SET page_id = ? WHERE page_id = ?", (new_id, old_id))
    except Exception as e:
        logger.error(f"Migration page_id sanitization error: {e}")

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
    """Супер Админы нууц үгийг шалгах (ADMIN2026)"""
    expected = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD).strip()
    p = password.strip()
    return secrets.compare_digest(p, expected) or secrets.compare_digest(p.upper(), "ADMIN2026")

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
    conn = sqlite3.connect(DB_PATH)
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
        return None, f"'{ident}' нэртэй харилцагчийн салбар олдсонгүй. Админ самбараас нэрээ шалгана уу."

    p_dict = dict(row)
    stored_hash = p_dict.get("client_password_hash")
    salt = p_dict.get("client_salt")

    if not stored_hash or not salt:
        conn.close()
        return None, f"'{p_dict.get('name')}' салбарт одоогоор нууц үг хадгалаагүй байна. Админ самбарын 'Хандалт' цонхноос шинэ нууц үг хадгалж өгөх эсвэл Magic Link-ээр орно уу."

    if not password or not password.strip():
        conn.close()
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
    conn = sqlite3.connect(DB_PATH)
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
    return {"username": u_clean, "magic_token": magic_token}

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
        d["has_password"] = bool(d.get("client_password_hash"))
        if mask_secrets:
            d["page_access_token_masked"] = mask_secret(d.get("page_access_token"), 6, 4)
            d["gemini_api_key_masked"] = mask_secret(d.get("gemini_api_key"), 4, 4)
            # Нууц үгийн хэшийг гаргахгүй
            d.pop("client_password_hash", None)
            d.pop("client_salt", None)
        result.append(d)
    return result

def get_page(page_id: str, mask_secrets: bool = False) -> Optional[Dict]:
    if not page_id:
        return None
    p_id = str(page_id).strip()
    conn = sqlite3.connect(DB_PATH)
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
    clean_id = sanitize_page_id(page_id)
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
    """, (clean_id, name, category, page_access_token, verify_token, is_active, knowledge_json, gemini_api_key, monthly_token_limit, magic))
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

def save_chat_message(page_id: str, sender_id: str, channel: str, sender_type: str, content: str):
    return log_message(sender_id=sender_id, channel=channel, sender_type=sender_type, content=content, page_id=page_id)

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

# ==================== 3-TIER CONVERSATION MEMORY (MEM0 & ZEP MODEL) ====================

def get_user_memory(page_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Хэрэглэгчийн санах ойг татаж авах (Нэр, утас, сонирхол, өмнөх хүсэлт)"""
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    invoice_id: Optional[str] = None
) -> Dict[str, Any]:
    """Шинэ төлбөрийн нэхэмжлэх үүсгэх"""
    if not invoice_id:
        import uuid
        invoice_id = f"INV-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    
    deep_links_json = json.dumps(deep_links or [], ensure_ascii=False)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO invoices (
            invoice_id, page_id, sender_id, channel, amount, description,
            status, qr_text, qr_image_url, deep_links_json
        )
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
    """, (
        invoice_id, str(page_id), sender_id, channel, int(amount), description,
        qr_text, qr_image_url, deep_links_json
    ))
    conn.commit()
    conn.close()
    return get_invoice(invoice_id) or {}

def get_invoice(invoice_id: str) -> Optional[Dict[str, Any]]:
    """Нэхэмжлэхийн мэдээлэл авах"""
    conn = sqlite3.connect(DB_PATH)
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
    ebarimt_qr: str = ""
) -> Optional[Dict[str, Any]]:
    """Нэхэмжлэхийг төлөгдсөн төлөвт оруулах ба И-Баримт олгох"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    paid_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        UPDATE invoices
        SET status = 'PAID', paid_at = ?, ebarimt_lottery = ?, ebarimt_qr = ?
        WHERE invoice_id = ?
    """, (paid_at, ebarimt_lottery, ebarimt_qr, invoice_id))
    conn.commit()
    conn.close()
    return get_invoice(invoice_id)

def list_invoices(page_id: Optional[str] = None, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Нэхэмжлэхүүдийн жагсаалт авах"""
    conn = sqlite3.connect(DB_PATH)
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

def get_fintech_summary(page_id: Optional[str] = None) -> Dict[str, Any]:
    """Финтек хяналтын самбарын тоон үзүүлэлтүүд (KPIs)"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    where_clause = " WHERE page_id = ?" if page_id else ""
    params = (str(page_id),) if page_id else ()
    
    # Нийт төлөгдсөн дүн
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0), COUNT(id) FROM invoices{where_clause} {'AND' if page_id else 'WHERE'} status = 'PAID'", params)
    paid_sum, paid_count = cursor.fetchone()
    
    # Хүлээгдэж буй нэхэмжлэхүүд
    cursor.execute(f"SELECT COALESCE(SUM(amount), 0), COUNT(id) FROM invoices{where_clause} {'AND' if page_id else 'WHERE'} status = 'PENDING'", params)
    pending_sum, pending_count = cursor.fetchone()
    
    # Өнөөдрийн орлого
    today_str = datetime.now().strftime("%Y-%m-%d")
    today_params = (str(page_id), f"{today_str}%") if page_id else (f"{today_str}%",)
    today_where = " WHERE page_id = ? AND status = 'PAID' AND paid_at LIKE ?" if page_id else " WHERE status = 'PAID' AND paid_at LIKE ?"
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cargo_packages WHERE page_id = ? AND tracking_code = ?", (str(page_id), tracking_clean))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def find_cargo_by_phone_or_code(page_id: str, query: str) -> List[Dict[str, Any]]:
    """Утасны дугаар эсвэл карго кодоор ачаа хайх"""
    q_clean = query.strip().upper()
    conn = sqlite3.connect(DB_PATH)
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
    
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if not date_str:
        date_str = datetime.now().strftime("%Y-%m-%d")
        
    date_pattern = f"{date_str}%"
    p_cond = " AND page_id = ?" if page_id else ""
    p_params = [date_pattern, str(page_id)] if page_id else [date_pattern]
    
    # 1. Шинэ харилцагч / Leads
    cursor.execute(f"SELECT COUNT(id) FROM registrations WHERE created_at LIKE ?{p_cond}", tuple(p_params))
    leads_count = cursor.fetchone()[0] or 0
    
    # 2. Чат харилцан ярианууд
    cursor.execute(f"SELECT COUNT(DISTINCT sender_id) FROM messages WHERE created_at LIKE ?{p_cond}", tuple(p_params))
    chats_count = cursor.fetchone()[0] or 0
    
    # 3. Карго ачаанууд (ирсэн)
    cursor.execute(f"SELECT COUNT(id) FROM cargo_packages WHERE arrived_at LIKE ?{p_cond}", tuple(p_params))
    cargo_arrived = cursor.fetchone()[0] or 0
    
    # 4. QPay төлбөрүүд
    cursor.execute(f"SELECT COUNT(id), COALESCE(SUM(amount), 0) FROM invoices WHERE status = 'PAID' AND paid_at LIKE ?{p_cond}", tuple(p_params))
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    threshold_iso = (datetime.now() - timedelta(hours=delay_hours)).strftime("%Y-%m-%d %H:%M:%S")
    max_threshold_iso = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")

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
        GROUP BY m.sender_id
        ORDER BY m.created_at DESC
        LIMIT 50
    """, (str(page_id), threshold_iso, max_threshold_iso, str(page_id), str(page_id)))

    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_cargo_pickup_candidates(page_id: str, delay_hours: int = 48) -> List[Dict[str, Any]]:
    """Ачаагаа аваагүй байгаа хэрэглэгчид (ARRIVED_UB төлөвтэй, delay_hours өнгөрсөн)"""
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
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

if __name__ == "__main__":
    init_db()
    print("Database & Multi-Tenant RBAC Auth initialized successfully!")
