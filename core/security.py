import os
import hmac
import hashlib
import logging
from typing import Dict, Any, Optional, Set
from fastapi import Request, HTTPException

import database

logger = logging.getLogger("core.security")

# ============================================================================
# CENTRALIZED RBAC MATRIX (Phase 1.2)
# ============================================================================
VALID_ROLES: Set[str] = {
    "super_admin",
    "admin",
    "manager",
    "agent",
    "warehouse_staff",
    "client",
    "read_only",
}

ADMIN_ROLES: Set[str] = {"super_admin", "admin"}

TENANT_SCOPED_ROLES: Set[str] = {
    "manager",
    "agent",
    "warehouse_staff",
    "client",
    "read_only",
}

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "super_admin": {
        "system:admin",
        "system:keys",
        "system:backup",
        "pages:read",
        "pages:write",
        "pages:delete",
        "leads:read",
        "leads:write",
        "leads:export",
        "sessions:read",
        "sessions:write",
        "knowledge:read",
        "knowledge:write",
        "fintech:read",
        "fintech:write",
        "cargo:read",
        "cargo:write",
        "retention:read",
        "retention:write",
        "appointments:read",
        "appointments:write",
        "executive:read",
        "executive:write",
    },
    "admin": {
        "system:admin",
        "system:keys",
        "system:backup",
        "pages:read",
        "pages:write",
        "pages:delete",
        "leads:read",
        "leads:write",
        "leads:export",
        "sessions:read",
        "sessions:write",
        "knowledge:read",
        "knowledge:write",
        "fintech:read",
        "fintech:write",
        "cargo:read",
        "cargo:write",
        "retention:read",
        "retention:write",
        "appointments:read",
        "appointments:write",
        "executive:read",
        "executive:write",
    },
    "manager": {
        "pages:read",
        "leads:read",
        "leads:write",
        "leads:export",
        "sessions:read",
        "sessions:write",
        "knowledge:read",
        "knowledge:write",
        "fintech:read",
        "fintech:write",
        "cargo:read",
        "cargo:write",
        "retention:read",
        "retention:write",
        "appointments:read",
        "appointments:write",
        "executive:read",
        "executive:write",
    },
    "client": {
        "pages:read",
        "leads:read",
        "leads:write",
        "leads:export",
        "sessions:read",
        "sessions:write",
        "knowledge:read",
        "knowledge:write",
        "fintech:read",
        "fintech:write",
        "cargo:read",
        "cargo:write",
        "retention:read",
        "retention:write",
        "appointments:read",
        "appointments:write",
        "executive:read",
        "executive:write",
    },
    "agent": {
        "pages:read",
        "leads:read",
        "leads:write",
        "sessions:read",
        "sessions:write",
        "knowledge:read",
        "fintech:read",
        "fintech:write",
        "cargo:read",
        "appointments:read",
        "appointments:write",
    },
    "warehouse_staff": {
        "pages:read",
        "cargo:read",
        "cargo:write",
        "leads:read",
    },
    "read_only": {
        "pages:read",
        "leads:read",
        "sessions:read",
        "knowledge:read",
        "fintech:read",
        "cargo:read",
        "retention:read",
        "appointments:read",
        "executive:read",
    },
}


def is_admin_role(role: Optional[str]) -> bool:
    return str(role or "").strip().lower() in ADMIN_ROLES


def has_permission(role: Optional[str], permission: str) -> bool:
    r = str(role or "").strip().lower()
    if r in ADMIN_ROLES:
        return True
    allowed = ROLE_PERMISSIONS.get(r, set())
    return permission in allowed


def constant_time_equal(a: Optional[str], b: Optional[str]) -> bool:
    """Constant-time string comparison to prevent timing side-channel attacks."""
    if not a or not b:
        return False
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


def is_production_mode() -> bool:
    """Систем production эсвэл хатуу хамгаалалтын горимд ажиллаж буй эсэхийг шалгах"""
    env = os.getenv("ENV", "").strip().lower()
    strict = os.getenv("STRICT_SECURITY", "").strip().lower()
    return env in ("production", "prod") or strict in ("1", "true", "yes")


def is_webhook_fail_closed() -> bool:
    """Webhook гарын үсгийн шалгалт fail-closed горимд байгаа эсэх"""
    if is_production_mode():
        return True
    fc = os.getenv("WEBHOOK_FAIL_CLOSED", "").strip().lower()
    return fc in ("1", "true", "yes")


def is_query_token_allowed() -> bool:
    """
    Production горимд query-string токен (`?token=...`)-ыг анхдагчаар хориглоно.
    Зөвхөн ALLOW_QUERY_TOKEN=1 үед эсвэл dev орчинд DISALLOW_QUERY_TOKEN!=1 үед зөвшөөрнө.
    """
    if os.getenv("DISALLOW_QUERY_TOKEN", "").strip() == "1":
        return False
    if is_production_mode():
        return os.getenv("ALLOW_QUERY_TOKEN", "").strip() == "1"
    return True


def extract_token_from_request(
    request: Optional[Request] = None,
    authorization: Optional[str] = None,
    session_token_cookie: Optional[str] = None,
    token: Optional[str] = None,
    auth_token: Optional[str] = None,
    client_token: Optional[str] = None,
) -> Optional[str]:
    """Request-ээс Bearer токен эсвэл HttpOnly cookie-г аюулгүй задлах"""
    token_str = None
    allow_query = is_query_token_allowed()

    if request:
        auth_h = request.headers.get("Authorization", "")
        if auth_h.startswith("Bearer "):
            token_str = auth_h[7:].strip()
        if not token_str:
            c = request.cookies.get("session_token")
            if c:
                token_str = str(c).strip()
        if not token_str and allow_query:
            q = (
                request.query_params.get("token")
                or request.query_params.get("auth_token")
                or request.query_params.get("client_token")
            )
            if q:
                token_str = str(q).strip()

    if not token_str:
        if authorization and isinstance(authorization, str) and authorization.startswith("Bearer "):
            token_str = authorization[7:].strip()
        elif session_token_cookie and isinstance(session_token_cookie, str):
            token_str = session_token_cookie.strip()
        elif allow_query and token and isinstance(token, str):
            token_str = token.strip()
        elif allow_query and auth_token and isinstance(auth_token, str):
            token_str = auth_token.strip()
        elif allow_query and client_token and isinstance(client_token, str):
            token_str = client_token.strip()

    return token_str


async def resolve_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """Хүсэлтээс одоогийн нэвтэрсэн хэрэглэгчийг тодорхойлох"""
    token_str = extract_token_from_request(request=request)
    if not token_str:
        return None

    session = database.get_session(token_str)
    if session:
        return session

    client_page = database.authenticate_client(token_str)
    if client_page:
        sess_token = database.create_session(role="client", page_id=client_page["page_id"])
        return database.get_session(sess_token)

    return None


async def require_user(request: Request, permission: Optional[str] = None) -> Dict[str, Any]:
    """Нэвтэрсэн хэрэглэгч байхыг заавал шаардах + RBAC permission шалгах"""
    user = await resolve_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтрэх шаардлагатай! (Unauthorized)")
    if permission and not has_permission(user.get("role"), permission):
        raise HTTPException(
            status_code=403,
            detail=f"Энэ үйлдлийг гүйцэтгэх эрх хүрэлцэхгүй байна! ({permission} required)",
        )
    return user


async def require_admin(request: Request) -> Dict[str, Any]:
    """Зөвхөн Супер Админ / Админ эрхтэй хэрэглэгчийг зөвшөөрөх"""
    user = await require_user(request)
    if not is_admin_role(user.get("role")):
        raise HTTPException(status_code=403, detail="Зөвхөн Супер Админ эрхтэй! (Forbidden)")
    return user


async def require_permission(request: Request, permission: str) -> Dict[str, Any]:
    """Тодорхой RBAC эрх шаардах"""
    return await require_user(request, permission=permission)


async def enforce_tenant_scope(
    request: Request,
    requested_page_id: Optional[str] = None,
    require_auth: bool = True,
    allow_admin_all: bool = False,
    permission: Optional[str] = None,
) -> Optional[str]:
    """
    Төвлөрсөн Tenant Isolation & RBAC шалгалт:
    - Хамгаалалттай endpoint бүр дээр анхдагчаар `require_auth=True` байх ба нэвтрээгүй бол 401 буцаана.
      Хэзээ ч хамгаалалттай endpoint дээр default tenant руу чимээгүй унахгүй!
    - Tenant-scoped эрхтэй (`client`, `manager`, `agent`, `warehouse_staff`, `read_only`) бол:
      Зөвхөн өөрийн `user['page_id']`-д хандана. Өөр `requested_page_id` дамжуулбал 403 буцаана!
    - Admin (`admin`, `super_admin`) эрхтэй бол: `requested_page_id` эсвэл бүх салбар (`None` хэрэв `allow_admin_all=True`).
    """
    user = await resolve_current_user(request)
    if not user:
        if require_auth or is_production_mode():
            raise HTTPException(status_code=401, detail="Нэвтрэх шаардлагатай! (Unauthorized)")
        return requested_page_id or database.DEFAULT_PAGE_ID

    role = str(user.get("role") or "").strip().lower()
    if permission and not has_permission(role, permission):
        raise HTTPException(
            status_code=403,
            detail=f"Энэ үйлдлийг гүйцэтгэх эрхгүй! ({permission} required)",
        )

    if not is_admin_role(role):
        client_pid = user.get("page_id")
        if not client_pid:
            raise HTTPException(status_code=403, detail="Хэрэглэгчийн салбар (page_id) тодорхойгүй байна!")
        if requested_page_id and str(requested_page_id).strip() not in ("", str(client_pid)):
            raise HTTPException(
                status_code=403,
                detail="Бусад салбарын мэдээлэлд хандах эрхгүй! (Cross-tenant access denied)",
            )
        return str(client_pid)

    # Admin / Super Admin
    if allow_admin_all:
        return requested_page_id if requested_page_id else None
    return requested_page_id or database.DEFAULT_PAGE_ID


def verify_resource_tenant_ownership(
    user: Optional[Dict[str, Any]],
    resource_page_id: Optional[str],
    require_auth: bool = True,
) -> None:
    """
    Тухайн обьект (Lead, Session, Invoice, Cargo, Appointment) нь
    нэвтэрсэн хэрэглэгчийн салбарт харьяалагдаж буй эсэхийг шалгах (IDOR хамгаалалт)
    """
    if not user:
        if require_auth or is_production_mode():
            raise HTTPException(status_code=401, detail="Нэвтрэх шаардлагатай! (Unauthorized)")
        return
    role = str(user.get("role") or "").strip().lower()
    if not is_admin_role(role):
        user_pid = user.get("page_id")
        if not user_pid or (resource_page_id and str(resource_page_id) != str(user_pid)):
            raise HTTPException(
                status_code=403,
                detail="Энэхүү бүртгэл танай салбарт хамаарахгүй байна! (IDOR Forbidden)",
            )


def verify_meta_webhook_signature(raw_body: bytes, signature_header: Optional[str]) -> bool:
    """
    Meta X-Hub-Signature-256 шалгалт.
    Fail-closed горимд (WEBHOOK_FAIL_CLOSED=1 эсвэл ENV=production) нууц түлхүүр байхгүй
    эсвэл гарын үсэг буруу бол шууд False буцаана.
    """
    app_secret = os.getenv("META_APP_SECRET", "").strip()
    if not app_secret:
        if is_webhook_fail_closed():
            logger.error("Meta webhook fail-closed: META_APP_SECRET is not configured")
            return False
        return True

    if not signature_header:
        return False

    expected_sig = "sha256=" + hmac.new(app_secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_header.strip(), expected_sig)


def verify_telegram_webhook_secret(secret_header: Optional[str]) -> bool:
    """
    Telegram X-Telegram-Bot-Api-Secret-Token шалгалт.
    Fail-closed горимд (WEBHOOK_FAIL_CLOSED=1 эсвэл ENV=production) нууц токен байхгүй
    эсвэл таарахгүй бол шууд False буцаана.
    """
    tg_secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
    if not tg_secret:
        if is_webhook_fail_closed():
            logger.error("Telegram webhook fail-closed: TELEGRAM_WEBHOOK_SECRET is not configured")
            return False
        return True

    if not secret_header:
        return False

    return hmac.compare_digest(secret_header.strip(), tg_secret)


def verify_manychat_webhook_secret(request: Request, page_id: Optional[str] = None) -> bool:
    """
    ManyChat webhook secret / token шалгалт.
    Fail-closed горимд MANYCHAT_WEBHOOK_SECRET эсвэл тухайн салбарын verify_token-той тулгаж шалгана.
    """
    expected = os.getenv("MANYCHAT_WEBHOOK_SECRET", "").strip()
    if not expected and page_id:
        page_cfg = database.get_page(page_id)
        if page_cfg and page_cfg.get("verify_token"):
            expected = str(page_cfg.get("verify_token")).strip()

    header_secret = (
        request.headers.get("X-ManyChat-Secret")
        or request.headers.get("X-Webhook-Secret")
        or ""
    ).strip()
    if not header_secret:
        auth_h = request.headers.get("Authorization", "")
        if auth_h.startswith("Bearer "):
            header_secret = auth_h[7:].strip()

    if not expected:
        if is_webhook_fail_closed():
            logger.error("ManyChat webhook fail-closed: MANYCHAT_WEBHOOK_SECRET is not configured")
            return False
        return True

    if not header_secret:
        return False

    return hmac.compare_digest(header_secret, expected)
