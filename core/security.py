import os
import hmac
import hashlib
import logging
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException

import database

logger = logging.getLogger("core.security")


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
    if request:
        auth_h = request.headers.get("Authorization", "")
        if auth_h.startswith("Bearer "):
            token_str = auth_h[7:].strip()
        if not token_str:
            c = request.cookies.get("session_token")
            if c:
                token_str = str(c).strip()
        # Production горимд query param-аар токен дамжуулахыг хориглох боломжтой
        if not token_str and os.getenv("DISALLOW_QUERY_TOKEN", "0") != "1":
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
        elif token and isinstance(token, str):
            token_str = token.strip()
        elif auth_token and isinstance(auth_token, str):
            token_str = auth_token.strip()
        elif client_token and isinstance(client_token, str):
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


async def require_user(request: Request) -> Dict[str, Any]:
    """Нэвтэрсэн хэрэглэгч (admin эсвэл client) байхыг заавал шаардах"""
    user = await resolve_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтрэх шаардлагатай! (Unauthorized)")
    return user


async def require_admin(request: Request) -> Dict[str, Any]:
    """Зөвхөн Супер Админ эрхтэй хэрэглэгчийг зөвшөөрөх"""
    user = await require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Зөвхөн Супер Админ эрхтэй! (Forbidden)")
    return user


async def enforce_tenant_scope(
    request: Request,
    requested_page_id: Optional[str] = None,
    require_auth: bool = False,
    allow_admin_all: bool = False,
) -> Optional[str]:
    """
    Төвлөрсөн Tenant Isolation & RBAC шалгалт:
    - Client эрхтэй бол: Зөвхөн өөрийн `user['page_id']`-д хандана. Өөр `requested_page_id` дамжуулбал 403 буцаана!
    - Admin эрхтэй бол: `requested_page_id` эсвэл бүх салбар (`None` хэрэв `allow_admin_all=True`).
    - Нэвтрээгүй бол: `require_auth=True` эсвэл `is_production_mode()` үед 401 буцаана.
    """
    user = await resolve_current_user(request)
    if not user:
        if require_auth or is_production_mode():
            raise HTTPException(status_code=401, detail="Нэвтрэх шаардлагатай! (Unauthorized)")
        return requested_page_id or database.DEFAULT_PAGE_ID

    if user.get("role") == "client":
        client_pid = user.get("page_id")
        if requested_page_id and str(requested_page_id) != str(client_pid):
            raise HTTPException(
                status_code=403,
                detail="Бусад салбарын мэдээлэлд хандах эрхгүй! (Cross-tenant access denied)",
            )
        return client_pid

    # Admin
    if allow_admin_all:
        return requested_page_id
    return requested_page_id or database.DEFAULT_PAGE_ID


def verify_resource_tenant_ownership(
    user: Optional[Dict[str, Any]],
    resource_page_id: Optional[str],
) -> None:
    """
    Тухайн обьект (Lead, Session, Invoice, Cargo, Appointment) нь
    нэвтэрсэн Client-ийн салбарт харьяалагдаж буй эсэхийг шалгах (IDOR хамгаалалт)
    """
    if not user:
        if is_production_mode():
            raise HTTPException(status_code=401, detail="Нэвтрэх шаардлагатай!")
        return
    if user.get("role") == "client":
        if resource_page_id and str(resource_page_id) != str(user.get("page_id")):
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
