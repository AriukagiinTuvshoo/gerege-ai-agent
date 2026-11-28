import os
import hmac
import hashlib
import logging
from typing import Dict, Any, List, Optional, Set
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


def resolve_tenant_login_role(
    client_page: Dict[str, Any],
    requested_role: Optional[str] = None,
    auth_type: str = "client",
) -> str:
    """
    Server-authoritative role resolution for tenant logins (P0 Security Fix).
    Prevents client-side privilege escalation:
    - Never trusts user-supplied 'role' in request payloads to grant elevated permissions.
    - Magic link tokens are strictly scoped to 'client' role.
    - Client logins default strictly to 'client' role.
    - Only server-side verified mappings (e.g. client_page['assigned_role']) can grant other tenant roles.
    """
    if auth_type == "magic":
        return "client"

    server_assigned = str(client_page.get("assigned_role") or "").strip().lower()
    if server_assigned in TENANT_SCOPED_ROLES:
        return server_assigned

    return "client"


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


# ---------------------------------------------------------------------------
# CORS origin allowlist (finding SEC-01 / B-02)
# ---------------------------------------------------------------------------
_DEV_DEFAULT_ORIGINS = (
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)


def resolve_allowed_origins() -> List[str]:
    """
    CORS-д зөвшөөрөгдөх origin-уудын жагсаалтыг буцаана.

    Яагаад: `allow_origins=["*"]` ба `allow_credentials=True` хослолд Starlette нь
    дуудагчийн `Origin`-ыг шууд буцаадаг ("reflect") тул дурын вэбсайт нэвтэрсэн
    хэрэглэгчийн cookie-той хүсэлт илгээж хариуг уншиж чаддаг байсан (SEC-01).

    Дүрэм:
      * `ALLOWED_ORIGINS` (таслалаар тусгаарласан) байвал түүнийг л ашиглана.
      * Wildcard (`*`) зөвхөн production БИШ үед зөвшөөрөгдөнө.
      * Production/strict горимд жагсаалт хоосон бол аюулгүй default (өөрөө) —
        хэзээ ч `*` руу буцахгүй (fail-closed).
      * `null` origin-ыг хэзээ ч зөвшөөрөхгүй.
    """
    raw = os.getenv("ALLOWED_ORIGINS", "").strip()
    prod = is_production_mode()

    if raw:
        origins = [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
        cleaned: List[str] = []
        for origin in origins:
            if origin == "*":
                # Never permit credentialed wildcard, in any mode.
                continue
            if origin.lower() == "null":
                continue
            if origin not in cleaned:
                cleaned.append(origin)
        if cleaned:
            return cleaned
    elif not prod:
        return list(_DEV_DEFAULT_ORIGINS)

    # Production (or an unusable config): bind to the app's own origins only.
    self_origin = os.getenv("APP_ORIGIN", "").strip().rstrip("/")
    if self_origin and self_origin.lower() != "null":
        return [self_origin]
    return []


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

    Phase 45 (F-44-A): this guard **fails closed on a missing tenant**. The previous
    condition was

        ``if not user_pid or (resource_page_id and str(resource_page_id) != str(user_pid))``

    whose second clause is falsy when ``resource_page_id`` is ``None`` or ``""`` - so a
    resource with no tenant of its own was **allowed to every tenant-scoped user**:

        resource_page_id='pageA' -> ALLOWED      (correct)
        resource_page_id='pageB' -> DENIED 403   (correct)
        resource_page_id=None    -> ALLOWED      (WRONG - the bug)
        resource_page_id=''      -> ALLOWED      (WRONG - the bug)

    That was reachable in principle because ``registrations.page_id`` is nullable. It is
    no longer reachable after Phase 45 made the column ``NOT NULL`` (migration 0008), but
    a guard that depends on a schema invariant somewhere else is one migration away from
    being wrong again. The rule now lives here, where the decision is made: a resource
    that cannot name its tenant cannot be proven to belong to the caller, so it is denied.

    Admins are unaffected - they are allowed across tenants by design, and the tenant
    check below never applied to them either.
    """
    if not user:
        if require_auth or is_production_mode():
            raise HTTPException(status_code=401, detail="Нэвтрэх шаардлагатай! (Unauthorized)")
        return
    role = str(user.get("role") or "").strip().lower()
    if not is_admin_role(role):
        user_pid = str(user.get("page_id") or "").strip()
        resource_pid = "" if resource_page_id is None else str(resource_page_id).strip()
        # Missing owner on either side is a denial, not an exemption. `not resource_pid`
        # comes first so the reason is explicit rather than implied by string inequality.
        if not user_pid or not resource_pid or resource_pid != user_pid:
            raise HTTPException(
                status_code=403,
                detail="Энэхүү бүртгэл танай салбарт хамаарахгүй байна! (IDOR Forbidden)",
            )


#: Phase 45 (F-44-B). The string that shipped as the fallback for `META_VERIFY_TOKEN`,
#: the `pages.verify_token` column default and the request-body default. It is in this
#: repository, in every published install and in the migrations, so it is a *published*
#: value: treating it as a secret is the defect, not an oversight to be documented.
PUBLIC_VERIFY_TOKEN_PLACEHOLDER = "agent_verify_secret_token_123"


def meta_verify_token_is_placeholder(token: Optional[str]) -> bool:
    """True when ``token`` carries no secrecy at all.

    Two shapes count: the published default itself, and anything a template would leave
    behind (`changeme`, `<generate: …>`, `your-…`). Comparison is case-insensitive and
    whitespace-trimmed, because those are the variations an operator actually types.
    """
    value = str(token or "").strip()
    if not value:
        return True
    lowered = value.lower()
    if lowered == PUBLIC_VERIFY_TOKEN_PLACEHOLDER:
        return True
    placeholders = ("changeme", "change_me", "placeholder", "your-", "<generate", "todo", "xxx")
    return any(marker in lowered for marker in placeholders)


def meta_verify_token_is_usable(token: Optional[str]) -> bool:
    """Whether the Meta handshake may proceed with ``token`` as the expected value.

    Phase 45 (F-44-B). The GET `/webhook` handler used

        ``expected_token = os.getenv("META_VERIFY_TOKEN", "agent_verify_secret_token_123")``

    so a deployment that never set the variable completed Meta's subscription handshake
    with a value that is printed in this repository. Phase 44 measured it: under
    ``ENV=production`` with the variable unset, the endpoint still accepted the public
    string.

    The rule is now the same one `_verify_admin_password` already applies to the admin
    password: in production (or `STRICT_SECURITY`), an unset, empty or placeholder value
    is **not usable**, and the caller must fail closed. Outside production the published
    default stays usable, because local development and the test suite rely on it and
    nothing is exposed there.

    This function decides only *whether a value may be used*. It never returns the value
    and never logs it, so it cannot leak the configured secret.
    """
    value = str(token or "").strip()
    if not value:
        return False
    if is_production_mode() and meta_verify_token_is_placeholder(value):
        return False
    return True


#: Phase 51 (F-51-5). The fallback `executive_bot_service.handle_owner_command` used for
#: `VERIFY_TOKEN` — the secret in a Telegram `/start <secret>` message that decides WHO
#: receives the executive reports. It is published in this repository and it appeared in no
#: template at all: not `.env.example`, not `docker-compose.prod.yml`, not
#: `docker-compose.staging.yml`, not `docs/`. `grep -rn GEREGE_VERIFY_2026` matched exactly
#: one line in the whole tree — the default itself — so no operator was ever told it existed,
#: let alone told to replace it.
PUBLIC_OWNER_COMMAND_SECRET = "GEREGE_VERIFY_2026"


def owner_command_secret_is_usable(value: Optional[str]) -> bool:
    """Whether ``value`` may serve as the expected Telegram ``/start <secret>`` owner secret.

    Phase 51 (F-51-5). The handler used

        expected_secret = os.getenv("VERIFY_TOKEN", "GEREGE_VERIFY_2026").strip()
        ...
        if not existing_mgr_id or str(existing_mgr_id) == str(chat_id) or provided_secret == expected_secret:
            os.environ["TELEGRAM_MANAGER_CHAT_ID"] = str(chat_id)
            database.update_page_telegram_settings(..., manager_chat_id=str(chat_id))

    so anybody who sent the bot `/start GEREGE_VERIFY_2026` became the owner: the daily
    executive report (revenue, invoices, cargo, customers) was redirected to their chat, the
    on-demand commands `/today`, `/report`, `/qpay` and `/cargo` answered to them, and the
    real owner was locked out by the guard that protects a registered manager. A Telegram bot
    is public by username, so the attacker needs no access to this deployment — only the
    string that is in this file. With `VERIFY_TOKEN` set but empty the hole was wider still:
    `provided_secret == expected_secret` became `"" == ""`, so a bare `/start` from a stranger
    took ownership.

    This is the third instance of one defect in this codebase — a value published in the
    repository being accepted as a credential. F-44-B closed it for `META_VERIFY_TOKEN`
    (the Meta handshake) and F-49-1 for the ManyChat webhook; both were found by following a
    published default to the place it was compared. This one was found the other way round,
    by listing every environment variable the code reads that no template documents.

    Unlike :func:`meta_verify_token_is_usable` this refuses the published value in **every**
    environment, not only in production. That function stays permissive in development
    because sixteen suites authenticate with the published Meta default and nothing is
    exposed by it there; nothing depends on this one (no test and no template ever named it),
    and development permissiveness is exactly how a published literal reaches production
    unnoticed. An operator who wants secret-based re-registration generates a value:

        VERIFY_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

    With no usable secret the flow degrades to the safe one: a registered owner keeps working,
    a stranger is refused, and a first `/start` still claims an unregistered slot — which is
    the documented onboarding behaviour and is unchanged here.

    Decides only *whether a value may be used*. It never returns the value and never logs it.
    """
    candidate = str(value or "").strip()
    if not candidate:
        return False
    if candidate.lower() == PUBLIC_OWNER_COMMAND_SECRET.lower():
        return False
    # Also refuses the other published literal (an operator who copied the Meta default into
    # VERIFY_TOKEN) and the unfilled-template shapes.
    return not meta_verify_token_is_placeholder(candidate)


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


def usable_webhook_secret(value: Optional[str]) -> str:
    """``value`` if it may serve as an *expected* webhook secret, else ``""``.

    Phase 49 (F-49-1). ``verify_manychat_webhook_secret`` used to accept any non-empty
    string as the expected secret, including the page-level ``verify_token`` whose default
    is ``agent_verify_secret_token_123`` — a value printed in this repository, in migration
    ``0001``, in ``core/models.py`` and in ``dashboard.html``. Measured against a running
    instance (development, ``WEBHOOK_FAIL_CLOSED=0``, no ``MANYCHAT_WEBHOOK_SECRET``):

        POST /api/manychat  X-ManyChat-Secret: agent_verify_secret_token_123  -> 200
        POST /api/manychat  X-ManyChat-Secret: definitely-not-the-token       -> 403

    so the published string was a *working credential* for a webhook that writes into the
    CRM. Production was not protected either: the fail-closed branch below only runs when
    ``expected`` is **empty**, and a placeholder default is not empty, so the comparison
    happily succeeded. Two defects, one cause — a published value being treated as a
    secret, exactly what F-44-B already established for ``META_VERIFY_TOKEN``.

    The rule is now the same one: ``meta_verify_token_is_usable`` decides, so an unset,
    empty or placeholder candidate is not a secret and the caller falls through to the
    fail-closed path. Development keeps accepting the published default (the suite and
    local runs depend on it and nothing is exposed there), production does not.

    Returns the value rather than a boolean because the caller needs it for
    ``hmac.compare_digest``; it never logs it.
    """
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if not meta_verify_token_is_usable(candidate):
        return ""
    return candidate


def verify_manychat_webhook_secret(request: Request, page_id: Optional[str] = None) -> bool:
    """
    ManyChat webhook secret / token шалгалт.
    Fail-closed горимд MANYCHAT_WEBHOOK_SECRET эсвэл тухайн салбарын verify_token-той тулгаж шалгана.

    Phase 49 (F-49-1): neither source is trusted as a secret until
    ``usable_webhook_secret`` accepts it, so the published ``pages.verify_token`` default
    can no longer authenticate a webhook in production. A rejected candidate is treated as
    *not configured*, which routes to the existing fail-closed branch below rather than to
    a comparison against a value that is in this repository.
    """
    env_candidate = os.getenv("MANYCHAT_WEBHOOK_SECRET", "").strip()
    expected = usable_webhook_secret(env_candidate)
    # Only for the diagnosis below: a candidate existed but was refused, which is a
    # different operator error from never configuring one. The value itself is never
    # logged or returned.
    refused_candidate = bool(env_candidate)
    if not expected and page_id:
        page_cfg = database.get_page(page_id)
        page_candidate = str((page_cfg or {}).get("verify_token") or "").strip()
        refused_candidate = refused_candidate or bool(page_candidate)
        expected = usable_webhook_secret(page_candidate)

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
            if refused_candidate:
                logger.error(
                    "ManyChat webhook fail-closed: the configured secret is empty or a "
                    "published placeholder, so it was refused (set MANYCHAT_WEBHOOK_SECRET "
                    "or a per-page verify_token to a generated value)"
                )
            else:
                logger.error("ManyChat webhook fail-closed: MANYCHAT_WEBHOOK_SECRET is not configured")
            return False
        return True

    if not header_secret:
        return False

    return hmac.compare_digest(header_secret, expected)


# ---------------------------------------------------------------------------
# Security response headers (finding SEC-03 / P2-04)
# ---------------------------------------------------------------------------
#: Third-party origins the dashboard actually loads. Kept explicit rather than a
#: wildcard: a CDN compromise is the exact scenario CSP is meant to bound, so the policy
#: only names the hosts the product really uses. If an asset is added to the templates,
#: add its origin here or the browser will block it.
CSP_SCRIPT_SRC = (
    "'self'",
    "https://cdn.tailwindcss.com",
    "https://cdnjs.cloudflare.com",
    "https://cdn.jsdelivr.net",
    "https://unpkg.com",
)
CSP_STYLE_SRC = (
    "'self'",
    "https://cdn.tailwindcss.com",
    "https://cdnjs.cloudflare.com",
    "https://fonts.googleapis.com",
)
CSP_FONT_SRC = ("'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:")
CSP_IMG_SRC = ("'self'", "data:", "blob:", "https:")
CSP_CONNECT_SRC = ("'self'",)
#: Nothing is embedded in an iframe today — `docs.google.com` and `sheets.new` in
#: `dashboard.html` are plain navigation links, which CSP does not govern. If a widget is
#: ever embedded, add its origin here.
CSP_FRAME_SRC = ("'none'",)


def build_content_security_policy() -> str:
    """
    Build the Content-Security-Policy header value.

    Honest note on `'unsafe-inline'` and `'unsafe-eval'`: `dashboard.html` (a single
    310 kB file) uses 118 inline `onclick=` handlers and four inline `<script>` blocks, and
    `cdn.tailwindcss.com` compiles CSS in the browser at runtime, which requires
    `eval`. A policy without these directives would break the entire dashboard, so they
    are present for now.

    That makes this policy a **partial** mitigation, not a full one: it still removes the
    ability to load script from an arbitrary attacker-controlled origin, and it bounds
    `object-src`, `base-uri`, `frame-ancestors` and form targets, which is where most
    injected-markup attacks start. It does *not* stop an injected inline handler from
    running. Removing the inline handlers is tracked separately as frontend work
    (`docs/audit/ROADMAP.md`); only then can `'unsafe-inline'` be dropped for a nonce.

    `'unsafe-eval'` is granted only for the Tailwind CDN; it is the price of runtime
    compilation, and self-hosting a compiled stylesheet would let it be removed.
    """
    script_src = tuple(CSP_SCRIPT_SRC) + ("'unsafe-inline'", "'unsafe-eval'")
    directives = {
        "default-src": ("'self'",),
        "script-src": script_src,
        "style-src": tuple(CSP_STYLE_SRC) + ("'unsafe-inline'",),
        "img-src": CSP_IMG_SRC,
        "font-src": CSP_FONT_SRC,
        "connect-src": CSP_CONNECT_SRC,
        "frame-src": CSP_FRAME_SRC,
        "object-src": ("'none'",),
        "base-uri": ("'self'",),
        "form-action": ("'self'",),
        "frame-ancestors": ("'none'",),
    }
    return "; ".join(f"{name} {' '.join(sources)}" for name, sources in directives.items())


def build_security_headers() -> Dict[str, str]:
    """
    Response headers applied to every response, success or error.

    HSTS is emitted **only** in production: sending it from a local HTTP dev server would
    pin `localhost` to HTTPS in the developer's browser for a year and is a well-known way
    to break a workstation. `X-Frame-Options` remains alongside the CSP
    `frame-ancestors` directive because older browsers do not implement the latter.
    """
    headers: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": build_content_security_policy(),
    }
    if is_production_mode():
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers
