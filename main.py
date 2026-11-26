import os
import io
import json
import time
import hmac
import hashlib
import logging
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from fastapi import FastAPI, Request, Response, BackgroundTasks, Query, UploadFile, File, Form, Header, Cookie, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
# P0-01 (B-01): every route builds an explicit JSONResponse, so `default_response_class`
# alone is not enough. Aliasing the response class makes all 50+ call sites driver-safe
# (datetime/Decimal/UUID/bytes) without touching each handler.
from core.serialization import SafeJSONResponse, SafeJSONResponse as JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import httpx

import database
import agent
import knowledge_base
import sheets_service
import fintech_service
import cargo_service
import executive_bot_service
import retention_service
import appointment_service
from core import security as core_security
from core import rate_limit as core_rate_limit
from core import login_identity as core_login_identity
from core import secret_guard as core_secret_guard
from core.pinned_http import download_remote_image
from core.monitoring import telemetry
from routers import system_router, automation_router

load_dotenv(override=True)

# Өгөгдлийн санг эхлүүлэх
database.init_db()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai_agent_app")

async def executive_scheduler_loop():
    """Өглөө бүр товлосон цагт өдрийн тайлан илгээх болон 15 минут тутамд автомат сэргээгч шалгах цикл"""
    logger.info("Executive Daily Briefing & Retention scheduler loop started.")
    last_sent_date = {}  # page_id -> date_str
    loop_count = 0
    while True:
        try:
            now = datetime.now()
            today_str = now.strftime("%Y-%m-%d")
            current_hm = now.strftime("%H:%M")

            pages = database.get_all_pages()
            for p in pages:
                pid = p.get("page_id")
                if not pid:
                    continue
                enabled = p.get("daily_report_enabled", 1)
                target_time = p.get("daily_report_time", "08:30")

                if enabled and current_hm == target_time:
                    if last_sent_date.get(pid) != today_str:
                        logger.info(f"Triggering scheduled daily executive report for page {pid} at {current_hm}")
                        res = await executive_bot_service.send_executive_report(page_id=pid)
                        logger.info(f"Scheduled report sent for {pid}: {res}")
                        last_sent_date[pid] = today_str

            # 15 минут тутамд автомат хаягдсан чат болон retention сэргээгчийг шалгах (loop_count % 20 == 0)
            loop_count += 1
            if loop_count % 20 == 0:
                await retention_service.run_automated_retention_checks()

            # Цаг захиалгын 2 цагийн өмнөх сануулгыг шалгаж илгээх
            await appointment_service.check_and_dispatch_appointment_reminders()

        except Exception as e:
            logger.error(f"Executive & Retention scheduler error: {e}")
        await asyncio.sleep(45)

#: Phase 49 (F-48A-3). What THIS process actually did with its inline scheduler, recorded
#: by `lifespan`. `/api/admin/worker/health` reports this instead of quoting
#: `DISABLE_INLINE_SCHEDULER`, because the variable states what an operator asked for while
#: this states what happened — and the two can disagree: `main.py` re-runs
#: `load_dotenv(override=True)` inside `/api/health`, so the environment of a long-running
#: process can change after startup without the scheduler task changing (F-48A-4).
#: `None` means the lifespan has not run (a router mounted in a test app, for example).
INLINE_SCHEDULER_STARTED: Optional[bool] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global INLINE_SCHEDULER_STARTED
    # E-02 Phase 4.1: validate BEFORE serving. In production a missing, blank or too-short
    # E02_ACCOUNT_KEY_SECRET raises here and the process exits, instead of logging a warning
    # and silently running with account-level throttling disabled. Development and tests are
    # unaffected. The secret value is never logged.
    core_rate_limit.validate_account_key_secret()
    core_rate_limit.refresh_account_key_secret()
    # E-02 Phase 6, R11: a production process must not serve with a per-process counter.
    # Raises RateLimitStoreUnavailable, which aborts startup (uvicorn exits non-zero) rather
    # than degrading to `limit x workers`. Development/tests are unaffected.
    core_rate_limit.validate_store_for_startup()
    # Phase 36: refuse to start with a pool configuration that cannot fit the server.
    # Phase 35 found 2x(10+20) + 30 = 90 against max_connections=100 with no guard, so an
    # over-subscribed deployment surfaced as random connection errors under load instead
    # of a clear startup failure. `--workers` is not visible from inside a worker process,
    # so it is passed explicitly through UVICORN_WORKERS (compose/Dockerfile set it).
    try:
        from core.db_engine import enforce_connection_budget
        enforce_connection_budget(api_processes=int(os.getenv("UVICORN_WORKERS", "1")))
    except RuntimeError:
        raise
    except Exception as exc:  # never let the guard itself block startup
        logger.warning(f"connection budget check skipped: {exc}")

    # Phase 45 (F-44-F): every required production secret, checked the way the account key
    # already was. Phase 44 found this rule existed for ONE credential and was documentation
    # for the rest - which is how a deployment could serve traffic with `META_VERIFY_TOKEN`
    # falling back to a value published in this repository.
    #
    # Deliberately LAST among the startup guards. Each guard above names a specific
    # misconfiguration ("REDIS_URL is required when running in production", "E02_ACCOUNT_
    # KEY_SECRET is too short"), and those messages are what an operator needs. Placing a
    # broad secret sweep first made it mask them: measured, four existing suites asserted
    # that a missing REDIS_URL is named in the failure, and instead received "META_APP_SECRET:
    # missing". A guard must not hide a more specific diagnosis of the same failure. In
    # production an unusable secret still raises and the process still exits; development
    # logs a warning and continues. Names and reasons only - never a value.
    core_secret_guard.validate_production_secrets()

    scheduler_task = None
    INLINE_SCHEDULER_STARTED = os.getenv("DISABLE_INLINE_SCHEDULER", "0") != "1"
    if INLINE_SCHEDULER_STARTED:
        scheduler_task = asyncio.create_task(executive_scheduler_loop())
    yield
    if scheduler_task:
        scheduler_task.cancel()
        try:
            await scheduler_task
        except asyncio.CancelledError:
            pass
    try:
        from core.db_engine import dispose_shared_engine
        dispose_shared_engine()
    except Exception as e:
        logger.warning(f"Database engine dispose warning: {e}")

app = FastAPI(
    title="Omnichannel AI Chatbot Agent & Multi-Tenant CRM Platform",
    lifespan=lifespan,
    # P0-01 (B-01): normalise driver values (datetime/Decimal/...) before JSON encoding.
    # FastAPI only runs `jsonable_encoder` for implicit `dict` returns; every explicit
    # `JSONResponse(...)` bypassed it and raised `TypeError: Object of type datetime is
    # not JSON serializable` on PostgreSQL, surfacing as HTTP 500.
    default_response_class=SafeJSONResponse,
)

app.include_router(system_router.router)
app.include_router(automation_router.router)

@app.middleware("http")
async def telemetry_and_error_tracking_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or os.urandom(8).hex()
    t0 = time.perf_counter()
    try:
        resp = await call_next(request)
        dur = (time.perf_counter() - t0) * 1000.0
        telemetry.record_request(request.url.path, request.method, resp.status_code, dur, request_id=req_id)
        resp.headers["X-Request-ID"] = req_id
        # SEC-03: one source of truth for the header set, shared with the error path below
        # so the two cannot drift apart.
        for header, value in core_security.build_security_headers().items():
            resp.headers[header] = value
        return resp
    except Exception as exc:
        dur = (time.perf_counter() - t0) * 1000.0
        telemetry.record_request(request.url.path, request.method, 500, dur, error_detail=str(exc), request_id=req_id)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": req_id},
            headers={
                "X-Request-ID": req_id,
                **core_security.build_security_headers(),
            },
        )

os.makedirs("static/qrcodes", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# SEC-01 (B-02): explicit origin allowlist. `allow_origins=["*"]` combined with
# `allow_credentials=True` makes Starlette reflect the caller's Origin, which lets any
# website read authenticated responses. See core_security.resolve_allowed_origins().
_ALLOWED_ORIGINS = core_security.resolve_allowed_origins()
if not _ALLOWED_ORIGINS and core_security.is_production_mode():
    logger.error(
        "CORS allowlist is empty in production. Set ALLOWED_ORIGINS "
        "(e.g. https://app.example.mn). Cross-origin browsers calls will be rejected."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-ManyChat-Secret", "X-Webhook-Secret"],
)

# Phase 45 (F-44-B): no fallback. An unset variable is now an empty string, which
# `core_security.meta_verify_token_is_usable` rejects in production instead of
# silently substituting a value that is published in this repository.
META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "").strip()
META_PAGE_ACCESS_TOKEN = os.getenv("META_PAGE_ACCESS_TOKEN", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_MANAGER_CHAT_ID = os.getenv("TELEGRAM_MANAGER_CHAT_ID", "")

# Webhook deduplication & Login rate-limiting state
#: How long a processed Meta `mid` is remembered (SEC-04). Meta retries a failed
#: delivery for up to ~7 days; 14 days is safely beyond that and keeps the table bounded
#: because `claim_notification_lock()` deletes expired rows as it goes.
_WEBHOOK_DEDUP_TTL_SECONDS = 14 * 24 * 60 * 60
# SEC-07: login attempts are counted in a shared store (Redis when configured), not in
# a process-local dict, so `--workers 2` no longer doubles the effective limit and a
# deploy no longer resets it. See `core/rate_limit.py`.

# -------------------------------------------------------------
# 1. ТУСЛАХ ИЛГЭЭГЧҮҮД (Meta, Telegram, Manager Notification)
# -------------------------------------------------------------
async def send_meta_message(recipient_id: str, text: str, page_token: Optional[str] = None):
    """Facebook Messenger / Instagram Direct руу тухайн хуудасны токеноор хариу илгээх"""
    load_dotenv(override=True)
    token = page_token or os.getenv("META_PAGE_ACCESS_TOKEN", "").strip()
    if not token or not text:
        logger.warning(f"send_meta_message skipped: token_exists={bool(token)}, text_len={len(text)}")
        return
    graph_ver = os.getenv("META_GRAPH_API_VERSION", "v22.0")
    url = f"https://graph.facebook.com/{graph_ver}/me/messages?access_token={token}"
    payload = {
        "recipient": {"id": recipient_id},
        "messaging_type": "RESPONSE",
        "message": {"text": text}
    }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload, timeout=10.0)
            if res.status_code != 200:
                logger.error(f"Meta Graph API error [{res.status_code}]: {res.text}")
            else:
                logger.info(f"Meta Graph API status: {res.status_code} (Sent to {recipient_id})")
    except Exception as e:
        logger.error(f"Meta илгээх алдаа: {e}")

async def send_telegram_message(chat_id: Any, text: str, page_id: Optional[str] = None):
    """Telegram хэрэглэгч рүү хариу илгээх (Markdown дэмжлэгтэй)"""
    page = database.get_page(page_id) if page_id else {}
    bot_token = (page.get("telegram_bot_token") if page else None) or os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not bot_token or not text:
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload, timeout=10.0)
            if res.status_code != 200:
                payload.pop("parse_mode", None)
                await client.post(url, json=payload, timeout=10.0)
            logger.info(f"Telegram status: {res.status_code}")
    except Exception as e:
        logger.error(f"Telegram илгээх алдаа: {e}")

async def notify_manager_telegram(lead_info: Dict[str, Any]):
    """Шинэ бүртгэл үүсмэгц Менежерийн Telegram руу түргэн мэдэгдэл өгөх"""
    manager_id = os.getenv("TELEGRAM_MANAGER_CHAT_ID", "").strip()
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not manager_id or not bot_token:
        return
    
    msg = (
        f"🚨 ШИНЭ БҮРТГЭЛ ИРЛЭЭ! (Lead #{lead_info.get('id')})\n"
        f"🏢 Хуудас: {lead_info.get('service', 'Ерөнхий')}\n"
        f"👤 Нэр: {lead_info.get('name')}\n"
        f"📱 Утас: {lead_info.get('phone')}\n"
        f"🌐 Суваг: {lead_info.get('channel', 'web')}\n"
        f"⏰ Огноо: {lead_info.get('created_at', 'Яг одоо')}"
    )
    await send_telegram_message(manager_id, msg)

# -------------------------------------------------------------
# 2. АЮУЛГҮЙ БАЙДАЛ БА СЕСС (RBAC Dependency)
# -------------------------------------------------------------
async def get_current_user(
    request: Optional[Request] = None,
    authorization: Optional[str] = None,
    session_token_cookie: Optional[str] = None,
    token: Optional[str] = None,
    auth_token: Optional[str] = None,
    client_token: Optional[str] = None,
    **kwargs
) -> Optional[Dict[str, Any]]:
    """Хүсэлтээс нэвтэрсэн хэрэглэгчийн эрх болон хуудасны ID-г авах (Bulletproof extraction)"""
    token_str = None
    
    # 1. Хэрэв request дамжуулсан бол request-ээс шүүх
    if request:
        auth_h = request.headers.get("Authorization", "")
        if auth_h.startswith("Bearer "):
            token_str = auth_h[7:].strip()
        if not token_str:
            c = request.cookies.get("session_token")
            if c:
                token_str = str(c).strip()
        if not token_str:
            q = request.query_params.get("token") or request.query_params.get("auth_token") or request.query_params.get("client_token")
            if q:
                token_str = str(q).strip()

    # 2. Шууд аргументээр ирсэн бол
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

    if not token_str:
        return None

    # Сессийг баазаас шалгах
    session = database.get_session(token_str)
    if session:
        return session

    # Хэрэв шууд Magic Token дамжуулсан бол
    client_page = database.authenticate_client(token_str)
    if client_page:
        sess_token = database.create_session(role="client", page_id=client_page["page_id"])
        return database.get_session(sess_token)

    return None

# -------------------------------------------------------------
# 3. НЭВТРЭЛТ БА ЭРХИЙН УДИРДЛАГА (Auth API)
# -------------------------------------------------------------
@app.post("/api/auth/login")
async def auth_login(payload: Dict[str, Any], request: Request, response: Response):
    # E-02 Phase 3: one resolver decides the client IP. `client_ip` is what gets stored in
    # audit logs and on the session row, so it must be the same value the limiter keys on —
    # previously it was `request.client.host` while the limiter used a different header
    # parse, so an attacker could appear as two different clients in one request.
    client_ip = core_rate_limit.resolve_client_ip(request)
    limiter = core_rate_limit.get_limiter()
    limit_hit = limiter.check(
        "auth_login", client_ip, *core_rate_limit.DEFAULT_LIMITS["auth_login"]
    )
    if not limit_hit["allowed"]:
        return JSONResponse(
            {"success": False, "error": "Хэт олон удаа буруу оролдлого хийлээ. 1 минутын дараа дахин оролдоно уу."},
            status_code=429,
            headers={"Retry-After": str(limit_hit["retry_after"])},
        )

    login_type = payload.get("type", "admin")  # 'admin', 'client', 'magic'
    
    if login_type == "admin":
        password = str(payload.get("password", "")).strip()
        if database.authenticate_admin(password):
            token = database.create_session(role="admin", page_id=None, ip_address=client_ip)
            response.set_cookie(
                key="session_token",
                value=token,
                max_age=86400 * 3,
                httponly=True,
                secure=core_security.is_production_mode(),
                samesite="lax",
            )
            database.record_audit_log("auth.login.success", actor_role="admin", ip_address=client_ip)
            return {
                "success": True,
                "token": token,
                "role": "admin",
                "page_id": None,
                "page_name": "👑 Супер Админ"
            }
        database.record_audit_log("auth.login.failed", actor_role="admin", ip_address=client_ip)
        return JSONResponse({"success": False, "error": "Админы нууц үг буруу байна!"}, status_code=401)

    elif login_type in ["client", "magic"]:
        identifier = str(payload.get("identifier") or payload.get("username") or payload.get("token") or "").strip()
        password = payload.get("password")

        # E-02 Phase 4/4.1: account-level throttle, independent of the per-IP limit above.
        #
        # Checked BEFORE authentication so a burned budget costs the attacker no password
        # verification, and so a throttled account cannot be told from a throttled unknown one
        # by response time.
        #
        # Phase 4.1 changes, all of them correctness fixes rather than new policy:
        #   * the identity is the account's canonical page_id, resolved from the database, so
        #     the username and page_id aliases of one account share one budget;
        #   * the counter is incremented here, atomically with its expiry, and admitted
        #     attempts consume a slot. A failed password keeps that slot; a successful one
        #     refunds exactly that slot. Nothing deletes the counter, so a failure recorded
        #     concurrently with a success is never erased.
        account_hit = core_rate_limit.check_account_login_allowed(identifier)
        if not account_hit["allowed"]:
            # E-02 Phase 6, R14: distinguish "throttled" from "throttle could not be enforced"
            # in the audit trail, but NOT in the response. Both are 429 with Retry-After and the
            # same body, so an attacker cannot learn whether the store is down — that knowledge
            # would be an invitation to attack during an outage.
            if account_hit.get("store_failed"):
                database.record_audit_log(
                    "auth.login.throttle_store_failed", actor_role="client", ip_address=client_ip
                )
            else:
                database.record_audit_log(
                    "auth.login.account_throttled", actor_role="client", ip_address=client_ip
                )
            return JSONResponse(
                {"success": False, "error": core_rate_limit.ACCOUNT_THROTTLE_MESSAGE},
                status_code=429,
                headers={"Retry-After": str(account_hit["retry_after"])},
            )

        client_page, err_msg = database.authenticate_client_detailed(identifier, password)
        if client_page:
            # Refund only the slot this successful login consumed. The IP counter is
            # deliberately untouched, and residual failures from earlier mistyping remain
            # until the window expires — see clear_account_failures_on_success.
            # The admission token is passed back so the refund can prove it is reversing the
            # exact slot this request consumed, in the exact window it consumed it. E-02
            # Phase 4.2: without it, a login whose password check outlived its window would
            # decrement the *next* window's counter and erase someone else's failure.
            core_rate_limit.clear_account_failures_on_success(
                account_hit["identity"],
                canonical=account_hit["canonical"],
                token=account_hit.get("token"),
            )
            page_id = client_page["page_id"]
            # P0 Fix: Server-authoritative role resolution. User payload 'role' is never trusted.
            resolved_role = core_security.resolve_tenant_login_role(
                client_page=client_page,
                requested_role=payload.get("role"),
                auth_type=login_type,
            )
            token = database.create_session(role=resolved_role, page_id=page_id, ip_address=client_ip)
            response.set_cookie(
                key="session_token",
                value=token,
                max_age=86400 * 3,
                httponly=True,
                secure=core_security.is_production_mode(),
                samesite="lax",
            )
            database.record_audit_log("auth.login.success", page_id=page_id, actor_role=resolved_role, actor_id=identifier, ip_address=client_ip)
            return {
                "success": True,
                "token": token,
                "role": resolved_role,
                "page_id": page_id,
                "page_name": client_page.get("name", "Харилцагчийн Хуудас"),
                "has_custom_key": bool(client_page.get("gemini_api_key")),
                "tokens_used": client_page.get("tokens_used", 0),
                "monthly_token_limit": client_page.get("monthly_token_limit", 100000)
            }
        # The slot this attempt consumed at admission stays counted as a failure: a wrong
        # password is exactly what the counter is for.
        core_rate_limit.record_account_failure(account_hit["identity"])

        # E-02 Phase 4: uniform failure. `err_msg` distinguishes "no such tenant" from
        # "wrong password" from "this tenant has no password set" from "no password sent" —
        # four different oracles in one string, and two of them also name the account.
        # It is kept for the server-side audit trail below, never for the client.
        database.record_audit_log("auth.login.failed", actor_role="client", actor_id=identifier, ip_address=client_ip)

        return JSONResponse(
            {"success": False, "error": "Харилцагчийн нэр, нууц үг эсвэл холбоос буруу байна!"},
            status_code=401,
        )

    return JSONResponse({"success": False, "error": "Үл мэдэгдэх төрөл"}, status_code=400)

@app.get("/api/auth/me")
async def auth_me(request: Request):
    auth_header = request.headers.get("Authorization")
    cookie_token = request.cookies.get("session_token")
    query_token = request.query_params.get("token") or request.query_params.get("client_token")
    
    user = await get_current_user(
        authorization=auth_header,
        session_token_cookie=cookie_token,
        token=query_token
    )
    if not user:
        return JSONResponse({"authenticated": False, "role": "guest"})

    page_data = None
    if user.get("page_id"):
        page_data = database.get_page(user["page_id"], mask_secrets=True)

    return JSONResponse({
        "authenticated": True,
        "token": user.get("session_token"),
        "role": user.get("role"),
        "page_id": user.get("page_id"),
        "page_name": page_data.get("name") if page_data else "👑 Супер Админ",
        "page_info": page_data
    })

@app.post("/api/auth/logout")
async def auth_logout(request: Request, response: Response):
    token = request.cookies.get("session_token") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        database.revoke_session(token)
        database.delete_session(token)
    response.delete_cookie("session_token")
    return {"success": True, "message": "Амжилттай гарлаа"}

# -------------------------------------------------------------
# 4. FACEBOOK & INSTAGRAM WEBHOOK (Multi-Tenant Routing)
# -------------------------------------------------------------
@app.get("/webhook")
async def verify_meta_webhook(
    hub_mode: Optional[str] = Query(None, alias="hub.mode"),
    hub_verify_token: Optional[str] = Query(None, alias="hub.verify_token"),
    hub_challenge: Optional[str] = Query(None, alias="hub.challenge")
):
    """Meta subscription handshake.

    Phase 45 (F-44-B). The expected value used to be
    ``os.getenv("META_VERIFY_TOKEN", "agent_verify_secret_token_123")``, so an unset
    variable fell back to a string published in this repository and the handshake
    succeeded anyway. `meta_verify_token_is_usable` now refuses an empty or placeholder
    value in production, which makes the endpoint fail closed there.

    The refusal is logged without the value and answered exactly like a wrong token, so
    the endpoint does not tell an unauthenticated caller whether the deployment is
    misconfigured or merely guessed wrong.
    """
    configured = os.getenv("META_VERIFY_TOKEN", "")
    if not core_security.meta_verify_token_is_usable(configured):
        if core_security.is_production_mode():
            logger.error(
                "Meta webhook fail-closed: META_VERIFY_TOKEN is unset, empty or still the "
                "published placeholder. The subscription handshake is refused in production."
            )
        return Response(content="Verification failed", status_code=403)

    expected_token = configured.strip()
    if hub_mode == "subscribe" and core_security.constant_time_equal(hub_verify_token, expected_token):
        logger.info("Meta Webhook баталгаажлаа!")
        return Response(content=hub_challenge, media_type="text/plain")
    return Response(content="Verification failed", status_code=403)

@app.post("/webhook")
async def meta_webhook_events(request: Request, background_tasks: BackgroundTasks):
    try:
        raw_body = await request.body()
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        if not core_security.verify_meta_webhook_signature(raw_body, sig_header):
            logger.warning("Meta webhook rejected by fail-closed signature check")
            return Response(content="Invalid or missing signature", status_code=403)

        data = json.loads(raw_body.decode("utf-8") or "{}")
        for entry in data.get("entry", []):
            entry_page_id = entry.get("id")
            for messaging_event in entry.get("messaging", []):
                sender_id = messaging_event.get("sender", {}).get("id")
                recipient_id = messaging_event.get("recipient", {}).get("id")
                message = messaging_event.get("message")
                if not message or message.get("is_echo"):
                    continue

                # Тухайн чат аль Facebook Page рүү ирснийг олох
                target_page_id = str(recipient_id or entry_page_id or database.DEFAULT_PAGE_ID)
                page_obj = database.get_page(target_page_id)

                # The tenant must exist before anything is written against it.
                #
                # `messages.page_id`, `session_states.page_id` and the other tenant columns
                # are now foreign keys (P1-06), so an unknown page would fail the whole
                # webhook with a 500 and Meta would retry for days. It must not be created
                # implicitly either: the page access token is not verified yet, so letting
                # an arbitrary sender conjure a tenant row would be a tenant-isolation hole.
                # Unknown pages are dropped with a warning; onboarding goes through the
                # authenticated admin flow.
                if not page_obj:
                    logger.warning(
                        f"Meta webhook for unregistered page {target_page_id!r}; ignoring event"
                    )
                    continue

                page_token = page_obj.get("page_access_token") or os.getenv("META_PAGE_ACCESS_TOKEN", "")

                # Meta webhook retry deduplication by `mid` (SEC-04).
                #
                # This used to be a process-local list. Production runs `--workers 2`
                # plus a separate worker process, so a Meta retry landing on another
                # process was processed twice and the customer got a duplicate reply.
                # The list also evicted the oldest 500 entries once it passed 2 000, so a
                # delayed retry could be re-processed.
                #
                # `claim_notification_lock()` is an atomic INSERT against the
                # `notification_locks` primary key, which works across processes and
                # survives a restart. A TTL bounds growth; Meta retries for up to ~7 days,
                # so the window is set well beyond that.
                mid = message.get("mid")
                if mid:
                    dedup_key = f"meta_mid:{mid}"
                    try:
                        if not database.claim_notification_lock(
                            dedup_key, channel="meta_webhook", ttl_seconds=_WEBHOOK_DEDUP_TTL_SECONDS
                        ):
                            logger.info(f"Duplicate Meta webhook delivery ignored (mid={mid})")
                            continue
                    except Exception:
                        # Fail *open* for availability: a dedup-store outage must not stop
                        # every inbound message. The failure is logged with a traceback so
                        # it is visible, and a duplicate reply is strictly less harmful than
                        # silently dropping a customer's message.
                        logger.exception(
                            f"Webhook dedup unavailable for mid={mid}; processing without dedup"
                        )


                user_text = message.get("text", "")
                attachments = message.get("attachments", [])
                image_bytes = None

                for att in attachments:
                    if att.get("type") == "image":
                        img_url = att.get("payload", {}).get("url")
                        if img_url:
                            # Phase 30: this fetched a URL taken straight from the webhook
                            # body with no scheme, address or redirect validation - the one
                            # genuinely attacker-influenced URL in the codebase. Reproduced:
                            # an unsigned webhook (META_APP_SECRET unset, non-production)
                            # naming http://127.0.0.1:<port>/internal/admin/token caused this
                            # process to GET it. A signed Meta delivery is still only as
                            # trustworthy as the URL Meta was given, so the fetch itself is
                            # what gets constrained, not just the caller.
                            try:
                                fetched = await download_remote_image(
                                    img_url, max_bytes=8 * 1024 * 1024
                                )
                                if fetched is not None:
                                    image_bytes = fetched
                                    logger.info(
                                        f"Image downloaded from Meta: {len(image_bytes)} bytes "
                                        f"(Page: {target_page_id})"
                                    )
                            except Exception as e:
                                # The type only. A URL here can carry a signed query token, and
                                # an error message is what ends up in a log or an alert.
                                logger.error(f"Image download error: {type(e).__name__}")
                        break

                if (user_text or image_bytes) and sender_id:
                    result = await asyncio.to_thread(
                        agent.process_message,
                        text=user_text,
                        image_bytes=image_bytes,
                        sender_id=f"meta_{sender_id}",
                        channel="facebook/instagram",
                        page_id=target_page_id
                    )
                    reply_text = result.get("reply", "")
                    if reply_text:
                        background_tasks.add_task(send_meta_message, sender_id, reply_text, page_token)
                    if result.get("registered") and result.get("reg_info"):
                        background_tasks.add_task(notify_manager_telegram, result["reg_info"])

            for change in entry.get("changes", []):
                field = change.get("field")
                if field in ("feed", "comments"):
                    target_page_id = str(entry_page_id or database.DEFAULT_PAGE_ID)
                    page_obj = database.get_page(target_page_id)
                    page_token = page_obj.get("page_access_token") if page_obj else os.getenv("META_PAGE_ACCESS_TOKEN", "")
                    background_tasks.add_task(process_meta_comment_event, target_page_id, change, page_token)

        return Response(content="EVENT_RECEIVED", status_code=200)
    except Exception as e:
        logger.error(f"Meta webhook алдаа: {e}")
        return Response(content="Error", status_code=500)


def _match_comment_automation(automations: List[Dict[str, Any]], post_id: str, comment_text: str) -> Optional[Dict[str, Any]]:
    text_lower = (comment_text or "").lower()
    for rule in automations:
        if not rule.get("is_active"):
            continue
        rule_post = (rule.get("post_id") or "*").strip()
        if rule_post != "*" and rule_post != str(post_id or ""):
            continue
        kw_raw = (rule.get("keyword_pattern") or "*").strip()
        if kw_raw == "*":
            return rule
        keywords = [k.strip().lower() for k in kw_raw.split(",") if k.strip()]
        if any(k in text_lower for k in keywords):
            return rule
    return None


async def process_meta_comment_event(target_page_id: str, change: Dict[str, Any], page_token: str) -> Optional[Dict[str, Any]]:
    """Facebook (feed) болон Instagram (comments) сэтгэгдэлд автоматаар хариулж DM илгээх"""
    field = change.get("field")
    value = change.get("value") or {}

    if field == "feed":
        if value.get("item") != "comment" or value.get("verb") != "add":
            return None
        comment_id = str(value.get("comment_id") or "").strip()
        post_id = str(value.get("post_id") or "").strip()
        comment_text = str(value.get("message") or "").strip()
        from_id = str((value.get("from") or {}).get("id") or "").strip()
        reply_edge = "comments"
    elif field == "comments":
        comment_id = str(value.get("id") or "").strip()
        post_id = str((value.get("media") or {}).get("id") or "").strip()
        comment_text = str(value.get("text") or "").strip()
        from_id = str((value.get("from") or {}).get("id") or "").strip()
        reply_edge = "replies"
    else:
        return None

    if not comment_id or not comment_text:
        return None
    if from_id and from_id == str(target_page_id):
        return None

    if not database.claim_notification_lock(
        f"comment_reply:{comment_id}",
        page_id=target_page_id,
        channel="meta_comment",
        ttl_seconds=86400,
    ):
        logger.info(f"Duplicate comment webhook skipped: {comment_id}")
        return None

    automations = database.list_comment_automations(page_id=target_page_id, active_only=True)
    matched = _match_comment_automation(automations, post_id, comment_text)
    if not matched:
        return None

    token = page_token or os.getenv("META_PAGE_ACCESS_TOKEN", "")
    if token:
        async with httpx.AsyncClient(timeout=10.0) as client:
            public_reply = (matched.get("public_reply_text") or "").strip()
            if public_reply:
                try:
                    await client.post(
                        f"https://graph.facebook.com/v19.0/{comment_id}/{reply_edge}",
                        params={"access_token": token},
                        json={"message": public_reply},
                    )
                except Exception as exc:
                    logger.warning(f"Public comment reply failed for {comment_id}: {exc}")

            cta_url = (matched.get("cta_url") or "").strip()
            cta_text = (matched.get("cta_button_text") or "").strip()
            dm_text = (matched.get("dm_message_text") or "").strip()
            if cta_url and cta_text:
                dm_payload = {
                    "attachment": {
                        "type": "template",
                        "payload": {
                            "template_type": "button",
                            "text": dm_text,
                            "buttons": [{"type": "web_url", "url": cta_url, "title": cta_text[:20]}],
                        },
                    }
                }
            else:
                dm_payload = {"text": dm_text}

            try:
                await client.post(
                    "https://graph.facebook.com/v19.0/me/messages",
                    params={"access_token": token},
                    json={"recipient": {"comment_id": comment_id}, "message": dm_payload},
                )
            except Exception as exc:
                logger.warning(f"Private DM reply failed for {comment_id}: {exc}")

    database.increment_comment_automation_trigger(matched["id"])
    database.log_message(
        sender_id=f"meta_comment_{from_id or comment_id}",
        channel="facebook/instagram",
        sender_type="bot",
        content=matched.get("dm_message_text", ""),
        page_id=target_page_id,
    )
    return matched


@app.get("/r/{code}")
async def redirect_tracked_link(code: str, request: Request):
    """CTR хяналттай богино холбоос (/r/{code}) — нээлттэй redirect хамгаалалттай"""
    _limit_hit = core_rate_limit.check_request_limit(request, "tracked_redirect")
    if _limit_hit:
        return JSONResponse(
            {"detail": "Хэт олон хүсэлт илгээлээ. Түр хүлээнэ үү."},
            status_code=429,
            headers={"Retry-After": str(_limit_hit["retry_after"])},
        )
    link_data = database.resolve_and_increment_tracked_link(code)
    if not link_data:
        raise HTTPException(status_code=404, detail="Холбоос олдсонгүй")
    target = (link_data.get("target_url") or "").strip()
    lowered = target.lower()
    if lowered.startswith("//") or not (lowered.startswith("https://") or lowered.startswith("http://") or target.startswith("/")):
        raise HTTPException(status_code=400, detail="Аюултай эсвэл буруу URL байна")
    return RedirectResponse(url=target, status_code=307)

# -------------------------------------------------------------
# 5. TELEGRAM WEBHOOK (Customer Chatbot & Owner Executive Commands)
# -------------------------------------------------------------
@app.post("/telegram/webhook")
async def telegram_webhook_events(request: Request, background_tasks: BackgroundTasks):
    try:
        header_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not core_security.verify_telegram_webhook_secret(header_secret):
            logger.warning("Telegram webhook rejected by fail-closed secret check")
            return Response(content="Forbidden", status_code=403)

        data = await request.json()
        message = data.get("message", {})
        chat_id = message.get("chat", {}).get("id")
        user_text = message.get("text", "")
        voice_data = message.get("voice") or message.get("audio")
        voice_bytes = None

        if voice_data and chat_id:
            file_id = voice_data.get("file_id")
            page_data = database.get_page(database.DEFAULT_PAGE_ID) or {}
            bot_token = page_data.get("telegram_bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
            if bot_token and file_id:
                try:
                    async with httpx.AsyncClient() as client:
                        f_res = await client.get(f"https://api.telegram.org/bot{bot_token}/getFile?file_id={file_id}", timeout=10.0)
                        if f_res.status_code == 200:
                            f_path = f_res.json().get("result", {}).get("file_path")
                            if f_path:
                                dl_res = await client.get(f"https://api.telegram.org/file/bot{bot_token}/{f_path}", timeout=15.0)
                                if dl_res.status_code == 200:
                                    voice_bytes = dl_res.content
                except Exception as ve:
                    logger.error(f"Telegram voice download error: {ve}")
        
        if chat_id and (user_text or voice_bytes):
            # 1. Эхлээд эзний интерактив комманд мөн эсэхийг шалгах (/start, /today, /report, /qpay, /cargo, /help)
            if user_text:
                owner_reply = await executive_bot_service.handle_owner_command(
                    chat_id=str(chat_id),
                    text=user_text,
                    page_id=database.DEFAULT_PAGE_ID
                )
                if owner_reply:
                    background_tasks.add_task(send_telegram_message, chat_id, owner_reply)
                    return {"status": "ok", "mode": "owner_command"}

            # 2. Энгийн харилцагчийн AI чатбот хариу (Текст болон Дуут зурвас)
            result = await asyncio.to_thread(
                agent.process_message,
                text=user_text,
                audio_bytes=voice_bytes,
                audio_mime="audio/ogg" if message.get("voice") else "audio/mpeg",
                sender_id=f"tg_{chat_id}",
                channel="telegram",
                page_id=database.DEFAULT_PAGE_ID
            )
            reply_text = result.get("reply", "")
            if reply_text:
                background_tasks.add_task(send_telegram_message, chat_id, reply_text)
            if result.get("registered") and result.get("reg_info"):
                background_tasks.add_task(notify_manager_telegram, result["reg_info"])
                
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Telegram webhook алдаа: {e}")
        return {"status": "error", "message": str(e)}

# -------------------------------------------------------------
# 6. ВЭБСАЙТ ВИДЖЕТ & ЧАТ СИМУЛЯТОР
# -------------------------------------------------------------
@app.get("/widget.js")
async def get_widget_js():
    return FileResponse("widget.js", media_type="application/javascript")

@app.post("/api/chat")
async def web_chat_endpoint(payload: Dict[str, Any], request: Request, background_tasks: BackgroundTasks):
    _limit_hit = core_rate_limit.check_request_limit(request, "api_chat")
    if _limit_hit:
        return JSONResponse(
            {"detail": "Хэт олон хүсэлт илгээлээ. Түр хүлээнэ үү."},
            status_code=429,
            headers={"Retry-After": str(_limit_hit["retry_after"])},
        )
    message = payload.get("message", "").strip()
    sender_id = payload.get("sender_id", "web_user")
    
    # Хэрэв client нэвтэрсэн бол зөвхөн өөрийн хуудсаар хязгаарлана
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client":
        page_id = user["page_id"]
    else:
        page_id = str(payload.get("page_id", database.DEFAULT_PAGE_ID))
    
    if not message:
        return JSONResponse({"reply": "Та мессежээ бичнэ үү.", "registered": False})
        
    result = await asyncio.to_thread(
        agent.process_message,
        text=message,
        sender_id=sender_id,
        channel="web",
        page_id=page_id
    )
    if result.get("registered") and result.get("reg_info"):
        background_tasks.add_task(notify_manager_telegram, result["reg_info"])
        
    return JSONResponse(result)

@app.post("/api/manychat")
@app.get("/api/manychat")
async def manychat_webhook_endpoint(request: Request, background_tasks: BackgroundTasks):
    """ManyChat / Instagram / Messenger External Request Webhook Bridge (Meta App Reviewгүйгээр шууд холбогдох)"""
    try:
        if request.method == "GET":
            payload = dict(request.query_params)
        else:
            payload = await request.json()
    except Exception:
        payload = {}

    target_page_id = str(payload.get("page_id") or request.query_params.get("page_id") or database.DEFAULT_PAGE_ID)
    if not core_security.verify_manychat_webhook_secret(request, page_id=target_page_id):
        logger.warning("ManyChat webhook rejected by fail-closed secret check")
        return Response(content="Forbidden", status_code=403)

    user_id = str(payload.get("user_id") or payload.get("id") or "manychat_user")
    message = str(payload.get("message") or payload.get("last_input_text") or payload.get("text") or "").strip()

    if not message:
        return JSONResponse({
            "version": "v2",
            "content": {
                "messages": [{"type": "text", "text": "Сайн байна уу! Танд хэрхэн туслах вэ?"}]
            },
            "reply": "Сайн байна уу! Танд хэрхэн туслах вэ?"
        })

    result = await asyncio.to_thread(
        agent.process_message,
        text=message,
        sender_id=f"mc_{user_id}",
        channel="manychat/instagram",
        page_id=target_page_id
    )

    reply_text = result.get("reply", "Сайн байна уу? Танд хэрхэн туслах вэ?")

    if result.get("registered") and result.get("reg_info"):
        background_tasks.add_task(notify_manager_telegram, result["reg_info"])

    return JSONResponse({
        "version": "v2",
        "content": {
            "messages": [
                {
                    "type": "text",
                    "text": reply_text
                }
            ]
        },
        "reply": reply_text,
        "registered": result.get("registered", False)
    })

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB max upload size

@app.post("/api/upload-receipt")
async def upload_receipt_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    text: Optional[str] = Form(""),
    sender_id: Optional[str] = Form("web_simulator_user"),
    page_id: Optional[str] = Form(database.DEFAULT_PAGE_ID)
):
    """Дашбоардын Чат Симулятораас гүйлгээний баримт (Screenshot) шалгах"""
    _limit_hit = core_rate_limit.check_request_limit(request, "api_upload_receipt")
    if _limit_hit:
        return JSONResponse(
            {"detail": "Хэт олон хүсэлт илгээлээ. Түр хүлээнэ үү."},
            status_code=429,
            headers={"Retry-After": str(_limit_hit["retry_after"])},
        )
    user = await core_security.resolve_current_user(request)
    if user and not core_security.is_admin_role(user.get("role")):
        target_page_id = user["page_id"]
    else:
        target_page_id = page_id or database.DEFAULT_PAGE_ID

    image_bytes = await file.read()
    if len(image_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Файлын хэмжээ 10MB-аас хэтэрсэн байна!")
    result = await asyncio.to_thread(
        agent.process_message,
        text=text or "",
        image_bytes=image_bytes,
        sender_id=sender_id or "web_simulator_user",
        channel="web_simulator",
        page_id=target_page_id
    )
    if result.get("registered") and result.get("reg_info"):
        background_tasks.add_task(notify_manager_telegram, result["reg_info"])
    return JSONResponse(result)

# -------------------------------------------------------------
# 7. MULTI-TENANT PAGES / CLIENTS CRUD (Эрхийн Шалгалттай)
# -------------------------------------------------------------
@app.get("/api/pages")
async def get_pages(request: Request):
    """
    Хуудсуудын жагсаалт (Protected):
    - Админ: Бүх хуудсыг харна (бүх нууц токенууд устгагдаж зөвхөн _masked үлдэнэ)
    - Client / Tenant Role: Зөвхөн өөрийнхөө хуудсыг ганцаарчилж харна
    - Unauthenticated: 401 Unauthorized
    """
    user = await core_security.require_permission(request, "pages:read")
    if not core_security.is_admin_role(user.get("role")):
        p = database.get_page(user["page_id"], mask_secrets=True, include_magic_token=True)
        return JSONResponse({"total": 1 if p else 0, "data": [p] if p else []})

    pages = database.get_all_pages(mask_secrets=True, include_magic_token=True)
    return JSONResponse({"total": len(pages), "data": pages})

@app.get("/api/pages/detail")
@app.get("/api/pages/{page_id}")
async def get_page_detail(request: Request, page_id: Optional[str] = None):
    raw_target = request.query_params.get("page_id") or page_id
    if not raw_target:
        return JSONResponse({"error": "page_id missing"}, status_code=400)

    target_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=raw_target,
        require_auth=True,
        permission="pages:read",
    )
    p = database.get_page(target_id, mask_secrets=True, include_magic_token=True)
    if not p:
        return JSONResponse({"error": "Page not found"}, status_code=404)
    return JSONResponse(p)

def _audit_or_report(action: str, *, operation: str, **fields) -> Optional[JSONResponse]:
    """Write a mandated audit event, or return the response that says it was not written.

    E-02 Phase 11 (R17). The business write has ALREADY COMMITTED by the time this is
    called — `save_page`, `delete_page` and `set_client_credentials` each own their
    transaction. So the one thing the response must never do is imply that the
    operation failed. Before R17 was fixed, a caller-side TypeError turned a
    successful create into a bare 500 "Internal server error": the page existed, the
    caller was told it did not, and no audit row was written.

    Returns None on success (the caller carries on), or a JSONResponse with status
    500 that states the truth. Auditing is *not* atomic with the business write —
    that would require threading one connection through three write paths — so this
    reports the gap instead of pretending it cannot happen.
    """
    try:
        database.record_audit_log(action, **fields)
        return None
    except database.AuditLogWriteError as exc:
        logger.error(
            "audit write failed for %s after %s had already committed: %s",
            action, operation, exc,
        )
        return JSONResponse(
            {
                "error": (
                    f"{operation} хийгдсэн боловч аудит лог бичигдсэнгүй. "
                    f"Энэ үйлдлийг гараар шалгана уу."
                ),
                "code": "audit_write_failed",
                "operation_completed": True,
                "audit_action": action,
            },
            status_code=500,
        )


@app.post("/api/pages")
async def create_or_update_page(payload: Dict[str, Any], request: Request):
    """Шинэ хуудас нэмэх (Зөвхөн Админ эрхтэй — P0-2)"""
    await core_security.require_admin(request)

    raw_page_id = str(payload.get("page_id", "")).strip()
    page_id = database.sanitize_page_id(raw_page_id)
    name = str(payload.get("name", "")).strip()

    if not page_id or not name:
        return JSONResponse({"error": "Page ID болон Нэр шаардлагатай"}, status_code=400)

    # Phase 49 (F-49-4). This endpoint is an upsert, but it read every column with a
    # literal default -- `payload.get("category", "general")`,
    # `payload.get("verify_token", "<the published placeholder>")`,
    # `payload.get("monthly_token_limit", 100000)` -- so a payload that simply did not
    # mention a column *reset* it. The dashboard's "Тохиргоо хадгалах" button posts
    # {page_id, name, page_access_token, knowledge_json}, and measured against a running
    # instance that single click:
    #
    #   verify_token        'real-49-verify-token-do-not-lose' -> 'agent_verify_secret_token_123'
    #   monthly_token_limit 5000                               -> 100000
    #
    # i.e. it replaced the page's webhook secret with a string published in this repository
    # (which `verify_manychat_webhook_secret` then accepted as a credential -- F-49-1) and
    # multiplied the tenant's token quota twenty times over. `category` and `is_active` were
    # reset the same way, the latter re-enabling a tenant somebody had disabled.
    #
    # Omitted now means *unchanged*: the stored row supplies the value. An explicit value in
    # the payload still wins, including an explicit null-free empty string for the two
    # columns whose emptiness is meaningful (`page_access_token`, `gemini_api_key`), which
    # `save_page` already preserves through COALESCE(NULLIF(...)).
    existing = database.get_page(page_id) or {}

    category = str(payload.get("category") or existing.get("category") or "general").strip()
    token = str(payload.get("page_access_token", "")).strip()
    verify_token = str(payload.get("verify_token") or existing.get("verify_token") or "").strip()
    gemini_key = str(payload.get("gemini_api_key", "")).strip()
    raw_limit = payload.get("monthly_token_limit")
    if raw_limit is None:
        raw_limit = existing.get("monthly_token_limit")
    monthly_limit = int(raw_limit) if raw_limit is not None else 100000
    raw_active = payload.get("is_active")
    if raw_active is None:
        # A NULL column must not be read as "disabled": absent means the schema default.
        raw_active = existing.get("is_active")
        if raw_active is None:
            raw_active = 1
    is_active = 1 if raw_active in (1, True, "1", "true", "True") else 0
    k_json = payload.get("knowledge_json")
    if k_json is None:
        k_json = existing.get("knowledge_json") or "{}"
    if isinstance(k_json, dict):
        k_json = json.dumps(k_json, ensure_ascii=False)

    try:
        database.save_page(
            page_id=page_id,
            name=name,
            category=category,
            page_access_token=token,
            verify_token=verify_token,
            knowledge_json=k_json,
            gemini_api_key=gemini_key,
            monthly_token_limit=monthly_limit,
            is_active=is_active
        )
    except Exception as exc:
        # E-02 Phase 10 (R16). A page_id must not equal any other tenant's login
        # username or page_id, ignoring case and whitespace, and two page_ids that
        # differ only by case are one login identifier. Revision `0006` enforces
        # that in the database, so the refusal arrives as a driver IntegrityError.
        # Translate it into a 409 that names the reason without revealing which
        # other tenant holds the identifier (same non-disclosure rule as 0005).
        if core_login_identity.is_identifier_violation(exc):
            return JSONResponse(
                {"error": "Энэ Page ID нь өөр салбарын нэвтрэх нэр эсвэл Page ID-тай давхцаж байна",
                 "code": "identifier_conflict"},
                status_code=409,
            )
        raise
    audit_error = _audit_or_report(
        "page.upsert",
        operation=f"Хуудас ({page_id}) хадгалах",
        page_id=page_id,
        actor_role="admin",
        resource_type="page",
        resource_id=page_id,
        # Explicitly enumerated, and deliberately excluding `token`, `verify_token` and
        # `gemini_key`: an audit log that records secrets is itself a disclosure.
        # Phase 49 (F-49-4): `is_active` was a hardcoded `True`, so the audit row asserted a
        # state the request never set — and after the fix above the endpoint genuinely can
        # write 0. The row now records what was written.
        details={"name": name, "category": category, "is_active": bool(is_active)},
    )
    if audit_error is not None:
        return audit_error
    agent.reset_sessions(page_id)
    return {"status": "success", "message": f"{name} хуудас амжилттай хадгалагдлаа!", "page_id": page_id}

@app.delete("/api/pages")
@app.delete("/api/pages/{page_id}")
async def delete_page_endpoint(request: Request, page_id: Optional[str] = None):
    """Хуудас устгах (Зөвхөн Админ эрхтэй — P0-2)"""
    target_id = request.query_params.get("page_id") or page_id
    if not target_id:
        return JSONResponse({"error": "page_id missing"}, status_code=400)

    await core_security.require_admin(request)

    success = database.delete_page(str(target_id))
    if not success:
        return JSONResponse({"error": "Үндсэн хуудсыг устгах боломжгүй"}, status_code=400)
    audit_error = _audit_or_report(
        "page.delete",
        operation=f"Хуудас ({target_id}) устгах",
        # page_id is deliberately None here (E-02 Phase 11, R18). `audit_logs.page_id`
        # is `ON DELETE SET NULL` so history outlives the tenant it describes, which
        # means a row may not reference a page that no longer exists. Passing the just-
        # deleted id made every deletion audit fail with `FOREIGN KEY constraint failed`
        # -- and R17's TypeError had been masking it, because the request died one line
        # earlier. The deleted page is still recorded, in `resource_id`.
        page_id=None,
        actor_role="admin",
        resource_type="page",
        resource_id=str(target_id),
        details={"deleted_page_id": str(target_id)},
    )
    if audit_error is not None:
        return audit_error
    agent.reset_sessions(str(target_id))
    return {"status": "deleted", "page_id": target_id}

@app.post("/api/pages/gemini_key")
@app.post("/api/pages/{page_id}/gemini_key")
async def update_page_gemini_key_endpoint(payload: Dict[str, Any], request: Request, page_id: Optional[str] = None):
    """Харилцагчийн хувийн Gemini API түлхүүр шинэчлэх (Админ болон тухайн Client өөрөө засаж болно)"""
    raw_target = payload.get("page_id") or page_id
    if not raw_target:
        return JSONResponse({"error": "page_id missing"}, status_code=400)

    target_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=raw_target,
        require_auth=True,
        permission="knowledge:write",
    )

    gemini_key = str(payload.get("gemini_api_key", "")).strip()
    monthly_limit = payload.get("monthly_token_limit")
    if monthly_limit is not None:
        try: monthly_limit = int(monthly_limit)
        except Exception: monthly_limit = None

    database.update_page_gemini_key(str(target_id), gemini_key, monthly_limit)
    agent.reset_sessions(str(target_id))
    return {"status": "success", "message": "Gemini API тохиргоо амжилттай шинэчлэгдлээ!"}

@app.post("/api/pages/credentials")
@app.post("/api/pages/{page_id}/credentials")
async def set_page_credentials_endpoint(payload: Dict[str, Any], request: Request, page_id: Optional[str] = None):
    """Харилцагчид зориулсан нэвтрэх эрх & Magic Link үүсгэх (Зөвхөн Админ — P0-2)"""
    await core_security.require_admin(request)

    target_page_id = payload.get("page_id") or page_id
    if not target_page_id:
        return JSONResponse({"error": "Хуудасны ID шаардлагатай"}, status_code=400)

    username = str(payload.get("username", "")).strip()
    password = payload.get("password")
    if not username:
        return JSONResponse({"error": "Хэрэглэгчийн нэр оруулна уу"}, status_code=400)

    # E-02 Phase 6, R10: a username owned by another tenant is a conflict, not an update.
    # Previously this silently rewrote the other tenant's row (cross-tenant takeover). It is
    # now refused with 409. Only the conflict is reported — never which tenant holds the name,
    # because that would turn the endpoint into a cross-tenant username oracle.
    try:
        res = database.set_client_credentials(str(target_page_id), username, password)
    except database.CredentialConflictError:
        # BEST-EFFORT audit, and it must never mask the 409. A refusal is a security
        # event worth recording, but the caller's correct answer is the 409 from the
        # Phase 4.1/`0005` non-disclosure contract. Before R17 was fixed the audit call
        # raised here, so the client saw 500 "Internal server error" instead — the
        # contract was silently broken and the refusal went unaudited anyway.
        try:
            database.record_audit_log(
                "page.credentials.conflict",
                page_id=str(target_page_id),
                actor_role="admin",
                resource_type="page",
                resource_id=str(target_page_id),
                details={"username_length": len(username)},
            )
        except database.AuditLogWriteError:
            logger.error(
                "audit write failed for page.credentials.conflict; returning 409 anyway",
                exc_info=True,
            )
        return JSONResponse(
            {"error": "Энэ нэвтрэх нэрийг өөр харилцагч ашиглаж байна. Өөр нэр сонгоно уу."},
            status_code=409,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    operation_label = f"Хуудас ({target_page_id}) нэвтрэх эрх шинэчлэх"
    audit_error = _audit_or_report(
        "page.credentials.updated",
        operation=operation_label,
        page_id=str(target_page_id),
        actor_role="admin",
        resource_type="page",
        resource_id=str(target_page_id),
        # The username may be a phone number or an email, so only its length is
        # recorded. The password is never touched: it is not in scope here at all.
        details={"username_length": len(username)},
    )
    if audit_error is not None:
        # E-03 (Phase 12 finding F-C). This endpoint must NOT let the audit gate the
        # response, and the reason is specific to what `set_client_credentials` does:
        # it has already rotated `client_magic_token`, revoked every session for the
        # page, and committed. Returning the audit error alone therefore tells the
        # caller "nothing was delivered" about a rotation that destroyed the token
        # they were still holding.
        #
        # Measured before this change: during an audit-store outage each retry rotated
        # the token again and revoked the sessions again, the previously distributed
        # token stopped working, the replacement was never returned, and only a
        # password login got the operator back in. Recovery needed the *first*
        # successful call, which had already happened and been discarded.
        #
        # So the new magic token is returned WITH the audit gap reported in the same
        # body. The caller gets the credential that is now live, and sees the truth
        # about the audit. Status stays 500 because an invariant genuinely was not
        # met, and `operation_completed` stays true.
        #
        # This changes no token property: same generator, same lifetime, same
        # revocation behaviour, same authentication path. It only stops discarding a
        # committed secret because a log write failed.
        body = {
            "error": (
                f"{operation_label} хийгдсэн боловч аудит лог бичигдсэнгүй. "
                f"Энэ үйлдлийг гараар шалгана уу."
            ),
            "code": "audit_write_failed",
            "operation_completed": True,
            "audit_action": "page.credentials.updated",
            # Delivered because it is already the live credential. The previous token
            # is dead, so withholding this leaves the caller with no working one.
            "data": res,
        }
        logger.error(
            "audit write failed for page.credentials.updated after %s committed; "
            "delivering the rotated magic token with the audit gap reported",
            operation_label,
        )
        return JSONResponse(body, status_code=500)
    return {"status": "success", "data": res}

# -------------------------------------------------------------
# 8. UNIFIED INBOX & HUMAN TAKEOVER (Client Isolation — P0-3)
# -------------------------------------------------------------
@app.get("/api/sessions")
async def get_active_sessions(
    request: Request,
    page_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    target_page = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="sessions:read",
    )
    if target_page:
        sessions = database.get_active_sessions(page_id=target_page)
    else:
        # Admin asked for every branch. E-01 removed the unscoped call, so the cross-tenant
        # view is now an explicit per-tenant aggregate rather than a silent "all rows" query.
        sessions = [
            row
            for page in database.get_all_pages()
            for row in database.get_active_sessions(page_id=page["page_id"])
        ]
        sessions.sort(key=lambda r: str(r.get("updated_at") or ""), reverse=True)
    sliced = sessions[offset : offset + limit]
    return JSONResponse({"total": len(sessions), "limit": limit, "offset": offset, "data": sliced})

@app.get("/api/sessions/{sender_id}/messages")
async def get_session_messages(sender_id: str, request: Request, page_id: Optional[str] = Query(None)):
    """
    One customer's messages inside ONE tenant.

    E-01: tenancy comes from the authenticated context (`enforce_tenant_scope`), never from
    `msgs[0]` (the oldest message, which may belong to any tenant) and never from the
    client-supplied `page_id`. The history query is tenant-scoped before any row is read,
    so a caller cannot even learn whether another tenant has that sender.
    """
    target_page = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=False,
        permission="sessions:read",
    )
    if not target_page:
        raise HTTPException(status_code=403, detail="Салбар тодорхойгүй байна! (Tenant scope required)")
    msgs = database.get_conversation_history(sender_id, page_id=target_page)
    is_takeover = database.is_session_human_takeover(sender_id, page_id=target_page)
    return JSONResponse({"sender_id": sender_id, "page_id": str(target_page), "is_human_takeover": is_takeover, "messages": msgs})


@app.post("/api/sessions/{sender_id}/takeover")
async def toggle_human_takeover(sender_id: str, payload: Dict[str, bool], request: Request, page_id: Optional[str] = Query(None)):
    """
    E-01: the tenant is resolved from the auth context and must own the session row.
    Previously ownership was read from the OLDEST message, so a sender who first talked to
    tenant A let tenant A flip takeover on tenant B's live conversation. A session that
    does not exist for the caller's tenant is 404, never a silent cross-tenant write.
    """
    target_page = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=False,
        permission="sessions:write",
    )
    if not target_page:
        raise HTTPException(status_code=403, detail="Салбар тодорхойгүй байна! (Tenant scope required)")

    owns_session = database.session_belongs_to_page(sender_id, page_id=target_page)
    has_history = bool(database.get_conversation_history(sender_id, limit=1, page_id=target_page))
    if not (owns_session or has_history):
        raise HTTPException(status_code=404, detail="Сесс олдсонгүй! (Session not found in this tenant)")

    takeover = payload.get("takeover", False)
    database.set_human_takeover(sender_id, takeover, page_id=target_page)
    database.record_audit_log(
        "session.takeover.changed",
        page_id=str(target_page),
        resource_type="session",
        resource_id=str(sender_id),
    )
    return {"status": "success", "page_id": str(target_page), "is_human_takeover": takeover}


@app.post("/api/sessions/{sender_id}/send")
async def manager_send_message(sender_id: str, payload: Dict[str, str], request: Request, background_tasks: BackgroundTasks, page_id: Optional[str] = Query(None)):
    """
    E-01: the outbound message is written to, and the conversation read from, the tenant
    that owns the authenticated session. `payload["page_id"]` is no longer trusted.
    """
    text = payload.get("message", "").strip()
    target_page = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=False,
        permission="sessions:write",
    )
    if not target_page:
        raise HTTPException(status_code=403, detail="Салбар тодорхойгүй байна! (Tenant scope required)")

    owns_session = database.session_belongs_to_page(sender_id, page_id=target_page)
    has_history = bool(database.get_conversation_history(sender_id, limit=1, page_id=target_page))
    if not (owns_session or has_history):
        raise HTTPException(status_code=404, detail="Сесс олдсонгүй! (Session not found in this tenant)")

    if not text:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    # E-01: the message is stored under the AUTHENTICATED tenant, not the request body.
    database.log_message(sender_id=sender_id, channel="omni", sender_type="agent", content=text, page_id=target_page)
    database.record_audit_log(
        "session.message.sent",
        page_id=str(target_page),
        resource_type="session",
        resource_id=str(sender_id),
    )

    page_obj = database.get_page(target_page)
    page_token = page_obj.get("page_access_token") if page_obj else None
    if sender_id.startswith("meta_"):
        background_tasks.add_task(send_meta_message, sender_id.replace("meta_", ""), text, page_token)
    elif sender_id.startswith("tg_"):
        background_tasks.add_task(send_telegram_message, sender_id.replace("tg_", ""), text, page_id=target_page)

    return {"status": "sent", "sender_id": sender_id, "page_id": str(target_page), "message": text}

# -------------------------------------------------------------
# 9. CRM & LEADS PIPELINE (Client Isolation — P0-3)
# -------------------------------------------------------------
@app.get("/api/registrations")
@app.get("/api/leads")
async def get_registrations(
    request: Request,
    page_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    target_page = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="leads:read",
    )
    rows = database.get_all_registrations(page_id=target_page)
    if status:
        rows = [r for r in rows if str(r.get("status", "")).lower() == status.lower()]
    if search:
        q = search.lower()
        rows = [
            r for r in rows
            if q in str(r.get("name", "")).lower()
            or q in str(r.get("phone", "")).lower()
            or q in str(r.get("service", "")).lower()
            or q in str(r.get("notes", "")).lower()
        ]
    sliced = rows[offset : offset + limit]
    return JSONResponse({"total": len(rows), "limit": limit, "offset": offset, "data": sliced})

@app.post("/api/leads/{lead_id}/status")
async def update_lead(lead_id: int, payload: Dict[str, Any], request: Request):
    user = await core_security.require_permission(request, "leads:write")
    lead = database.get_lead_by_id(lead_id)
    if not lead:
        raise HTTPException(status_code=404, detail="Lead not found")
    core_security.verify_resource_tenant_ownership(user, lead.get("page_id"), require_auth=True)
    status = payload.get("status", "шинэ")
    notes = payload.get("notes")
    database.update_lead_status(lead_id, status, notes)
    return {"status": "updated", "lead_id": lead_id}

@app.get("/api/export/csv")
async def export_csv(
    request: Request,
    page_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    target_page = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="leads:export",
    )
    csv_data = database.sync_to_csv(page_id=target_page)
    filename = f"leads_{target_page or 'all'}.csv"
    
    return Response(
        content=csv_data.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }
    )

@app.get("/api/export/excel")
async def export_excel(
    request: Request,
    page_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    target_page = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="leads:export",
    )
    excel_stream = database.generate_excel(page_id=target_page)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"leads_{target_page or 'all'}_{timestamp}.xlsx"
    
    return Response(
        content=excel_stream.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }
    )

@app.post("/api/pages/{page_id}/google_sheets")
async def update_page_google_sheets_endpoint(page_id: str, payload: Dict[str, Any], request: Request):
    await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="knowledge:write",
    )
    url = payload.get("google_sheets_url", "").strip()
    if url:
        try:
            sheets_service.normalize_sheet_csv_url(url)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
    database.update_page_google_sheets(page_id, url)
    agent.reset_sessions(page_id)
    return {"success": True, "page_id": page_id, "google_sheets_url": url}

def _save_page_sheets_list(page_id: str, sheets_list: List[Dict[str, Any]]):
    page_obj = database.get_page(page_id)
    if not page_obj:
        raise HTTPException(status_code=404, detail="Салбар олдсонгүй")
    raw_kj = page_obj.get("knowledge_json") or "{}"
    try:
        kj = json.loads(raw_kj) if isinstance(raw_kj, str) else dict(raw_kj)
    except Exception:
        kj = {}
    kj["sheets"] = sheets_list

    # Keep first google sheet url in google_sheets_url for backward compatibility
    first_gs_url = next((s.get("url", "") for s in sheets_list if s.get("type") == "google" and s.get("url")), "")
    database.update_page_google_sheets(page_id, first_gs_url)
    database.save_page(
        page_id=page_id,
        name=page_obj.get("name", "Салбар"),
        category=page_obj.get("category", "general"),
        page_access_token=page_obj.get("page_access_token", ""),
        # Phase 49 (F-49-4): carry the stored value through, and never substitute the
        # published placeholder — `save_page` preserves the stored secret on an empty one.
        verify_token=page_obj.get("verify_token") or "",
        knowledge_json=json.dumps(kj, ensure_ascii=False, indent=2),
        gemini_api_key=page_obj.get("gemini_api_key", ""),
        monthly_token_limit=page_obj.get("monthly_token_limit", 100000),
        # `save_page`'s default is 1, so a sheet edit used to re-enable a tenant that had
        # been disabled. The stored state is carried through instead.
        is_active=(0 if page_obj.get("is_active") in (0, False) else 1)
    )
    agent.reset_sessions()

@app.get("/api/pages/{page_id}/sheets")
async def list_page_sheets_endpoint(page_id: str, request: Request):
    await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="knowledge:read",
    )

    page_obj = database.get_page(page_id)
    if not page_obj:
        raise HTTPException(status_code=404, detail="Салбар олдсонгүй")

    sheets = sheets_service.get_page_sheets_list(page_obj)
    summary = []
    for s in sheets:
        s_type = s.get("type", "google")
        cols = s.get("columns") or []
        row_count = s.get("row_count")
        if s_type == "excel":
            rows = s.get("rows") or []
            row_count = len(rows)
            if not cols and rows:
                cols = list(rows[0].keys())
        summary.append({
            "id": s.get("id"),
            "title": s.get("title") or "Хүснэгт",
            "type": s_type,
            "url": s.get("url", ""),
            "filename": s.get("filename", ""),
            "columns": cols,
            "row_count": row_count if row_count is not None else "Шалгаагүй",
            "updated_at": s.get("updated_at", "")
        })
    return {"success": True, "sheets": summary}

@app.post("/api/pages/{page_id}/sheets/add")
async def add_page_google_sheet_endpoint(page_id: str, payload: Dict[str, Any], request: Request):
    await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="knowledge:write",
    )

    url = (payload.get("url") or payload.get("google_sheets_url") or "").strip()
    title = (payload.get("title") or "").strip()
    if not url:
        return JSONResponse({"success": False, "error": "Google Sheet холбоос оруулна уу."}, status_code=400)

    try:
        rows = sheets_service.fetch_sheet_rows(url, force_refresh=True)
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": f"Хүснэгтийг уншихад алдаа гарлаа ({e}). 'Anyone with the link can view' эрхтэй эсэхийг шалгана уу."
        }, status_code=400)

    cols = list(rows[0].keys()) if rows else []
    page_obj = database.get_page(page_id)
    sheets = sheets_service.get_page_sheets_list(page_obj)
    import uuid, time
    new_sheet = {
        "id": f"gs_{uuid.uuid4().hex[:8]}",
        "title": title or f"Google Хүснэгт #{len(sheets) + 1}",
        "type": "google",
        "url": url,
        "columns": cols,
        "row_count": len(rows),
        "updated_at": time.strftime("%Y-%m-%d %H:%M")
    }
    sheets.append(new_sheet)
    _save_page_sheets_list(page_id, sheets)
    return {
        "success": True,
        "sheet": new_sheet,
        "count": len(rows),
        "columns": cols,
        "sample": rows[:3]
    }

@app.post("/api/pages/{page_id}/sheets/upload")
async def upload_page_excel_sheets_endpoint(page_id: str, request: Request, file: UploadFile = File(...)):
    await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="knowledge:write",
    )

    file_bytes = await file.read()
    if not file_bytes:
        return JSONResponse({"success": False, "error": "Хоосон файл байна."}, status_code=400)
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Excel файлын хэмжээ 10MB-аас хэтэрсэн байна!")

    try:
        extracted_sheets = sheets_service.parse_uploaded_excel_bytes(file_bytes, file.filename or "excel.xlsx")
    except Exception as e:
        return JSONResponse({"success": False, "error": f"Excel файл уншихад алдаа гарлаа: {e}"}, status_code=400)

    if not extracted_sheets:
        return JSONResponse({"success": False, "error": "Хүснэгтэд өгөгдөл олдсонгүй."}, status_code=400)

    page_obj = database.get_page(page_id)
    sheets = sheets_service.get_page_sheets_list(page_obj)
    sheets.extend(extracted_sheets)
    _save_page_sheets_list(page_id, sheets)

    return {
        "success": True,
        "added_count": len(extracted_sheets),
        "added_sheets": [
            {
                "id": s["id"],
                "title": s["title"],
                "row_count": s["row_count"],
                "columns": s["columns"]
            }
            for s in extracted_sheets
        ]
    }

@app.delete("/api/pages/{page_id}/sheets/{sheet_id}")
async def delete_page_sheet_endpoint(page_id: str, sheet_id: str, request: Request):
    await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="knowledge:write",
    )

    page_obj = database.get_page(page_id)
    sheets = sheets_service.get_page_sheets_list(page_obj)
    filtered = [s for s in sheets if s.get("id") != sheet_id]
    _save_page_sheets_list(page_id, filtered)
    return {"success": True, "remaining": len(filtered)}

@app.post("/api/pages/{page_id}/test_sheet")
async def test_page_google_sheet_endpoint(page_id: str, payload: Dict[str, Any], request: Request):
    await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="knowledge:read",
    )
    
    url = payload.get("google_sheets_url", "").strip()
    if not url:
        return JSONResponse({"success": False, "error": "Google Sheets холбоос оруулаагүй байна."}, status_code=400)
    
    try:
        rows = sheets_service.fetch_sheet_rows(url, force_refresh=True)
    except Exception as e:
        return JSONResponse({
            "success": False, 
            "error": f"Хүснэгтийг уншиж чадсангүй ({e}). Та Google Sheet-ийнхээ 'Share' эрхийг 'Anyone with the link can view' болгосон эсэхээ шалгана уу."
        }, status_code=400)
    if not rows:
        return JSONResponse({
            "success": False, 
            "error": "Хүснэгт хоосон эсвэл уншиж чадсангүй. 'Share' эрхийг 'Anyone with the link can view' болгосон эсэхээ шалгана уу."
        }, status_code=400)
        
    cols = list(rows[0].keys()) if rows else []
    return {
        "success": True,
        "count": len(rows),
        "columns": cols,
        "sample": rows[:3]
    }

# -------------------------------------------------------------
# 10. МЭДЛЭГИЙН САН (KNOWLEDGE BASE) API
# -------------------------------------------------------------
@app.get("/api/knowledge")
async def get_knowledge(request: Request, page_id: Optional[str] = Query(None)):
    target_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="knowledge:read",
    )
    
    page_obj = database.get_page(target_id)
    if page_obj and page_obj.get("knowledge_json"):
        try:
            return JSONResponse(json.loads(page_obj["knowledge_json"]))
        except Exception:
            pass
    return JSONResponse(knowledge_base.load_knowledge())

@app.post("/api/knowledge")
async def update_knowledge(payload: Dict[str, Any], request: Request, page_id: Optional[str] = Query(None)):
    target_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id or payload.get("page_id"),
        require_auth=True,
        permission="knowledge:write",
    )
    
    page_obj = database.get_page(target_id)
    k_str = json.dumps(payload, ensure_ascii=False, indent=2)

    if page_obj:
        database.save_page(
            page_id=target_id,
            name=page_obj.get("name", "Page"),
            category=page_obj.get("category", "general"),
            page_access_token=page_obj.get("page_access_token", ""),
            # Phase 49 (F-49-4): carry the stored value through, and never substitute the
            # published placeholder — `save_page` preserves the stored secret on an empty one.
            verify_token=page_obj.get("verify_token") or "",
            knowledge_json=k_str,
            gemini_api_key=page_obj.get("gemini_api_key", ""),
            monthly_token_limit=page_obj.get("monthly_token_limit", 100000),
            # `save_page`'s default is 1, so a knowledge edit used to re-enable a tenant
            # that had been disabled. The stored state is carried through instead.
            is_active=(0 if page_obj.get("is_active") in (0, False) else 1)
        )
    if target_id == database.DEFAULT_PAGE_ID:
        knowledge_base.save_knowledge(payload)

    agent.reset_sessions(target_id)
    return {"status": "success", "message": f"{target_id} хуудасны мэдлэгийн сан амжилттай шинэчлэгдлээ!"}

# -------------------------------------------------------------
# 11. СИСТЕМИЙН ЭРҮҮЛ МЭНД БА ТҮЛХҮҮРҮҮД
# -------------------------------------------------------------
@app.get("/api/live")
async def liveness_check():
    """Cheap liveness probe (Phase 36).

    Answers only "is this process serving HTTP?". No database, no Redis, no counting.
    Phase 35 measured `/api/health` at 28 ms on an empty database rising to 95 ms at 10k
    rows because it loads every registration and every active session; that is the wrong
    cost profile for a probe a container runtime or load balancer calls every few seconds.
    This endpoint has a constant cost of roughly a dictionary literal.

    Deliberately NOT dependent on the database or Redis: a restart cannot fix either, so
    making liveness depend on them would turn a dependency outage into a crash loop. That
    reasoning is why `/api/health` was already Redis-independent (E-02 Phase 6) and it
    applies equally here. Readiness is `/api/ready`.
    """
    return JSONResponse({"status": "alive"})


@app.get("/api/health")
async def health_check():
    """Deep-ish health: dependency flags plus a *bounded* data summary.

    Phase 36 replaced the unbounded table scan. Previously this loaded every registration
    and every active session on every call, so its cost grew linearly with the customer's
    data and a monitor pointed here became a source of load. The totals are now capped at
    HEALTH_SUMMARY_SCAN_LIMIT rows and reported as "at least N" when the cap is reached,
    which keeps the diagnostic value (is there data? roughly how much?) at a constant cost.

    Use `/api/live` for container liveness and `/api/ready` for readiness. This endpoint is
    for a human or a low-frequency dashboard, not a probe.
    """
    load_dotenv(override=True)
    # Phase 36: counts come from `COUNT(*)`, not from materialising rows.
    #
    # The previous implementation called get_all_registrations() and
    # get_all_pages(), then fetched every page's active sessions, so the endpoint's cost
    # and memory use grew linearly with the tenant's data (measured: 28 ms empty,
    # 94.6 ms at 10k rows) while a health probe called it every few seconds.
    #
    # `COUNT(*)` is O(1)-ish for the planner and allocates nothing per row. It is still a
    # scan on SQLite, so this endpoint remains unsuitable as a high-frequency liveness
    # probe -- that is what /api/live is for -- but it no longer scales with data volume
    # in a way that can exhaust a worker.
    # Explicit statements rather than an f-string over a table name. The names below are
    # literals, but Phase 26's rule is that SQL is never assembled from a variable: a
    # future edit that passed user input into a helper like the previous `_count(table)`
    # would have been an injection with no visible string concatenation at the call site.
    # Bandit also flags the interpolated form (B608), and a suppression there would have
    # been the wrong trade.
    _HEALTH_COUNTS = {
        "pages": "SELECT COUNT(*) FROM pages",
        "registrations": "SELECT COUNT(*) FROM registrations",
        # Exactly preserves the previous number: the old code summed
        # len(get_active_sessions(page)) over every page, and that function returns every
        # `session_states` row for a page with no `is_active` filter (despite its name), so
        # the cross-tenant total is simply the table's row count. Adding a filter here
        # would have silently changed the reported figure.
        "session_states": "SELECT COUNT(*) FROM session_states",
    }

    def _count(name: str) -> "int | None":
        """Run one of the fixed COUNT(*) statements, or None if it fails."""
        statement = _HEALTH_COUNTS.get(name)
        if statement is None:
            return None
        conn = None
        cur = None
        try:
            conn = database.get_connection()
            cur = conn.cursor()
            cur.execute(statement)
            row = cur.fetchone()
            if row is None:
                return None
            return int(row[0] if not isinstance(row, dict) else list(row.values())[0])
        except Exception as exc:
            logger.warning(f"health: count({name}) unavailable: {exc}")
            return None
        finally:
            if cur is not None:
                try:
                    cur.close()
                except Exception:
                    pass
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    total_pages = _count("pages")
    total_leads = _count("registrations")
    active_sessions = _count("session_states")
    summary_available = None not in (total_pages, total_leads, active_sessions)
    return JSONResponse({
        "status": "healthy",
        # F-50-1: on its own, `gemini_ready` has always meant "a key is configured" while
        # reading as "the AI works". `genai.Client(api_key=...)` makes no network call, so it
        # reported true for a wrong, revoked or unreachable key too — measured live with
        # every generation attempt failing and every reply coming from the deterministic
        # fallback. The observed verdict is now published beside it, and the historical field
        # keeps its historical value so no existing consumer changes behaviour.
        # Counters and a closed enum only: this endpoint is unauthenticated, so it carries no
        # exception text — the rule /api/ready states in its own comment.
        **agent.gemini_status(),
        "model": agent.get_model_name(),
        # SEC-07: lets an operator confirm limits are actually shared across workers
        # rather than silently per-process.
        "rate_limit_backend": core_rate_limit.get_limiter().backend(),
        "rate_limits_shared_across_workers": core_rate_limit.get_limiter().is_shared(),
        "meta_token_configured": bool(os.getenv("META_PAGE_ACCESS_TOKEN", "").strip()),
        "telegram_configured": bool(os.getenv("TELEGRAM_BOT_TOKEN", "").strip()),
        # None means "could not be counted"; it is not reported as 0.
        "total_pages": total_pages,
        "total_leads": total_leads,
        "active_sessions": active_sessions,
        "summary_available": summary_available,
    })

@app.get("/api/ready")
async def readiness_check():
    """Readiness probe verifying database and task queue connectivity (Phase 8)"""
    from core import db_engine, task_queue
    db_ok = False
    conn = None
    cur = None
    try:
        conn = database.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        db_ok = True
    except Exception as e:
        logger.error(f"Readiness DB check failed: {e}")
    finally:
        if cur is not None:
            try:
                cur.close()
            except Exception:
                pass
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    try:
        q_stats = task_queue.get_queue_stats()
    except Exception as qe:
        logger.warning(f"Readiness queue stats fallback: {qe}")
        q_stats = {"backend": "unavailable"}

    # E-02 Phase 6, R11. Readiness must not report healthy while the account limiter cannot
    # enforce its policy: in production that limiter is the shared store, so a Redis outage
    # means logins are refused (R14 fail-closed) *and* the IP limit is dead. "Healthy" there
    # would be false in both directions — it would hide an outage, and it would let a load
    # balancer keep sending traffic to a deployment that cannot authenticate anybody.
    #
    # Deliberately NOT in liveness: restarts cannot fix Redis, so making liveness depend on it
    # would produce a crash-loop during an outage and turn a partial failure into a total one.
    # Outside production the shared store is optional (the documented memory fallback), so the
    # check is informational only and never fails readiness.
    limiter = core_rate_limit.get_limiter()
    shared_store_required = core_rate_limit.shared_store_required()
    if shared_store_required:
        store_ok = limiter.ping()
    else:
        store_ok = True
    store_backend = limiter.backend()

    ready = db_ok and store_ok
    status_code = 200 if ready else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "ready": ready,
            "status": "ready" if ready else "not_ready",
            "database": "ok" if db_ok else "failed",
            "engine": "postgresql" if db_engine.is_postgres() else "sqlite",
            # Backend *kind*, never the URL, and no exception text: this endpoint is
            # unauthenticated and its output is readable by anyone who can reach it.
            "rate_limit_store": store_backend,
            "rate_limit_store_required": shared_store_required,
            "rate_limit_store_ok": store_ok,
            "queue_backend": q_stats.get("backend", "sqlite"),
            "queue_stats": q_stats,
        },
    )

#: `POST /api/update-keys` payload field -> the `.env` key it owns. Only a field the admin
#: actually submitted is written (F-51-3): the endpoint used to rebuild the whole file from a
#: fixed 8-key map, which deleted every other setting it did not know about.
UPDATE_KEYS_ENV_NAMES = {
    "gemini_key": "GEMINI_API_KEY",
    "meta_token": "META_PAGE_ACCESS_TOKEN",
    "meta_verify": "META_VERIFY_TOKEN",
    "tg_token": "TELEGRAM_BOT_TOKEN",
    "tg_manager_id": "TELEGRAM_MANAGER_CHAT_ID",
    "admin_password": "ADMIN_PASSWORD",
}


def merge_env_file(updates: Dict[str, str], path: str = ".env") -> Dict[str, Any]:
    """Write `updates` into an existing dotenv file, losing nothing else in it.

    F-51-3. `POST /api/update-keys` used to do this::

        with open(".env", "w") as f:
            for k, v in keys_map.items():      # exactly 8 fixed keys
                f.write(f"{k}={v}\\n")

    That is truncation, not an update. Measured against this repository's own `.env`
    (170 lines, 42 keys): saving one field from the dashboard left an 8-line file. Gone were
    `DATABASE_URL`, `DB_PATH`, `CSV_PATH`, `REDIS_URL`, `ALLOWED_ORIGINS`, `TRUSTED_PROXIES`,
    `E02_ACCOUNT_KEY_SECRET`, `MANYCHAT_WEBHOOK_SECRET` and the whole `BACKUP_*` block, so the
    next restart came up on SQLite, with no shared rate-limit store, with the account-key
    secret missing (the limiter silently degrades to a per-worker counter), with the ManyChat
    webhook secret gone and with no offsite backup configuration. Every explanatory comment
    was lost too, so the file stopped being readable as documentation.

    This merges instead: a key already in the file is updated on its own line, a key that is
    not there is appended, and every other line - including comments and blank lines - is
    preserved byte for byte. The write is atomic (`mkstemp` in the same directory, then
    `os.replace`) and keeps the file's existing mode, so a concurrent reader never sees a
    half-written `.env` and a 0600 file does not become 0644.

    A value containing a newline is refused rather than written. `os.replace` would happily
    store `"x\\nADMIN_PASSWORD=pwned"` as two lines, which is a credential write nobody
    submitted - the payload arrives over HTTP, so the newline is attacker-shaped input even
    though the caller is an authenticated admin.

    Returns a report so a caller (or a test) can assert what happened::

        {"path": ..., "updated": [names], "appended": [names], "preserved": int, "mode": "0o600"}

    `preserved` counts assignment keys that were already in the file and were *not* touched.
    Raises `FileNotFoundError` when the file does not exist: creating a brand new `.env` from
    one submitted key is the same data loss in the other direction, and the caller has
    already decided that writing is allowed at all.
    """
    import stat
    import tempfile

    for name, value in updates.items():
        if "\n" in value or "\r" in value:
            raise ValueError(
                f"{name}: refusing to write a value containing a newline - it would inject "
                f"extra keys into {path}"
            )

    with open(path, "r", encoding="utf-8") as fh:
        original = fh.read()
    mode = stat.S_IMODE(os.stat(path).st_mode)

    lines = original.split("\n")
    index_of: Dict[str, int] = {}
    for i, line in enumerate(lines):
        if line.startswith("#") or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        if name and name.replace("_", "").isalnum():
            index_of[name] = i          # the last assignment wins, as dotenv itself does

    updated: List[str] = []
    appended: List[str] = []
    for name, value in updates.items():
        if name in index_of:
            lines[index_of[name]] = f"{name}={value}"
            updated.append(name)
        else:
            appended.append(name)
    if appended:
        while lines and lines[-1] == "":   # keep the file's trailing-newline convention
            lines.pop()
        lines.extend(f"{name}={updates[name]}" for name in appended)
        lines.append("")

    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".env.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write("\n".join(lines))
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    return {
        "path": path,
        "updated": sorted(updated),
        "appended": sorted(appended),
        "preserved": len([n for n in index_of if n not in updates]),
        "mode": oct(mode),
    }


@app.post("/api/update-keys")
async def update_keys(payload: Dict[str, str], request: Request):
    """Админы системийн түлхүүрүүд засах (Зөвхөн Админ — P0-2)"""
    await core_security.require_admin(request)

    # F-51-3: refuse a newline before anything is mutated. The value is about to be written
    # into `.env`, where a newline means "and also set this other key" (see merge_env_file).
    for _field in UPDATE_KEYS_ENV_NAMES:
        _value = str(payload.get(_field, "") or "")
        if "\n" in _value or "\r" in _value:
            raise HTTPException(
                status_code=400,
                detail=f"{_field}: a value containing a line break is rejected",
            )

    for k in ["gemini_key", "meta_token", "meta_verify", "tg_token", "tg_manager_id", "admin_password"]:
        v = payload.get(k, "").strip()
        if k == "gemini_key" and v:
            os.environ["GEMINI_API_KEY"] = v
            agent._init_default_gemini()
        elif k == "meta_token" and v:
            os.environ["META_PAGE_ACCESS_TOKEN"] = v
        elif k == "meta_verify" and v:
            os.environ["META_VERIFY_TOKEN"] = v
        elif k == "tg_token" and v:
            os.environ["TELEGRAM_BOT_TOKEN"] = v
        elif k == "tg_manager_id" and v:
            os.environ["TELEGRAM_MANAGER_CHAT_ID"] = v
        elif k == "admin_password" and v:
            os.environ["ADMIN_PASSWORD"] = v

    database.record_audit_log("system.keys.updated", actor_role="admin", details={"updated_fields": [k for k in payload if payload.get(k)]})

    # O-51-6 (Phase 52). Which fields this request actually mutated in `os.environ`. The loop
    # above only assigns on a non-empty value, so the list is computed the same way rather than
    # taken from the payload's keys.
    applied_fields = [
        field for field in UPDATE_KEYS_ENV_NAMES
        if str(payload.get(field, "") or "").strip()
    ]
    persisted = False
    write_gate_open = (
        not core_security.is_production_mode()
        and os.getenv("ALLOW_ENV_FILE_WRITE", "0") == "1"
    )

    # Production горимд plaintext .env файл руу бичихгүй
    if write_gate_open:
        # F-51-3: write only what this request actually submitted. The previous code rebuilt
        # the whole file from a fixed 8-key map, which deleted ~34 other settings - including
        # GEMINI_MODEL and PORT, which this endpoint does not even accept as input.
        updates = {
            UPDATE_KEYS_ENV_NAMES[field]: os.environ[UPDATE_KEYS_ENV_NAMES[field]]
            for field in UPDATE_KEYS_ENV_NAMES
            if str(payload.get(field, "") or "").strip()
            and UPDATE_KEYS_ENV_NAMES[field] in os.environ
        }
        if updates:
            try:
                report = merge_env_file(updates)
                persisted = True
                logger.info(
                    ".env updated: wrote %s; %d other key(s) preserved",
                    ", ".join(report["updated"] + report["appended"]),
                    report["preserved"],
                )
            except Exception as env_err:
                # Names and counts only - never a value, which is a credential.
                logger.warning(f"Could not update .env file: {env_err}")

    # O-51-6 (Phase 52). The response used to be an unconditional "saved successfully" for a
    # change that, with the write gate closed, no file recorded and no restart survives. The
    # consequence was not cosmetic. `TELEGRAM_MANAGER_CHAT_ID` in `os.environ` is one of the two
    # sources `executive_bot_service.handle_owner_command` reads to decide who owns the
    # executive reports, so an admin call to this endpoint with the gate closed produced a
    # process that believed a different owner was registered from the one in the database - and
    # from the one the WORKER process believed, since the worker is a separate process that
    # never sees this assignment and is what actually sends the 08:30 report. Nothing reconciled
    # the two except a restart, and nothing told the operator a restart was needed.
    #
    # The in-process update is kept: `tests/test_e51_env_write_merge.py` documents it as the
    # intended behaviour ("the in-process update still succeeds") and an admin rotating a key
    # mid-run should not have to restart to use it. What changes is that the response and the log
    # now say which of the two happened, so the state of the system can be read instead of
    # inferred. Names only, never values.
    process_only = [] if persisted else sorted(
        UPDATE_KEYS_ENV_NAMES[field] for field in applied_fields
    )
    if process_only:
        reason = "production mode" if core_security.is_production_mode() else (
            "ALLOW_ENV_FILE_WRITE is not 1"
        )
        warning = (
            f"Applied to this process only, not written to .env ({reason}); a restart reverts "
            f"it and no other process ever saw it: {', '.join(process_only)}."
        )
        if "TELEGRAM_MANAGER_CHAT_ID" in process_only:
            warning += (
                " This one is worse than the others: the executive-report recipient is per "
                "page in the database, and the worker - a separate process, and the one that "
                "actually sends the 08:30 report - reads that row. This process and the worker "
                "now disagree about who owns the reports. Register it with POST "
                "/api/executive/settings, or persist .env and restart, to make it durable."
            )
        logger.warning("update-keys: %s", warning)
        message = (
            "Тохиргоо энэ процессод хэрэглэгдлээ, гэхдээ .env файлд хадгалагдсангүй "
            "(дахин ачааллахад буцна)."
        )
    else:
        warning = None
        message = "Тохиргоо амжилттай хадгалагдлаа!"

    return {
        "status": "success",
        "message": message,
        # O-51-6: the truth about durability, for a client that would rather read a field than
        # parse a sentence.
        "persisted": persisted,
        "process_only": process_only,
        "warning": warning,
    }

# -------------------------------------------------------------
# 8. ФИНТЕК & ТӨЛБӨРИЙН АВТОМАТЖУУЛАЛТ (QPAY v2, DEEP LINKS, E-BARIMT)
# -------------------------------------------------------------
def _html_template_env() -> "jinja2.Environment":
    """The Jinja2 environment for the two server-rendered pages.

    Phase 25: both sites previously built `jinja2.Environment(loader=...)` with the default
    `autoescape=False`, so every value interpolated into `payment.html` and `scanner.html`
    was emitted verbatim. `scanner.html` renders `page_id` straight from a query parameter
    into a JavaScript string, and `/scanner` requires no authentication:

        GET /scanner?page_id=%22;alert(document.cookie)//

    rendered `const pageId = "";alert(document.cookie)//";` - arbitrary script execution in
    any browser that followed a crafted link. `payment.html` additionally interpolated the
    invoice description and company name into HTML.

    `select_autoescape` covers the HTML sinks; `|tojson` (see the templates) covers the two
    values that land inside a `<script>` block, where HTML escaping is the wrong tool and
    `tojson` is the right one.

    One constructor rather than two: a security setting duplicated at two call sites is a
    setting that will eventually be applied to only one of them.
    """
    import jinja2

    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(searchpath="templates"),
        autoescape=jinja2.select_autoescape(
            enabled_extensions=("html", "htm", "xml"),
            default_for_string=True,
            default=True,
        ),
    )


@app.get("/pay/{invoice_id}", response_class=HTMLResponse)
async def serve_payment_page(invoice_id: str, request: Request):
    """QPay төлбөрийн интерфэйс хуудас (QR код, банкны апп товчлуурууд, И-Баримт)"""
    inv = database.get_invoice(invoice_id)
    if not inv:
        return HTMLResponse(
            content="""<!DOCTYPE html><html lang="mn"><head><meta charset="UTF-8"><title>Нэхэмжлэх олдсонгүй</title><script src="https://cdn.tailwindcss.com"></script></head><body class="bg-slate-950 text-white min-h-screen flex items-center justify-center p-4"><div class="text-center p-8 bg-slate-900 rounded-2xl border border-slate-800"><h1 class="text-2xl font-bold mb-2">Нэхэмжлэх олдсонгүй</h1><p class="text-slate-400 text-sm">Төлбөрийн дугаар хүчингүй эсвэл цуцлагдсан байна.</p></div></body></html>""",
            status_code=404
        )

    page = database.get_page(inv["page_id"]) or {}
    company_name = page.get("name", "Гэрэгэ Системс")

    template_env = _html_template_env()
    template = template_env.get_template("payment.html")
    rendered = template.render(
        invoice_id=inv["invoice_id"],
        amount=inv["amount"],
        description=inv.get("description", "Үйлчилгээний төлбөр"),
        company_name=company_name,
        qr_image_url=inv.get("qr_image_url") or "",
        deep_links=inv.get("deep_links") or []
    )
    return HTMLResponse(content=rendered)

@app.get("/api/fintech/invoices/{invoice_id}/status")
async def get_invoice_status_api(invoice_id: str, request: Request):
    """
    Төлбөрийн төлөвийг шалгах (Real-time Polling).

    P1-04 (B-05) — Cross-tenant BOLA fix:
    - Нэвтэрсэн хэрэглэгч зөвхөн ӨӨРИЙН tenant-ийн нэхэмжлэхийг харна; өөр tenant-ийн
      нэхэмжлэх бол `404` (оршин байгаа эсэхийг ч задруулахгүй — enumeration-ээс сэргийлнэ).
    - Админ бүх нэхэмжлэхийг харна.
    - Нэвтрээгүй (public) хандалт нь allowlist-ийн projection авна: төлбөрийн хуудсанд
      хэрэгтэй талбарууд (`status`, `amount`, `currency`, `description`, `ebarimt`) —
      энэ нь тестээр баталгаажсан contract
      (`tests/test_p1_payment_security.py::test_public_invoice_status_filters_pii`).
    - `sender_id`, утас, `qpay_*`, `callback_verified` зэрэг PII/дотоод талбар хэзээ ч
      буцахгүй.

    Тэмдэглэл: энэ endpoint нь зөвхөн нээлттэй invoice ID-г мэддэг талд зориулагдсан
    (төлбөрийн холбоос). Нэвтэрсэн хэрэглэгчийн хувьд tenant хязгаарыг энд хатуу
    хэрэгжүүлдэг — өөр tenant-ийн нэхэмжлэхийг таах замаар уншиж болохгүй.
    """
    inv = database.get_invoice(invoice_id)
    if not inv:
        return JSONResponse(status_code=404, content={"error": "Invoice not found"})

    user = await core_security.resolve_current_user(request)

    if user:
        role = str(user.get("role") or "").strip().lower()
        is_admin = core_security.is_admin_role(role)
        same_tenant = bool(user.get("page_id")) and str(user.get("page_id")) == str(
            inv.get("page_id")
        )
        if not (is_admin or same_tenant):
            # 404 (not 403): never confirm the existence of another tenant's invoice.
            return JSONResponse(status_code=404, content={"error": "Invoice not found"})
        return {
            "status": inv.get("status", "PENDING"),
            "invoice": dict(inv),
            "ebarimt": {
                "lottery": inv.get("ebarimt_lottery"),
                "qr_data": inv.get("ebarimt_qr"),
            },
        }

    # Unauthenticated polling: allowlisted projection, PII never included.
    # This shape is a tested contract (tests/test_p1_payment_security.py
    # ::test_public_invoice_status_filters_pii) and is required for the payment page.
    return {
        "status": inv.get("status", "PENDING"),
        "invoice": {
            "invoice_id": inv.get("invoice_id"),
            "page_id": inv.get("page_id"),
            "amount": inv.get("amount"),
            "currency": inv.get("currency", "MNT"),
            "description": inv.get("description", "Үйлчилгээний төлбөр"),
            "status": inv.get("status", "PENDING"),
            "paid_at": inv.get("paid_at"),
            "created_at": inv.get("created_at"),
            "ebarimt_lottery": inv.get("ebarimt_lottery"),
            "ebarimt_qr": inv.get("ebarimt_qr"),
        },
        "ebarimt": {
            "lottery": inv.get("ebarimt_lottery"),
            "qr_data": inv.get("ebarimt_qr"),
        },
    }

@app.get("/api/fintech/qpay/callback")
@app.post("/api/fintech/qpay/callback")
async def qpay_webhook_callback(request: Request, invoice_id: Optional[str] = Query(None)):
    """
    Банк / QPay-ийн албан ёсны webhook хүлээн авагч (QPay v2 стандарт: HTTP 200 SUCCESS)
    P1-SEC-03 Hardening: Fail-Closed Provider Verification & Idempotency.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    inv_id = invoice_id or request.query_params.get("qpay_payment_id") or body.get("sender_invoice_no") or body.get("invoice_id")
    if not inv_id:
        return JSONResponse(status_code=400, content={"error": "invoice_id missing"})

    inv = database.get_invoice(inv_id)
    if not inv:
        return JSONResponse(status_code=404, content={"error": "invoice not found"})

    # 1. Idempotency check: Already paid invoices return SUCCESS immediately without duplicate processing
    if inv.get("status") == "PAID":
        logger.info(f"QPay callback for invoice {inv_id} already marked PAID (idempotent 200)")
        return Response(content="SUCCESS", media_type="text/plain", status_code=200)

    page = database.get_page(inv.get("page_id", database.DEFAULT_PAGE_ID)) or {}
    qpay_user = page.get("qpay_username") or os.getenv("QPAY_USERNAME", "").strip()
    qpay_pass = page.get("qpay_password") or os.getenv("QPAY_PASSWORD", "").strip()
    qpay_obj_id = (
        body.get("object_id")
        or request.query_params.get("object_id")
        or request.query_params.get("qpay_payment_id")
        or inv.get("qpay_invoice_id")
    )

    # 2. Credential & Provider Verification (Fail-Closed)
    allow_mock_callback = (
        not core_security.is_production_mode()
        and os.getenv("ALLOW_MOCK_QPAY_CALLBACK", "").strip() in ("1", "true")
    )

    if not (qpay_user and qpay_pass and qpay_obj_id):
        if not allow_mock_callback:
            logger.error(f"QPay callback rejected for {inv_id}: Provider verification required (credentials or object_id missing, Fail-Closed)")
            return Response(content="PROVIDER_VERIFICATION_REQUIRED", media_type="text/plain", status_code=400)
        provider_payment_id = f"MOCK_QPAY_{int(time.time())}"
        callback_verified = 0
    else:
        token = await fintech_service.get_qpay_token(qpay_user, qpay_pass)
        if not token:
            logger.error(f"QPay callback auth failed for {inv_id}: Unable to obtain provider token")
            return Response(content="PROVIDER_AUTH_FAILED", media_type="text/plain", status_code=400)

        expected_amount = int(inv.get("amount") or 0)
        expected_currency = str(inv.get("currency") or "MNT")
        detail = await fintech_service.check_qpay_payment_live_detailed(
            token,
            str(qpay_obj_id),
            expected_amount=expected_amount,
            expected_currency=expected_currency,
        )
        if not detail.get("verified"):
            logger.warning(f"QPay live verification failed for {inv_id}: {detail}")
            return Response(content="FAILED_VERIFICATION", media_type="text/plain", status_code=400)

        provider_payment_id = detail.get("provider_payment_id") or str(qpay_obj_id)
        callback_verified = 1

    # 3. Only process payment once provider verification has genuinely passed
    result = await fintech_service.process_successful_payment(
        inv_id,
        callback_data=body,
        provider_payment_id=provider_payment_id,
        callback_verified=callback_verified,
    )
    # E-03 (Phase 12 finding F-B). This return value used to be discarded, so the
    # `audit_recorded` flag Phase 11 added had no consumer at all: a payment could be
    # settled with no `payment.confirmed` row and the only trace was a log line inside
    # the service. Report it explicitly against this caller.
    #
    # The HTTP answer deliberately does NOT change. QPay retries any non-200, and the
    # money has already moved; a retry cannot write an audit row that the audit store
    # refused, and would only re-drive a settled payment. The audit gap is an
    # operator-reconciliation problem, not a provider-retry problem.
    fintech_service.report_audit_outcome(result, caller="qpay_callback")
    return Response(content="SUCCESS", media_type="text/plain", status_code=200)

@app.post("/api/fintech/invoices/{invoice_id}/simulate-pay")
async def simulate_invoice_payment_api(invoice_id: str, request: Request):
    """
    Төлбөрийн симулятор (P1-SEC-01 Hardening):
    - Default нь DENY (Fail-Closed).
    - Production орчинд ямар ч нөхцөлд симулятор ажиллахгүй (HTTP 403 Forbidden).
    - Зөвхөн аюулгүй DEV/TEST горимд (ENABLE_PAYMENT_SIMULATOR=1 эсвэл ENV=test/development)
      болон зөвхөн баталгаажсан Админ эрхтэй хэрэглэгч ажиллуулах эрхтэй.
    - Tenant isolation: Хэрэв tenant-scoped эрхтэй хэрэглэгч бол тухайн салбарын нэхэмжлэх мөн эсэхийг шалгана.
    """
    if core_security.is_production_mode():
        return JSONResponse(
            {"success": False, "error": "Production орчинд төлбөрийн симулятор хаалттай (Forbidden)."},
            status_code=403,
        )

    sim_enabled = os.getenv("ENABLE_PAYMENT_SIMULATOR", "").strip().lower() in ("1", "true", "yes")
    env_name = os.getenv("ENV", "").strip().lower()
    is_dev_test = env_name in ("development", "dev", "test", "testing")
    if not (sim_enabled or is_dev_test):
        return JSONResponse(
            {"success": False, "error": "Төлбөрийн симулятор идэвхгүй байна (ENABLE_PAYMENT_SIMULATOR=1 шаардлагатай)."},
            status_code=403,
        )

    user = await core_security.resolve_current_user(request)
    if not user:
        return JSONResponse(
            {"success": False, "error": "Нэвтрэх шаардлагатай (Unauthorized)."},
            status_code=401,
        )

    user_role = str(user.get("role") or "").strip().lower()
    if not core_security.is_admin_role(user_role):
        return JSONResponse(
            {"success": False, "error": "Зөвхөн системийн админ симулятор ашиглах эрхтэй (Forbidden)."},
            status_code=403,
        )

    inv = database.get_invoice(invoice_id)
    if not inv:
        return JSONResponse({"success": False, "error": "Нэхэмжлэх олдсонгүй"}, status_code=404)

    user_pid = user.get("page_id")
    if user_pid and inv.get("page_id") and str(inv.get("page_id")) != str(user_pid):
        return JSONResponse(
            {"success": False, "error": "Бусад салбарын нэхэмжлэхийг дуурайлган төлөх эрхгүй (Cross-tenant denied)."},
            status_code=403,
        )

    res = await fintech_service.process_successful_payment(
        invoice_id,
        provider_payment_id=f"SIMULATED_{int(time.time())}",
        callback_verified=0,
    )
    # E-03 (Phase 12 finding F-B). Same duty as the webhook caller above: this path
    # returns the result to an authenticated admin, so the audit outcome is reported
    # explicitly rather than left for the caller to notice a key it was never told to
    # look for. `res["audit_recorded"]` is now present on every return path (True /
    # False / None) instead of only the success path.
    fintech_service.report_audit_outcome(res, caller="simulate_pay")
    return res

@app.get("/api/fintech/summary")
async def get_fintech_summary_api(request: Request, page_id: Optional[str] = Query(None)):
    """Финтек хяналтын самбарын KPI тоон үзүүлэлтүүд"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="fintech:read",
    )
    return database.get_fintech_summary(pid)

@app.get("/api/fintech/invoices")
async def get_fintech_invoices_api(
    request: Request,
    page_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500)
):
    """Нэхэмжлэхүүдийн жагсаалт"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="fintech:read",
    )
    return database.list_invoices(page_id=pid, limit=limit, status=status)

@app.post("/api/fintech/settings")
async def save_fintech_settings_api(
    payload: Dict[str, Any],
    request: Request
):
    """QPay худалдаа эрхлэгчийн эрх болон И-Баримт тохиргоо хадгалах"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="fintech:write",
    )
    target_page_id = str(pid or database.DEFAULT_PAGE_ID)
    stored = database.get_page(target_page_id) or {}

    # Phase 53 (F-53-5): a partial body used to store empty strings over the merchant's
    # payment credentials. Measured live: `{"ebarimt_enabled": 1}` alone wiped qpay_username,
    # qpay_password and qpay_invoice_code and answered success:true.
    values, changed, preserved, cleared, mask_echoes = _merged_settings(
        payload, stored, FINTECH_SETTINGS_SPEC
    )

    success = database.update_page_qpay_settings(
        page_id=target_page_id,
        username=values["qpay_username"],
        password=values["qpay_password"],
        invoice_code=values["qpay_invoice_code"],
        ebarimt_enabled=values["ebarimt_enabled"],
    )
    if not success:
        return {
            "success": False,
            "written": False,
            "page_id": target_page_id,
            "changed": [],
            "preserved": preserved,
            "cleared": [],
            "mask_echoes": mask_echoes,
            "message": f"'{target_page_id}' хуудас олдсонгүй - ямар ч тохиргоо хадгалагдсангүй.",
        }

    # Phase 53 (F-53-6): the audit table held ZERO rows for any payment-credential change,
    # on the endpoint that stores the merchant's QPay password. Money moves with these
    # values, so the change is recorded - names and booleans only, never the password or
    # even its mask.
    if changed:
        action = (
            "fintech.credentials.cleared"
            if ("qpay_password" in cleared or "qpay_username" in cleared)
            else "fintech.credentials.updated"
        )
        actor = await _settings_actor(request)
        audit_failure = _audit_or_report(
            action,
            operation="fintech settings update",
            page_id=target_page_id,
            actor_role=actor["actor_role"],
            actor_id=actor["actor_id"],
            resource_type="fintech_credentials",
            resource_id=target_page_id,
            details={
                "via": "api",
                "changed_fields": changed,
                "preserved_fields": preserved,
                "cleared_fields": cleared,
                "mask_echo_fields": mask_echoes,
                "has_qpay": bool(values["qpay_username"] and values["qpay_password"]),
                "ebarimt_enabled": values["ebarimt_enabled"],
                "session_ref": actor["session_ref"],
            },
            ip_address=core_rate_limit.resolve_client_ip(request),
        )
        if audit_failure is not None:
            return audit_failure

    return {
        "success": True,
        "written": True,
        "page_id": target_page_id,
        "changed": changed,
        "preserved": preserved,
        "cleared": cleared,
        "mask_echoes": mask_echoes,
        "message": (
            "QPay болон И-Баримт тохиргоо амжилттай хадгалагдлаа"
            if changed
            else "Тохиргоо хэвээр үлдлээ - ямар ч утга өөрчлөгдөөгүй."
        ),
    }

@app.post("/api/fintech/create-invoice")
async def create_invoice_manual_api(
    payload: Dict[str, Any],
    request: Request
):
    """Самбараас шууд төлбөрийн нэхэмжлэх үүсгэх (Tenant Scoped — IDOR Protected)"""
    page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="fintech:write",
    )
    amount = int(payload.get("amount", 10000))
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Мөнгөн дүн 0-ээс их байх ёстой")
    desc = payload.get("description", "Үйлчилгээний төлбөр")
    # Phase 36 (F-36-3): honour a trusted proxy's X-Forwarded-Proto so a TLS-terminated
    # deployment does not mint http:// payment callbacks and pay-page links.
    base_url = core_rate_limit.build_external_base_url(request)
    order = await fintech_service.create_payment_order(
        page_id=page_id or database.DEFAULT_PAGE_ID,
        amount=amount,
        description=desc,
        sender_id=payload.get("sender_id", "admin_manual"),
        channel="manual",
        base_url=base_url
    )
    return order

# -------------------------------------------------------------
# 9. КАРГО АГУУЛАХЫН БАРКОД СКАННЕР БА АВТО МЭДЭГДЭЛ (CARGO MODULE)
# -------------------------------------------------------------
@app.get("/scanner", response_class=HTMLResponse)
async def serve_warehouse_scanner(request: Request, page_id: Optional[str] = Query(None)):
    """Гар утасны агуулахын камертай баркод сканнер"""
    pid = page_id or database.DEFAULT_PAGE_ID
    template_env = _html_template_env()
    template = template_env.get_template("scanner.html")
    rendered = template.render(page_id=pid)
    return HTMLResponse(content=rendered)

@app.post("/api/cargo/scan")
async def scan_cargo_package_api(payload: Dict[str, Any], request: Request):
    """Агуулахын ажилтан баркод уншуулах үед ачааг бүртгэж авто мэдэгдэл илгээх (Tenant Scoped)"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="cargo:write",
    )
    code = payload.get("tracking_code", "").strip()
    if not code:
        return JSONResponse(status_code=400, content={"error": "tracking_code is required"})
    loc = payload.get("location", "УБ Төв Агуулах")
    # Phase 36 (F-36-3): honour a trusted proxy's X-Forwarded-Proto so a TLS-terminated
    # deployment does not mint http:// payment callbacks and pay-page links.
    base_url = core_rate_limit.build_external_base_url(request)
    res = await cargo_service.scan_and_notify_package(
        page_id=pid or database.DEFAULT_PAGE_ID,
        tracking_code=code,
        location=loc,
        weight_kg=payload.get("weight_kg"),
        price_amount=payload.get("price_amount"),
        base_url=base_url
    )
    return res

@app.post("/api/cargo/{tracking_code}/deliver")
async def deliver_cargo_api(tracking_code: str, request: Request, page_id: Optional[str] = Query(None)):
    """Ачааг олгосон гэж тэмдэглэх (Tenant Scoped)"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="cargo:write",
    )
    pkg = database.mark_cargo_delivered(pid or database.DEFAULT_PAGE_ID, tracking_code)
    return {"success": bool(pkg), "package": pkg}

@app.get("/api/cargo/packages")
async def list_cargo_packages_api(
    request: Request,
    page_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500)
):
    """Карго ачаануудын жагсаалт"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="cargo:read",
    )
    return database.list_cargo_packages(pid or database.DEFAULT_PAGE_ID, status=status, limit=limit)

@app.get("/api/cargo/summary")
async def get_cargo_summary_api(request: Request, page_id: Optional[str] = Query(None)):
    """Карго самбарын хураангуй KPI үзүүлэлтүүд"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="cargo:read",
    )
    return database.get_cargo_summary(pid or database.DEFAULT_PAGE_ID)

@app.post("/api/cargo/import-manifest")
async def import_cargo_manifest_api(
    request: Request,
    file: UploadFile = File(...),
    page_id: Optional[str] = Query(None),
):
    """Excel файлаас карго ачаануудыг олноор нь импортлох"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="cargo:write",
    )
    file_bytes = await file.read()
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Excel файлын хэмжээ 10MB-аас хэтэрсэн байна!")
    return cargo_service.import_manifest_from_excel_bytes(pid or database.DEFAULT_PAGE_ID, file_bytes, file.filename)

# -------------------------------------------------------------
# 11. ӨГЛӨӨНИЙ 08:30 ЭЗНИЙ ТАЙЛАН & TELEGRAM BOT API
# -------------------------------------------------------------
@app.get("/api/executive/preview")
async def preview_executive_report_api(
    request: Request,
    page_id: Optional[str] = Query(None),
    date_str: Optional[str] = Query(None)
):
    """Өглөөний эзний тайлангийн шуурхай урьдчилсан харагдац"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="executive:read",
    )
    report_text = executive_bot_service.format_executive_report(page_id=pid or database.DEFAULT_PAGE_ID, target_date=date_str)
    metrics = database.get_daily_executive_metrics(page_id=pid or database.DEFAULT_PAGE_ID, date_str=date_str)
    return {"report_text": report_text, "metrics": metrics}

@app.post("/api/executive/send-report")
async def send_executive_report_api(payload: Dict[str, Any], request: Request):
    """Тайланг яг одоо Telegram-аар илгээх"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="executive:write",
    )
    # F-34-1: `payload["chat_id"]` used to be forwarded verbatim, so a caller scoped to
    # tenant A could direct A's report — including A's revenue figures — into tenant B's
    # Telegram chat by naming B's chat id. The recipient is now always the scoped tenant's
    # own `telegram_manager_chat_id`. The dashboard never sent `chat_id`, so nothing that
    # works today stops working; an explicitly supplied value is rejected rather than
    # silently ignored, so a caller cannot believe it took effect.
    if str(payload.get("chat_id") or "").strip():
        raise HTTPException(
            status_code=400,
            detail="chat_id тохируулах боломжгүй. Хүлээн авагч нь тухайн салбарын тохиргооноос тодорхойлогдоно.",
        )
    date_str = payload.get("date_str")
    res = await executive_bot_service.send_executive_report(
        chat_id=None, page_id=pid or database.DEFAULT_PAGE_ID, target_date=date_str
    )
    return res

# ---------------------------------------------------------------------------
# Phase 53 — settings forms MERGE, they do not replace (F-53-1 … F-53-9)
# ---------------------------------------------------------------------------
def _settings_text(value: Any) -> str:
    """The stored form of a text field: a string, stripped, never None."""
    return "" if value is None else str(value).strip()


def _settings_flag(value: Any) -> int:
    """The stored form of an on/off field: 1 or 0.

    The rule before Phase 53 was ``1 if payload.get(key, True) else 0``. Two defects, both
    measured live: an ABSENT key meant "on", so a partial save that named only the report
    time re-enabled daily reports the operator had turned off (F-53-2, and `worker.py` plus
    the scheduler loop in this file act on that column), and the string "0" was truthy, so
    it meant "on" too.
    """
    if isinstance(value, str):
        return 0 if value.strip().lower() in ("", "0", "false", "no", "off") else 1
    return 1 if value else 0


def _settings_hours(value: Any) -> int:
    """The stored form of a delay in hours: an int, falling back to the schema default."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 2


#: Every settings form that writes several stored columns from one JSON body. Each entry maps
#: the payload key to ``(stored column, default when the row has none, coerce, mask_style)``.
#: ``mask_styles`` is empty only for a non-credential, and says which mask shapes the API shows
#: for that field, so an echo of one is recognised instead of being stored as a new secret.
EXECUTIVE_SETTINGS_SPEC = {
    "telegram_bot_token": ("telegram_bot_token", "", _settings_text, ("ellipsis", "bullets")),
    "telegram_manager_chat_id": ("telegram_manager_chat_id", "", _settings_text, None),
    "daily_report_time": ("daily_report_time", "08:30", _settings_text, None),
    "daily_report_enabled": ("daily_report_enabled", 1, _settings_flag, None),
}
FINTECH_SETTINGS_SPEC = {
    "qpay_username": ("qpay_username", "", _settings_text, None),
    "qpay_password": ("qpay_password", "", _settings_text, ("bullets",)),
    "qpay_invoice_code": ("qpay_invoice_code", "", _settings_text, None),
    "ebarimt_enabled": ("ebarimt_enabled", 1, _settings_flag, None),
}
RETENTION_RULE_SPEC = {
    "delay_hours": ("delay_hours", 2, _settings_hours, None),
    "message_template": ("message_template", "", _settings_text, None),
    "is_active": ("is_active", 1, _settings_flag, None),
}
_MASK_BULLET = "\u2022"


def _is_mask_echo(incoming: str, stored_value: str, mask_styles) -> bool:
    """True when `incoming` is a mask this API showed, not a credential.

    Three recognised shapes, and the first two do NOT depend on anything being stored:

    * ``head...tail`` — what `GET /api/executive/settings` builds for the bot token;
    * a value containing the bullet character — what `database.mask_secret` ships for the
      QPay password and for `telegram_bot_token_masked` on `GET /api/pages`;
    * an exact match against the mask of the value that IS stored, in any of the three
      widths the API uses.

    Measured, the first version of this function required a non-empty `stored_value` before
    it looked at the incoming text, so a mask posted at a field that had just been emptied
    was STORED AS THE CREDENTIAL: the probe page ended up holding a QPay password made of
    bullets and a bot token of `111222...TIC`. A payment credential that is really a mask
    fails in the most confusing way available, so the shape rules now apply to an empty
    field as well.

    The consequence, stated rather than hidden: a credential whose real value contains the
    bullet character cannot be stored through these forms, because it cannot be told apart
    from a mask. The bullet is this API's own mask character and no QPay password or Telegram
    bot token uses it; the response names the field in `mask_echoes`, so a caller can see the
    value was not stored instead of wondering why.
    """
    if not mask_styles or not incoming:
        return False
    if "ellipsis" in mask_styles and "..." in incoming:
        return True
    if "bullets" in mask_styles and _MASK_BULLET in incoming:
        return True
    if not stored_value:
        return False
    return any(
        incoming == database.mask_secret(stored_value, head, tail)
        for head, tail in ((6, 4), (4, 4), (2, 2))
    )


def _merged_settings(payload: Dict[str, Any], stored: Dict[str, Any], spec: Dict[str, tuple]):
    """Merge one settings form over what is already stored.

    Returns ``(values, changed, preserved, cleared, mask_echoes)``. ``values`` holds what to
    store; every list holds **field names only**, so a response or an audit row built from
    them can say what moved without carrying a credential. `mask_echoes` names the fields
    where the caller posted a mask and the stored value was kept instead.

    The rule, which is the whole fix:

    * a key the payload does not NAME keeps the value already stored — `preserved`;
    * a key named with an empty value is an EXPLICIT clear — that is the documented way to
      unregister a report recipient (O-51-5) and the live checks depend on it, so it stays;
    * a key named with the mask the API showed is treated as unchanged, not stored.

    Before this, all three handlers read ``payload.get(key, "")`` and handed the result
    straight to an UPDATE, so a body that named one field stored empty strings over every
    other field. Measured live on a disposable page: `POST /api/executive/settings
    {"daily_report_time": "09:15"}` destroyed the stored bot token AND the recipient
    (F-53-1), and `POST /api/fintech/settings {"ebarimt_enabled": 1}` destroyed the QPay
    merchant username, password and invoice code (F-53-5). This is the same defect class B4
    fixed for `POST /api/update-keys`, which destroyed 35 keys the same way.
    """
    values: Dict[str, Any] = {}
    changed, preserved, cleared = [], [], []
    mask_echoes = []
    for key, (stored_key, default, coerce, mask_styles) in spec.items():
        raw_stored = stored.get(stored_key)
        stored_value = coerce(default if raw_stored is None else raw_stored)
        if key not in payload:
            values[key] = stored_value
            preserved.append(key)
            continue
        incoming = coerce(payload.get(key))
        if _is_mask_echo(str(incoming), str(stored_value), mask_styles):
            values[key] = stored_value
            preserved.append(key)
            mask_echoes.append(key)
            continue
        values[key] = incoming
        if incoming == stored_value:
            preserved.append(key)
        else:
            changed.append(key)
            if isinstance(incoming, str) and not incoming and stored_value not in ("", 0):
                # a stored value was removed. An on/off field is 1 or 0, not "cleared".
                cleared.append(key)
    return (
        values,
        sorted(set(changed)),
        sorted(set(preserved)),
        sorted(set(cleared)),
        sorted(set(mask_echoes)),
    )


async def _settings_actor(request: Request) -> Dict[str, str]:
    """Who is acting, in a form that carries no credential.

    `enforce_tenant_scope` resolves the user and returns only the page id, so this resolves
    it once more: one extra indexed `sessions` lookup per settings save, on endpoints an
    operator clicks a few times a day. The session token is a bearer credential, so it is
    recorded only as a 12-hex-character SHA-256 prefix — enough for an auditor to tie
    several rows to one login, not enough to replay it.
    """
    user = await core_security.resolve_current_user(request) or {}
    token = str(user.get("session_token") or "")
    return {
        "actor_role": str(user.get("role") or "unknown"),
        "actor_id": str(user.get("page_id") or ""),
        "session_ref": hashlib.sha256(token.encode("utf-8")).hexdigest()[:12] if token else "",
    }


@app.get("/api/executive/settings")
async def get_executive_settings_api(request: Request, page_id: Optional[str] = Query(None)):
    """Telegram бот болон өглөөний тайлангийн тохиргоог авах"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="executive:read",
    )
    page = database.get_page(pid or database.DEFAULT_PAGE_ID) or {}
    bot_token = page.get("telegram_bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "")
    masked_token = f"{bot_token[:6]}...{bot_token[-4:]}" if len(bot_token) > 10 else ("Тохируулаагүй" if not bot_token else "***")
    return {
        "telegram_bot_token_masked": masked_token,
        "has_bot_token": bool(bot_token),
        "telegram_manager_chat_id": page.get("telegram_manager_chat_id") or os.getenv("TELEGRAM_MANAGER_CHAT_ID", ""),
        "daily_report_time": page.get("daily_report_time", "08:30"),
        "daily_report_enabled": bool(page.get("daily_report_enabled", 1))
    }

@app.post("/api/executive/settings")
async def update_executive_settings_api(payload: Dict[str, Any], request: Request):
    """Telegram бот болон өглөөний тайлангийн тохиргоог хадгалах"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="executive:write",
    )
    target_page_id = str(pid or database.DEFAULT_PAGE_ID)
    stored = database.get_page(target_page_id) or {}

    # Phase 53 (F-53-1, F-53-2): merge over what is stored instead of replacing it.
    values, changed, preserved, cleared, mask_echoes = _merged_settings(
        payload, stored, EXECUTIVE_SETTINGS_SPEC
    )

    wrote = database.update_page_telegram_settings(
        page_id=target_page_id,
        bot_token=values["telegram_bot_token"],
        manager_chat_id=values["telegram_manager_chat_id"],
        report_time=values["daily_report_time"],
        report_enabled=values["daily_report_enabled"],
    )
    if not wrote:
        # F-53-4: no row matched, so nothing was stored. This handler used to answer
        # success:true here - measured against a page that was never created, it wrote 0
        # rows and reported "амжилттай хадгалагдлаа". The status stays 200 because the
        # dashboard branches on `data.success`, and the message now says what happened.
        return {
            "success": False,
            "written": False,
            "page_id": target_page_id,
            "changed": [],
            "preserved": preserved,
            "cleared": [],
            "mask_echoes": mask_echoes,
            "message": f"'{target_page_id}' хуудас олдсонгүй - ямар ч тохиргоо хадгалагдсангүй.",
        }

    # Phase 53 (F-53-3): this is the path that changes WHO receives the daily executive
    # report with `executive:write`, and it wrote no audit row at all - measured, four
    # recipient changes left the audit table at 78 rows. O-51-4 (Phase 52) audited the
    # `/start` path in `executive_bot_service`; the same state change reached through the
    # API was still invisible, so an auditor querying `executive.recipient.%` saw only the
    # unauthenticated path. The action names come from that same vocabulary, so one query
    # now covers both. A save that changes nothing writes nothing: unlike an unauthenticated
    # `/start`, where "the same identity asked again" is itself evidence, a repeated form
    # save is not an event.
    previous_manager = _settings_text(stored.get("telegram_manager_chat_id"))
    new_manager = values["telegram_manager_chat_id"]
    if previous_manager != new_manager:
        if not previous_manager:
            action = "executive.recipient.registered"
        elif not new_manager:
            action = "executive.recipient.cleared"
        else:
            action = "executive.recipient.transferred"
    elif changed:
        action = "executive.settings.updated"
    else:
        action = None

    if action:
        actor = await _settings_actor(request)
        audit_failure = _audit_or_report(
            action,
            operation="executive settings update",
            page_id=target_page_id,
            actor_role=actor["actor_role"],
            actor_id=actor["actor_id"],
            resource_type="executive_recipient",
            resource_id=target_page_id,
            details={
                "via": "api",
                "chat_id": new_manager,
                "previous_chat_id": previous_manager,
                "changed_fields": changed,
                "preserved_fields": preserved,
                "cleared_fields": cleared,
                "mask_echo_fields": mask_echoes,
                # the bot token is named as a fact, never as a value or a mask
                "bot_token_changed": "telegram_bot_token" in changed,
                "bot_token_cleared": "telegram_bot_token" in cleared,
                "has_bot_token": bool(values["telegram_bot_token"]),
                "daily_report_enabled": values["daily_report_enabled"],
                "session_ref": actor["session_ref"],
            },
            ip_address=core_rate_limit.resolve_client_ip(request),
        )
        if audit_failure is not None:
            return audit_failure

    return {
        "success": True,
        "written": True,
        "page_id": target_page_id,
        "changed": changed,
        "preserved": preserved,
        "cleared": cleared,
        "mask_echoes": mask_echoes,
        "message": (
            "Telegram болон өглөөний тайлангийн тохиргоо амжилттай хадгалагдлаа"
            if changed
            else "Тохиргоо хэвээр үлдлээ - ямар ч утга өөрчлөгдөөгүй."
        ),
    }

# -------------------------------------------------------------
# 12. АВТОМАТ МАРКЕТИНГ & ХАРИЛЦАГЧИЙГ СЭРГЭЭХ API (RETENTION & BROADCAST)
# -------------------------------------------------------------
@app.get("/api/retention/rules")
async def get_retention_rules_api(request: Request, page_id: Optional[str] = Query(None)):
    """Салбарын автомат сэргээлтийн дүрмүүдийн жагсаалт"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="retention:read",
    )
    rules = database.get_automated_rules(pid or database.DEFAULT_PAGE_ID)
    return {"rules": rules}

@app.post("/api/retention/rules")
async def update_retention_rule_api(payload: Dict[str, Any], request: Request):
    """Сэргээх дүрмийг шинэчлэх"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="retention:write",
    )
    target_page_id = str(pid or database.DEFAULT_PAGE_ID)
    rule_type = _settings_text(payload.get("rule_type"))
    if not rule_type:
        raise HTTPException(status_code=400, detail="rule_type and message_template are required")

    # Phase 53 (F-53-9): `payload.get("delay_hours", 2)` and `payload.get("is_active", True)`
    # were written straight into an upsert, so a body naming only the message reset the delay
    # to 2 hours and re-activated a rule the operator had switched off - which then messages
    # customers on its own schedule. `rule_type` stays required because it is half of the
    # upsert key; the other columns merge over the stored row.
    stored_rows = {
        str(row.get("rule_type")): row
        for row in database.get_automated_rules(target_page_id)
    }
    values, changed, preserved, _cleared, _mask_echoes = _merged_settings(
        payload, stored_rows.get(rule_type, {}), RETENTION_RULE_SPEC
    )
    if not values["message_template"]:
        raise HTTPException(status_code=400, detail="rule_type and message_template are required")

    database.update_automated_rule(
        page_id=target_page_id,
        rule_type=rule_type,
        delay_hours=values["delay_hours"],
        message_template=values["message_template"],
        is_active=bool(values["is_active"]),
    )
    # Deliberately not audited. A retention rule is marketing content, not an authorisation
    # fact or a credential, and this codebase audits the first two; adding a row per rule
    # edit would bury the recipient and payment rows that matter. Recorded here so the
    # omission is a decision, not an oversight.
    return {
        "success": True,
        "page_id": target_page_id,
        "rule_type": rule_type,
        "changed": changed,
        "preserved": preserved,
        "message": "Дүрэм амжилттай хадгалагдлаа",
    }

@app.post("/api/retention/broadcast")
async def send_broadcast_api(payload: Dict[str, Any], request: Request):
    """1-Click Broadcast илгээх"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="retention:write",
    )
    title = payload.get("title", "").strip()
    message = payload.get("message", "").strip()
    target_segment = payload.get("target_segment", "all")
    channel = payload.get("channel", "all")
    
    if not title or not message:
        raise HTTPException(status_code=400, detail="Гарчиг болон зурвасын эх бичвэр шаардлагатай")
        
    res = await retention_service.send_broadcast(
        page_id=pid or database.DEFAULT_PAGE_ID,
        title=title,
        message=message,
        target_segment=target_segment,
        channel=channel
    )
    return res

@app.get("/api/retention/campaigns")
async def list_campaigns_api(
    request: Request,
    page_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=200)
):
    """Маркетингийн өмнөх кампэйнуудын түүх"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="retention:read",
    )
    return database.list_marketing_campaigns(pid or database.DEFAULT_PAGE_ID, limit=limit)

@app.get("/api/retention/summary")
async def get_retention_summary_api(request: Request, page_id: Optional[str] = Query(None)):
    """Маркетингийн нэгдсэн үзүүлэлтүүд"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="retention:read",
    )
    return database.get_marketing_summary(pid or database.DEFAULT_PAGE_ID)

@app.post("/api/retention/trigger-checks")
async def trigger_retention_checks_api(request: Request):
    """Автомат сэргээлтийн шалгалтыг гараар яг одоо ажиллуулах (тухайн салбарын хүрээнд)"""
    # F-34-2: this used to call `require_permission` only and then run the all-tenants
    # sweep, so a `client` scoped to one tenant could make the server send follow-up
    # messages into every other tenant. Scope is now resolved to the caller's tenant; only
    # an admin (whose scope resolves to the default page unless one is named) can widen it.
    page_id = request.query_params.get("page_id")
    scoped = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="retention:write",
    )
    if not scoped:
        raise HTTPException(status_code=403, detail="Салбар тодорхойгүй байна! (Tenant scope required)")
    base_url = core_rate_limit.build_external_base_url(request).rstrip("/")
    stats = await retention_service.run_automated_retention_checks(base_url=base_url, page_id=scoped)
    return {"success": True, "stats": stats, "page_id": str(scoped)}

# -------------------------------------------------------------
# 13. ЦАГ ЗАХИАЛГА & ИНТЕРАКТИВ ХУАНЛИ API (APPOINTMENTS)
# -------------------------------------------------------------
@app.get("/api/appointments")
async def list_appointments_api(
    request: Request,
    page_id: Optional[str] = Query(None),
    date_str: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500)
):
    """Салбарын цаг захиалгуудын жагсаалт"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="appointments:read",
    )
    appts = database.list_appointments(page_id=pid or database.DEFAULT_PAGE_ID, date_str=date_str, status=status, limit=limit)
    return {"count": len(appts), "data": appts}

@app.post("/api/appointments")
async def create_appointment_manual_api(payload: Dict[str, Any], request: Request):
    """Самбараас шууд шинэ цаг захиалга нэмэх"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.get("page_id"),
        require_auth=True,
        permission="appointments:write",
    )
    name = payload.get("customer_name", "").strip()
    phone = payload.get("customer_phone", "").strip()
    service = payload.get("service_name", "").strip()
    date_val = payload.get("appointment_date", "").strip()
    time_val = payload.get("appointment_time", "").strip()
    notes = payload.get("notes", "").strip()

    if not name or not phone or not date_val or not time_val:
        raise HTTPException(status_code=400, detail="Нэр, утас, огноо, цаг заавал шаардлагатай")

    appt = database.create_appointment(
        page_id=pid or database.DEFAULT_PAGE_ID,
        customer_name=name,
        customer_phone=phone,
        service_name=service or "Үйлчилгээ",
        appointment_date=date_val,
        appointment_time=time_val,
        channel="dashboard",
        notes=notes
    )
    if not appt:
        return JSONResponse(status_code=409, content={"success": False, "message": f"{date_val} {time_val} цагт өөр захиалга байна"})
    return {"success": True, "appointment": appt}

@app.post("/api/appointments/{appointment_id}/status")
async def update_appointment_status_api(appointment_id: int, payload: Dict[str, Any], request: Request):
    """Цаг захиалгын төлөв өөрчлөх ('CONFIRMED', 'COMPLETED', 'CANCELLED') — Tenant Scoped"""
    user = await core_security.require_permission(request, "appointments:write")
    appt = database.get_appointment_by_id(appointment_id)
    if not appt:
        raise HTTPException(status_code=404, detail="Appointment not found")
    core_security.verify_resource_tenant_ownership(user, appt.get("page_id"), require_auth=True)
    new_status = payload.get("status", "CONFIRMED")
    success = database.update_appointment_status(appointment_id, new_status)
    return {"success": success, "status": new_status}

@app.get("/api/appointments/summary")
async def get_appointments_summary_api(request: Request, page_id: Optional[str] = Query(None)):
    """Цаг захиалгын хяналтын самбарын тооцоолол"""
    pid = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        permission="appointments:read",
    )
    return database.get_appointments_summary(pid or database.DEFAULT_PAGE_ID)

# -------------------------------------------------------------
# 14. MULTIMODAL VOICE NOTE CHAT API (ДУУТ ЗУРВАС СЕРВЕР)
# -------------------------------------------------------------
@app.post("/api/chat/voice")
async def voice_chat_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(None),
    audio_file: Optional[UploadFile] = File(None),
    page_id: Optional[str] = Form(None),
    sender_id: Optional[str] = Form("web_voice_user"),
    text: Optional[str] = Form("")
):
    """Вэб симулятор болон гадаад сувгаас дуут зурвас хүлээн авч Gemini AI-аар боловсруулах"""
    upload = file or audio_file
    if not upload:
        raise HTTPException(status_code=400, detail="Аудио файл шаардлагатай")

    audio_bytes = await upload.read()
    if len(audio_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Аудио файлын хэмжээ 10MB-аас хэтэрсэн байна!")
    pid = page_id or database.DEFAULT_PAGE_ID
    mime = upload.content_type or "audio/webm"
    fname = (upload.filename or "").lower()
    if "ogg" in mime or fname.endswith(".ogg"):
        mime = "audio/ogg"
    elif "mp3" in mime or fname.endswith(".mp3"):
        mime = "audio/mp3"
    elif "wav" in mime or fname.endswith(".wav"):
        mime = "audio/wav"

    result = await asyncio.to_thread(
        agent.process_message,
        text=text or "",
        audio_bytes=audio_bytes,
        audio_mime=mime,
        sender_id=sender_id,
        channel="web_voice",
        page_id=pid
    )
    return result

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
async def serve_dashboard():
    with open("dashboard.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/privacy", response_class=HTMLResponse)
async def serve_privacy_policy():
    return """<!DOCTYPE html>
<html lang="mn">
<head>
  <meta charset="UTF-8">
  <title>Нууцлалын Бодлого — Гэрэгэ</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#0a0a0c] text-[#ece8e1] min-h-screen p-6 md:p-12 font-sans">
  <div class="max-w-3xl mx-auto space-y-6 bg-[#121316] p-8 rounded-2xl border border-white/10">
    <h1 class="text-3xl font-bold text-white">Нууцлалын Бодлого (Privacy Policy)</h1>
    <p class="text-xs text-stone-400">Сүүлд шинэчлэгдсэн: 2026-11-11</p>
    
    <div class="space-y-4 text-sm text-stone-300 leading-relaxed">
      <h2 class="text-lg font-semibold text-white">1. Ерөнхий зүйл</h2>
      <p>Энэхүү систем нь Facebook Messenger, Instagram болон вэб сувгаар ирсэн харилцагчийн асуулт, хүсэлтэд хиймэл оюун ухааны тусламжтайгаар шуурхай хариулах зориулалттай харилцагчийн үйлчилгээний платформ юм.</p>

      <h2 class="text-lg font-semibold text-white">2. Бид ямар мэдээлэл цуглуулдаг вэ?</h2>
      <p>Бид зөвхөн хэрэглэгчийн бичсэн чат мессеж, лавлагаа, холбоо барих утас болон нэр, гүйлгээний баримтын мэдээллийг хэрэглэгчийн хүсэлтээр үйлчилгээ үзүүлэх зорилгоор бүртгэнэ.</p>

      <h2 class="text-lg font-semibold text-white">3. Мэдээллийн ашиглалт</h2>
      <p>Цуглуулсан мэдээллийг зөвхөн тухайн байгууллага, салбарын үйлчилгээ үзүүлэх, захиалга болон бүртгэлийг баталгаажуулахад ашиглах бөгөөд гуравдагч этгээдэд дамжуулахгүй.</p>

      <h2 class="text-lg font-semibold text-white">4. Мэдээлэл устгах (User Data Deletion)</h2>
      <p>Хэрэглэгч өөрийн бүртгэгдсэн мэдээллийг устгуулахыг хүсвэл тухайн салбарын чатаар "Бүртгэл устгах" гэж бичих эсвэл удирдлагад мэдэгдэн устгуулах бүрэн эрхтэй.</p>

      <h2 class="text-lg font-semibold text-white">5. Холбоо барих</h2>
      <p>Асуулт, санал байвал салбарын чатаар болон системийн удирдлагад хандана уу.</p>
    </div>
  </div>
</body>
</html>"""

@app.get("/terms", response_class=HTMLResponse)
async def serve_terms_of_service():
    return """<!DOCTYPE html>
<html lang="mn">
<head>
  <meta charset="UTF-8">
  <title>Үйлчилгээний Нөхцөл — Гэрэгэ</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#0a0a0c] text-[#ece8e1] min-h-screen p-6 md:p-12 font-sans">
  <div class="max-w-3xl mx-auto space-y-6 bg-[#121316] p-8 rounded-2xl border border-white/10">
    <h1 class="text-3xl font-bold text-white">Үйлчилгээний Нөхцөл (Terms of Service)</h1>
    <p class="text-xs text-stone-400">Сүүлд шинэчлэгдсэн: 2026-11-11</p>
    <div class="space-y-4 text-sm text-stone-300 leading-relaxed">
      <p>Манай харилцагчийн ухаалаг туслахыг ашигласнаар та энэхүү үйлчилгээний нөхцөлийг зөвшөөрсөнд тооцогдоно.</p>
      <p>Систем нь мэдээлэл олгох, бүртгэл хийх зорилготой бөгөөд албан ёсны шийдвэрийг байгууллагын менежер эцэслэн баталгаажуулна.</p>
    </div>
  </div>
</body>
</html>"""

@app.get("/b/{branch_slug}", response_class=HTMLResponse)
@app.get("/{branch_slug}", response_class=HTMLResponse)
async def serve_branch_portal_or_page(branch_slug: str):
    """
    Салбар бүрийн тусгай цэвэр холбоос (жишээ нь: /cargo, /salon, /turshilt).
    Админы эрх задруулахгүйгээр зөвхөн тухайн салбарын эрхээр эсвэл нэвтрэх цонхоор нээнэ.
    """
    slug_clean = branch_slug.strip().lower()
    if slug_clean in {"favicon.ico", "robots.txt", "widget.js", "api", "webhook", "admin", "dashboard", "privacy", "terms", "pay", "static", "scanner"}:
        raise HTTPException(status_code=404, detail="Not found")

    all_pages = database.get_all_pages()
    matched_page = None
    for p in all_pages:
        pid = str(p.get("page_id") or "").lower()
        uname = str(p.get("client_username") or "").lower()
        pname = str(p.get("name") or "").lower()
        if slug_clean in {pid, uname, pname} or slug_clean == pname.replace(" ", "-"):
            matched_page = p
            break

    with open("dashboard.html", "r", encoding="utf-8") as f:
        html_str = f.read()

    if matched_page:
        # Inject safe branch hint (never exposes admin token, only pre-selects branch for client login)
        branch_hint = json.dumps({
            "page_id": matched_page.get("page_id"),
            "name": matched_page.get("name"),
            "client_username": matched_page.get("client_username") or ""
        }, ensure_ascii=False)
        inject_script = f"<script>window.__INITIAL_BRANCH_HINT__ = {branch_hint};</script></head>"
        html_str = html_str.replace("</head>", inject_script, 1)

    return html_str

if __name__ == "__main__":
    import uvicorn

    # Phase 27 (B104). `python main.py` is the developer entrypoint; it used to bind
    # 0.0.0.0 with reload=True, which is `--reload`'s watch-everything behaviour applied to
    # a server reachable from the whole local network. Nothing in the deployment path uses
    # this block - the container runs `uvicorn main:app` directly (see Dockerfile) - so
    # binding loopback by default costs nothing and closes the "I ran it on my laptop at a
    # cafe" case, where development mode also means dev CORS and dev auth.
    #
    # The deployment genuinely needs 0.0.0.0 *inside the container*, because there is no
    # reverse proxy in this topology (docker-compose.prod.yml publishes port 8000 directly).
    # That is unchanged, and it is set by the Dockerfile, not by this block. Anyone who
    # needs to reach this entrypoint from another machine sets HOST explicitly and knows
    # what they are doing.
    host = os.getenv("HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.getenv("PORT", 8000))
    reload_flag = os.getenv("RELOAD", "1") not in ("0", "false", "False", "no")
    shown = "localhost" if host in ("127.0.0.1", "::1") else host
    print(f"Гэрэгэ — Харилцааны Ухаалаг Систем: http://{shown}:{port}")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print(
            f"warning: binding {host} exposes the development server, with reload enabled, "
            "to every interface on this machine. Do not use this entrypoint in production."
        )
    uvicorn.run("main:app", host=host, port=port, reload=reload_flag)
