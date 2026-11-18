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

@asynccontextmanager
async def lifespan(app: FastAPI):
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

    scheduler_task = None
    if os.getenv("DISABLE_INLINE_SCHEDULER", "0") != "1":
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

META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "agent_verify_secret_token_123")
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
    expected_token = os.getenv("META_VERIFY_TOKEN", META_VERIFY_TOKEN).strip()
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
                            try:
                                async with httpx.AsyncClient() as client:
                                    img_resp = await client.get(img_url, timeout=15.0)
                                    if img_resp.status_code == 200:
                                        image_bytes = img_resp.content
                                        logger.info(f"Image downloaded from Meta: {len(image_bytes)} bytes (Page: {target_page_id})")
                            except Exception as e:
                                logger.error(f"Image download error: {e}")
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
    category = str(payload.get("category", "general")).strip()
    token = str(payload.get("page_access_token", "")).strip()
    verify_token = str(payload.get("verify_token", "agent_verify_secret_token_123")).strip()
    gemini_key = str(payload.get("gemini_api_key", "")).strip()
    monthly_limit = int(payload.get("monthly_token_limit", 100000))
    k_json = payload.get("knowledge_json", "{}")
    if isinstance(k_json, dict):
        k_json = json.dumps(k_json, ensure_ascii=False)

    if not page_id or not name:
        return JSONResponse({"error": "Page ID болон Нэр шаардлагатай"}, status_code=400)

    try:
        database.save_page(
            page_id=page_id,
            name=name,
            category=category,
            page_access_token=token,
            verify_token=verify_token,
            knowledge_json=k_json,
            gemini_api_key=gemini_key,
            monthly_token_limit=monthly_limit
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
        details={"name": name, "category": category, "is_active": True},
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
    audit_error = _audit_or_report(
        "page.credentials.updated",
        operation=f"Хуудас ({target_page_id}) нэвтрэх эрх шинэчлэх",
        page_id=str(target_page_id),
        actor_role="admin",
        resource_type="page",
        resource_id=str(target_page_id),
        # The username may be a phone number or an email, so only its length is
        # recorded. The password is never touched: it is not in scope here at all.
        details={"username_length": len(username)},
    )
    if audit_error is not None:
        return audit_error
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
        verify_token=page_obj.get("verify_token", "agent_verify_secret_token_123"),
        knowledge_json=json.dumps(kj, ensure_ascii=False, indent=2),
        gemini_api_key=page_obj.get("gemini_api_key", ""),
        monthly_token_limit=page_obj.get("monthly_token_limit", 100000)
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
            verify_token=page_obj.get("verify_token", "agent_verify_secret_token_123"),
            knowledge_json=k_str,
            gemini_api_key=page_obj.get("gemini_api_key", ""),
            monthly_token_limit=page_obj.get("monthly_token_limit", 100000)
        )
    if target_id == database.DEFAULT_PAGE_ID:
        knowledge_base.save_knowledge(payload)

    agent.reset_sessions(target_id)
    return {"status": "success", "message": f"{target_id} хуудасны мэдлэгийн сан амжилттай шинэчлэгдлээ!"}

# -------------------------------------------------------------
# 11. СИСТЕМИЙН ЭРҮҮЛ МЭНД БА ТҮЛХҮҮРҮҮД
# -------------------------------------------------------------
@app.get("/api/health")
async def health_check():
    load_dotenv(override=True)
    rows = database.get_all_registrations()
    pages = database.get_all_pages()
    # E-01: `get_active_sessions` is tenant-scoped, so the cross-tenant total is an
    # explicit per-tenant aggregate instead of an unscoped "give me everything" call.
    sessions = [s for p in pages for s in database.get_active_sessions(page_id=p["page_id"])]
    return JSONResponse({
        "status": "healthy",
        "gemini_ready": agent.is_gemini_ready(),
        "model": agent.get_model_name(),
        # SEC-07: lets an operator confirm limits are actually shared across workers
        # rather than silently per-process.
        "rate_limit_backend": core_rate_limit.get_limiter().backend(),
        "rate_limits_shared_across_workers": core_rate_limit.get_limiter().is_shared(),
        "meta_token_configured": bool(os.getenv("META_PAGE_ACCESS_TOKEN", "").strip()),
        "telegram_configured": bool(os.getenv("TELEGRAM_BOT_TOKEN", "").strip()),
        "total_pages": len(pages),
        "total_leads": len(rows),
        "active_sessions": len(sessions)
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

@app.post("/api/update-keys")
async def update_keys(payload: Dict[str, str], request: Request):
    """Админы системийн түлхүүрүүд засах (Зөвхөн Админ — P0-2)"""
    await core_security.require_admin(request)

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

    # Production горимд plaintext .env файл руу бичихгүй
    if not core_security.is_production_mode() and os.getenv("ALLOW_ENV_FILE_WRITE", "0") == "1":
        keys_map = {
            "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY", ""),
            "GEMINI_MODEL": os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite"),
            "META_PAGE_ACCESS_TOKEN": os.getenv("META_PAGE_ACCESS_TOKEN", ""),
            "META_VERIFY_TOKEN": os.getenv("META_VERIFY_TOKEN", ""),
            "TELEGRAM_BOT_TOKEN": os.getenv("TELEGRAM_BOT_TOKEN", ""),
            "TELEGRAM_MANAGER_CHAT_ID": os.getenv("TELEGRAM_MANAGER_CHAT_ID", ""),
            "ADMIN_PASSWORD": os.getenv("ADMIN_PASSWORD", database.DEFAULT_ADMIN_PASSWORD),
            "PORT": os.getenv("PORT", "8000")
        }
        try:
            with open(".env", "w", encoding="utf-8") as f:
                for k, v in keys_map.items():
                    f.write(f"{k}={v}\n")
        except Exception as env_err:
            logger.warning(f"Could not write .env file (read-only fs): {env_err}")

    return {"status": "success", "message": "Тохиргоо амжилттай хадгалагдлаа!"}

# -------------------------------------------------------------
# 8. ФИНТЕК & ТӨЛБӨРИЙН АВТОМАТЖУУЛАЛТ (QPAY v2, DEEP LINKS, E-BARIMT)
# -------------------------------------------------------------
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

    import jinja2
    template_loader = jinja2.FileSystemLoader(searchpath="templates")
    template_env = jinja2.Environment(loader=template_loader)
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
    await fintech_service.process_successful_payment(
        inv_id,
        callback_data=body,
        provider_payment_id=provider_payment_id,
        callback_verified=callback_verified,
    )
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

    success = database.update_page_qpay_settings(
        page_id=pid,
        username=payload.get("qpay_username", ""),
        password=payload.get("qpay_password", ""),
        invoice_code=payload.get("qpay_invoice_code", ""),
        ebarimt_enabled=payload.get("ebarimt_enabled", 1)
    )
    return {"success": success}

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
    base_url = str(request.base_url)
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
    import jinja2
    template_loader = jinja2.FileSystemLoader(searchpath="templates")
    template_env = jinja2.Environment(loader=template_loader)
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
    base_url = str(request.base_url)
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
    chat_id = payload.get("chat_id")
    date_str = payload.get("date_str")
    res = await executive_bot_service.send_executive_report(chat_id=chat_id, page_id=pid or database.DEFAULT_PAGE_ID, target_date=date_str)
    return res

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
    bot_token = payload.get("telegram_bot_token", "")
    manager_chat_id = payload.get("telegram_manager_chat_id", "")
    daily_report_time = payload.get("daily_report_time", "08:30")
    daily_report_enabled = 1 if payload.get("daily_report_enabled", True) else 0

    if bot_token and "..." in bot_token:
        page = database.get_page(pid or database.DEFAULT_PAGE_ID) or {}
        bot_token = page.get("telegram_bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "")

    database.update_page_telegram_settings(
        page_id=pid or database.DEFAULT_PAGE_ID,
        bot_token=bot_token,
        manager_chat_id=manager_chat_id,
        report_time=daily_report_time,
        report_enabled=daily_report_enabled
    )
    return {"success": True, "message": "Telegram болон өглөөний тайлангийн тохиргоо амжилттай хадгалагдлаа"}

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
    rule_type = payload.get("rule_type")
    delay_hours = payload.get("delay_hours", 2)
    message_template = payload.get("message_template", "")
    is_active = payload.get("is_active", True)
    
    if not rule_type or not message_template:
        raise HTTPException(status_code=400, detail="rule_type and message_template are required")
        
    database.update_automated_rule(
        page_id=pid or database.DEFAULT_PAGE_ID,
        rule_type=rule_type,
        delay_hours=int(delay_hours),
        message_template=message_template,
        is_active=bool(is_active)
    )
    return {"success": True, "message": "Дүрэм амжилттай хадгалагдлаа"}

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
    """Автомат сэргээлтийн шалгалтыг гараар яг одоо ажиллуулах"""
    await core_security.require_permission(request, "retention:write")
    base_url = str(request.base_url).rstrip("/")
    stats = await retention_service.run_automated_retention_checks(base_url=base_url)
    return {"success": True, "stats": stats}

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
    port = int(os.getenv("PORT", 8000))
    print(f"Гэрэгэ — Харилцааны Ухаалаг Систем: http://localhost:{port}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
