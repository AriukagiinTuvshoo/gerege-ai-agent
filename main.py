import os
import io
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from fastapi import FastAPI, Request, Response, BackgroundTasks, Query, UploadFile, File, Form, Header, Cookie, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import httpx

import database
import agent
import knowledge_base
import sheets_service
import fintech_service
import cargo_service

load_dotenv(override=True)

# Өгөгдлийн санг эхлүүлэх
database.init_db()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai_agent_app")

app = FastAPI(title="Omnichannel AI Chatbot Agent & Multi-Tenant CRM Platform")

os.makedirs("static/qrcodes", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "agent_verify_secret_token_123")
META_PAGE_ACCESS_TOKEN = os.getenv("META_PAGE_ACCESS_TOKEN", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_MANAGER_CHAT_ID = os.getenv("TELEGRAM_MANAGER_CHAT_ID", "")

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
    url = f"https://graph.facebook.com/v21.0/me/messages?access_token={token}"
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

async def send_telegram_message(chat_id: Any, text: str):
    """Telegram хэрэглэгч рүү хариу илгээх"""
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not bot_token or not text:
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload, timeout=10.0)
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
async def auth_login(payload: Dict[str, Any], response: Response):
    login_type = payload.get("type", "admin")  # 'admin', 'client', 'magic'
    
    if login_type == "admin":
        password = str(payload.get("password", "")).strip()
        if database.authenticate_admin(password):
            token = database.create_session(role="admin", page_id=None)
            response.set_cookie(key="session_token", value=token, max_age=86400*3, httponly=True)
            return {
                "success": True,
                "token": token,
                "role": "admin",
                "page_id": None,
                "page_name": "👑 Супер Админ"
            }
        return JSONResponse({"success": False, "error": "Админы нууц үг буруу байна!"}, status_code=401)

    elif login_type in ["client", "magic"]:
        identifier = str(payload.get("identifier") or payload.get("username") or payload.get("token") or "").strip()
        password = payload.get("password")
        client_page, err_msg = database.authenticate_client_detailed(identifier, password)
        if client_page:
            page_id = client_page["page_id"]
            token = database.create_session(role="client", page_id=page_id)
            response.set_cookie(key="session_token", value=token, max_age=86400*3, httponly=True)
            return {
                "success": True,
                "token": token,
                "role": "client",
                "page_id": page_id,
                "page_name": client_page.get("name", "Харилцагчийн Хуудас"),
                "has_custom_key": bool(client_page.get("gemini_api_key")),
                "tokens_used": client_page.get("tokens_used", 0),
                "monthly_token_limit": client_page.get("monthly_token_limit", 100000)
            }
        return JSONResponse({"success": False, "error": err_msg or "Харилцагчийн нэр, нууц үг эсвэл холбоос буруу байна!"}, status_code=401)

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
    if hub_mode == "subscribe" and (hub_verify_token == expected_token or hub_verify_token == "agent_verify_secret_token_123"):
        logger.info("Meta Webhook баталгаажлаа!")
        return Response(content=hub_challenge, media_type="text/plain")
    return Response(content="Verification failed", status_code=403)

@app.post("/webhook")
async def meta_webhook_events(request: Request, background_tasks: BackgroundTasks):
    try:
        data = await request.json()
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
                page_token = page_obj.get("page_access_token") if page_obj else os.getenv("META_PAGE_ACCESS_TOKEN", "")

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
                    result = agent.process_message(
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
                        
        return Response(content="EVENT_RECEIVED", status_code=200)
    except Exception as e:
        logger.error(f"Meta webhook алдаа: {e}")
        return Response(content="Error", status_code=500)

# -------------------------------------------------------------
# 5. TELEGRAM WEBHOOK
# -------------------------------------------------------------
@app.post("/telegram/webhook")
async def telegram_webhook_events(request: Request, background_tasks: BackgroundTasks):
    try:
        data = await request.json()
        message = data.get("message", {})
        chat_id = message.get("chat", {}).get("id")
        user_text = message.get("text", "")
        
        if chat_id and user_text:
            result = agent.process_message(
                text=user_text,
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
        
    result = agent.process_message(
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

    result = agent.process_message(
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
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client":
        target_page_id = user["page_id"]
    else:
        target_page_id = page_id or database.DEFAULT_PAGE_ID

    image_bytes = await file.read()
    result = agent.process_message(
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
    Хуудсуудын жагсаалт:
    - Админ: Бүх хуудсыг харна (токенууд нууцлагдсан)
    - Client: Зөвхөн өөрийнхөө хуудсыг ганцаарчилж харна
    """
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client":
        p = database.get_page(user["page_id"], mask_secrets=True)
        return JSONResponse({"total": 1, "data": [p] if p else []})

    pages = database.get_all_pages(mask_secrets=True)
    return JSONResponse({"total": len(pages), "data": pages})

@app.get("/api/pages/detail")
@app.get("/api/pages/{page_id}")
async def get_page_detail(request: Request, page_id: Optional[str] = None):
    target_id = request.query_params.get("page_id") or page_id
    if not target_id:
        return JSONResponse({"error": "page_id missing"}, status_code=400)

    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client" and user.get("page_id") != target_id:
        return JSONResponse({"error": "Хандах эрхгүй хуудас байна!"}, status_code=403)

    p = database.get_page(target_id, mask_secrets=True)
    if not p:
        return JSONResponse({"error": "Page not found"}, status_code=404)
    return JSONResponse(p)

@app.post("/api/pages")
async def create_or_update_page(payload: Dict[str, Any], request: Request):
    """Шинэ хуудас нэмэх (Зөвхөн Админ эрхтэй)"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client":
        return JSONResponse({"error": "Зөвхөн Супер Админ шинэ харилцагчийн хуудас нэмэх эрхтэй!"}, status_code=403)

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
    agent.reset_sessions()
    return {"status": "success", "message": f"{name} хуудас амжилттай хадгалагдлаа!", "page_id": page_id}

@app.delete("/api/pages")
@app.delete("/api/pages/{page_id}")
async def delete_page_endpoint(request: Request, page_id: Optional[str] = None):
    """Хуудас устгах (Зөвхөн Админ эрхтэй)"""
    target_id = request.query_params.get("page_id") or page_id
    if not target_id:
        return JSONResponse({"error": "page_id missing"}, status_code=400)

    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client":
        return JSONResponse({"error": "Устгах эрхгүй!"}, status_code=403)

    success = database.delete_page(str(target_id))
    if not success:
        return JSONResponse({"error": "Үндсэн хуудсыг устгах боломжгүй"}, status_code=400)
    agent.reset_sessions()
    return {"status": "deleted", "page_id": target_id}

@app.post("/api/pages/gemini_key")
@app.post("/api/pages/{page_id}/gemini_key")
async def update_page_gemini_key_endpoint(payload: Dict[str, Any], request: Request, page_id: Optional[str] = None):
    """Харилцагчийн хувийн Gemini API түлхүүр шинэчлэх (Админ болон тухайн Client өөрөө засаж болно)"""
    target_id = payload.get("page_id") or page_id
    if not target_id:
        return JSONResponse({"error": "page_id missing"}, status_code=400)

    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client" and user.get("page_id") != target_id:
        return JSONResponse({"error": "Та зөвхөн өөрийнхөө хуудасны түлхүүрийг засах эрхтэй!"}, status_code=403)

    gemini_key = str(payload.get("gemini_api_key", "")).strip()
    monthly_limit = payload.get("monthly_token_limit")
    if monthly_limit is not None:
        try: monthly_limit = int(monthly_limit)
        except Exception: monthly_limit = None

    database.update_page_gemini_key(str(target_id), gemini_key, monthly_limit)
    agent.reset_sessions()
    return {"status": "success", "message": "Gemini API тохиргоо амжилттай шинэчлэгдлээ!"}

@app.post("/api/pages/credentials")
@app.post("/api/pages/{page_id}/credentials")
async def set_page_credentials_endpoint(payload: Dict[str, Any], request: Request, page_id: Optional[str] = None):
    """Харилцагчид зориулсан нэвтрэх эрх & Magic Link үүсгэх (Зөвхөн Админ)"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client":
        return JSONResponse({"error": "Эрх хүрэхгүй!"}, status_code=403)

    target_page_id = payload.get("page_id") or page_id
    if not target_page_id:
        return JSONResponse({"error": "Хуудасны ID шаардлагатай"}, status_code=400)

    username = str(payload.get("username", "")).strip()
    password = payload.get("password")
    if not username:
        return JSONResponse({"error": "Хэрэглэгчийн нэр оруулна уу"}, status_code=400)

    res = database.set_client_credentials(str(target_page_id), username, password)
    return {"status": "success", "data": res}

# -------------------------------------------------------------
# 8. UNIFIED INBOX & HUMAN TAKEOVER (Client Isolation)
# -------------------------------------------------------------
@app.get("/api/sessions")
async def get_active_sessions(request: Request, page_id: Optional[str] = Query(None)):
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    target_page = user["page_id"] if (user and user.get("role") == "client") else page_id
    sessions = database.get_active_sessions(page_id=target_page)
    return JSONResponse({"total": len(sessions), "data": sessions})

@app.get("/api/sessions/{sender_id}/messages")
async def get_session_messages(sender_id: str, request: Request):
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    msgs = database.get_conversation_history(sender_id)
    if user and user.get("role") == "client" and msgs:
        # Client зөвхөн өөрийн хуудсанд хамаарах чатыг үзэх ёстой
        if any(m.get("page_id") and m.get("page_id") != user["page_id"] for m in msgs):
            return JSONResponse({"error": "Хандах эрхгүй чат!"}, status_code=403)

    is_takeover = database.is_session_human_takeover(sender_id)
    return JSONResponse({"sender_id": sender_id, "is_human_takeover": is_takeover, "messages": msgs})

@app.post("/api/sessions/{sender_id}/takeover")
async def toggle_human_takeover(sender_id: str, payload: Dict[str, bool]):
    takeover = payload.get("takeover", False)
    database.set_human_takeover(sender_id, takeover)
    return {"status": "success", "is_human_takeover": takeover}

@app.post("/api/sessions/{sender_id}/send")
async def manager_send_message(sender_id: str, payload: Dict[str, str], request: Request, background_tasks: BackgroundTasks):
    text = payload.get("message", "").strip()
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    target_page_id = user["page_id"] if (user and user.get("role") == "client") else payload.get("page_id", database.DEFAULT_PAGE_ID)

    if not text:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    database.log_message(sender_id=sender_id, channel="omni", sender_type="agent", content=text, page_id=target_page_id)

    if sender_id.startswith("meta_"):
        meta_id = sender_id.replace("meta_", "")
        page_obj = database.get_page(target_page_id)
        page_token = page_obj.get("page_access_token") if page_obj else None
        background_tasks.add_task(send_meta_message, meta_id, text, page_token)
    elif sender_id.startswith("tg_"):
        tg_id = sender_id.replace("tg_", "")
        background_tasks.add_task(send_telegram_message, tg_id, text)

    return {"status": "sent", "sender_id": sender_id, "message": text}

# -------------------------------------------------------------
# 9. CRM & LEADS PIPELINE (Client Isolation)
# -------------------------------------------------------------
@app.get("/api/registrations")
@app.get("/api/leads")
async def get_registrations(request: Request, page_id: Optional[str] = Query(None)):
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    target_page = user["page_id"] if (user and user.get("role") == "client") else page_id
    rows = database.get_all_registrations(page_id=target_page)
    return JSONResponse({"total": len(rows), "data": rows})

@app.post("/api/leads/{lead_id}/status")
async def update_lead(lead_id: int, payload: Dict[str, Any]):
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
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        auth_token=token
    )
    
    target_page = None
    if user and user.get("role") == "client":
        target_page = user.get("page_id")
    else:
        target_page = page_id
        
    csv_data = database.sync_to_csv(page_id=target_page)
    filename = f"leads_{target_page or 'all'}.csv"
    
    return Response(
        content=csv_data.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Access-Control-Allow-Origin": "*"
        }
    )

@app.get("/api/export/excel")
async def export_excel(
    request: Request,
    page_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        auth_token=token
    )
    
    target_page = None
    if user and user.get("role") == "client":
        target_page = user.get("page_id")
    else:
        target_page = page_id
        
    excel_stream = database.generate_excel(page_id=target_page)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"leads_{target_page or 'all'}_{timestamp}.xlsx"
    
    return Response(
        content=excel_stream.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Access-Control-Allow-Origin": "*"
        }
    )

@app.post("/api/pages/{page_id}/google_sheets")
async def update_page_google_sheets_endpoint(page_id: str, payload: Dict[str, Any], request: Request):
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтэрнэ үү")
    if user["role"] == "client" and user["page_id"] != page_id:
        raise HTTPException(status_code=403, detail="Зөвшөөрөлгүй хандалт")
    
    url = payload.get("google_sheets_url", "").strip()
    database.update_page_google_sheets(page_id, url)
    agent.reset_sessions()
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
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтэрнэ үү")
    if user["role"] == "client" and user["page_id"] != page_id:
        raise HTTPException(status_code=403, detail="Зөвшөөрөлгүй хандалт")

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
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтэрнэ үү")
    if user["role"] == "client" and user["page_id"] != page_id:
        raise HTTPException(status_code=403, detail="Зөвшөөрөлгүй хандалт")

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
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтэрнэ үү")
    if user["role"] == "client" and user["page_id"] != page_id:
        raise HTTPException(status_code=403, detail="Зөвшөөрөлгүй хандалт")

    file_bytes = await file.read()
    if not file_bytes:
        return JSONResponse({"success": False, "error": "Хоосон файл байна."}, status_code=400)

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
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтэрнэ үү")
    if user["role"] == "client" and user["page_id"] != page_id:
        raise HTTPException(status_code=403, detail="Зөвшөөрөлгүй хандалт")

    page_obj = database.get_page(page_id)
    sheets = sheets_service.get_page_sheets_list(page_obj)
    filtered = [s for s in sheets if s.get("id") != sheet_id]
    _save_page_sheets_list(page_id, filtered)
    return {"success": True, "remaining": len(filtered)}

@app.post("/api/pages/{page_id}/test_sheet")
async def test_page_google_sheet_endpoint(page_id: str, payload: Dict[str, Any], request: Request):
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Нэвтэрнэ үү")
    if user["role"] == "client" and user["page_id"] != page_id:
        raise HTTPException(status_code=403, detail="Зөвшөөрөлгүй хандалт")
    
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
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    target_id = user["page_id"] if (user and user.get("role") == "client") else (page_id or database.DEFAULT_PAGE_ID)
    
    page_obj = database.get_page(target_id)
    if page_obj and page_obj.get("knowledge_json"):
        try:
            return JSONResponse(json.loads(page_obj["knowledge_json"]))
        except Exception:
            pass
    return JSONResponse(knowledge_base.load_knowledge())

@app.post("/api/knowledge")
async def update_knowledge(payload: Dict[str, Any], request: Request, page_id: Optional[str] = Query(None)):
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    target_id = user["page_id"] if (user and user.get("role") == "client") else (page_id or database.DEFAULT_PAGE_ID)
    
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

    agent.reset_sessions()
    return {"status": "success", "message": f"{target_id} хуудасны мэдлэгийн сан амжилттай шинэчлэгдлээ!"}

# -------------------------------------------------------------
# 11. СИСТЕМИЙН ЭРҮҮЛ МЭНД БА ТҮЛХҮҮРҮҮД
# -------------------------------------------------------------
@app.get("/api/health")
async def health_check():
    load_dotenv(override=True)
    rows = database.get_all_registrations()
    sessions = database.get_active_sessions()
    pages = database.get_all_pages()
    return JSONResponse({
        "status": "healthy",
        "gemini_ready": agent.is_gemini_ready(),
        "model": agent.get_model_name(),
        "meta_token_configured": bool(os.getenv("META_PAGE_ACCESS_TOKEN", "").strip()),
        "telegram_configured": bool(os.getenv("TELEGRAM_BOT_TOKEN", "").strip()),
        "total_pages": len(pages),
        "total_leads": len(rows),
        "active_sessions": len(sessions)
    })

@app.post("/api/update-keys")
async def update_keys(payload: Dict[str, str], request: Request):
    """Админы системийн түлхүүрүүд засах (Зөвхөн Админ)"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token")
    )
    if user and user.get("role") == "client":
        return JSONResponse({"error": "Эрх хүрэхгүй!"}, status_code=403)

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
async def get_invoice_status_api(invoice_id: str):
    """Төлбөрийн төлөвийг шалгах (Real-time Polling)"""
    inv = database.get_invoice(invoice_id)
    if not inv:
        return JSONResponse(status_code=404, content={"error": "Invoice not found"})
    return {
        "status": inv.get("status", "PENDING"),
        "invoice": inv,
        "ebarimt": {
            "lottery": inv.get("ebarimt_lottery"),
            "qr_data": inv.get("ebarimt_qr")
        }
    }

@app.post("/api/fintech/qpay/callback")
async def qpay_webhook_callback(request: Request, invoice_id: Optional[str] = Query(None)):
    """Банк / QPay-ийн албан ёсны webhook хүлээн авагч"""
    try:
        body = await request.json()
    except Exception:
        body = {}
    inv_id = invoice_id or body.get("sender_invoice_no") or body.get("invoice_id")
    if not inv_id:
        return JSONResponse(status_code=400, content={"error": "invoice_id missing"})
    res = await fintech_service.process_successful_payment(inv_id, callback_data=body)
    return res

@app.post("/api/fintech/invoices/{invoice_id}/simulate-pay")
async def simulate_invoice_payment_api(invoice_id: str):
    """1 секундэд автоматаар баталгаажуулж турших (Simulator)"""
    res = await fintech_service.process_successful_payment(invoice_id)
    return res

@app.get("/api/fintech/summary")
async def get_fintech_summary_api(request: Request):
    """Финтек хяналтын самбарын KPI тоон үзүүлэлтүүд"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        token=request.query_params.get("token") or request.query_params.get("client_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    page_id = user.get("page_id")
    return database.get_fintech_summary(page_id)

@app.get("/api/fintech/invoices")
async def get_fintech_invoices_api(
    request: Request,
    status: Optional[str] = Query(None),
    limit: int = Query(50)
):
    """Нэхэмжлэхүүдийн жагсаалт"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        token=request.query_params.get("token") or request.query_params.get("client_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    page_id = user.get("page_id")
    return database.list_invoices(page_id=page_id, limit=limit, status=status)

@app.post("/api/fintech/settings")
async def save_fintech_settings_api(
    payload: Dict[str, Any],
    request: Request
):
    """QPay худалдаа эрхлэгчийн эрх болон И-Баримт тохиргоо хадгалах"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        token=request.query_params.get("token") or request.query_params.get("client_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    page_id = payload.get("page_id") or user.get("page_id")
    if not page_id:
        raise HTTPException(status_code=400, detail="page_id required")
    if user.get("role") == "client" and user.get("page_id") != page_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    success = database.update_page_qpay_settings(
        page_id=page_id,
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
    """Самбараас шууд төлбөрийн нэхэмжлэх үүсгэх"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        token=request.query_params.get("token") or request.query_params.get("client_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    page_id = payload.get("page_id") or user.get("page_id") or database.DEFAULT_PAGE_ID
    amount = int(payload.get("amount", 10000))
    desc = payload.get("description", "Үйлчилгээний төлбөр")
    base_url = str(request.base_url)
    order = await fintech_service.create_payment_order(
        page_id=page_id,
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
    """Агуулахын ажилтан баркод уншуулах үед ачааг бүртгэж авто мэдэгдэл илгээх"""
    pid = payload.get("page_id") or database.DEFAULT_PAGE_ID
    code = payload.get("tracking_code", "").strip()
    if not code:
        return JSONResponse(status_code=400, content={"error": "tracking_code is required"})
    loc = payload.get("location", "УБ Төв Агуулах")
    base_url = str(request.base_url)
    res = await cargo_service.scan_and_notify_package(
        page_id=pid,
        tracking_code=code,
        location=loc,
        weight_kg=payload.get("weight_kg"),
        price_amount=payload.get("price_amount"),
        base_url=base_url
    )
    return res

@app.post("/api/cargo/{tracking_code}/deliver")
async def deliver_cargo_api(tracking_code: str, page_id: Optional[str] = Query(None)):
    """Ачааг олгосон гэж тэмдэглэх"""
    pid = page_id or database.DEFAULT_PAGE_ID
    pkg = database.mark_cargo_delivered(pid, tracking_code)
    return {"success": bool(pkg), "package": pkg}

@app.get("/api/cargo/packages")
async def list_cargo_packages_api(
    request: Request,
    status: Optional[str] = Query(None),
    limit: int = Query(50)
):
    """Карго ачаануудын жагсаалт"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        token=request.query_params.get("token") or request.query_params.get("client_token")
    )
    pid = (user.get("page_id") if user else None) or database.DEFAULT_PAGE_ID
    return database.list_cargo_packages(pid, status=status, limit=limit)

@app.get("/api/cargo/summary")
async def get_cargo_summary_api(request: Request):
    """Карго самбарын хураангуй KPI үзүүлэлтүүд"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        token=request.query_params.get("token") or request.query_params.get("client_token")
    )
    pid = (user.get("page_id") if user else None) or database.DEFAULT_PAGE_ID
    return database.get_cargo_summary(pid)

@app.post("/api/cargo/import-manifest")
async def import_cargo_manifest_api(
    request: Request,
    file: UploadFile = File(...)
):
    """Excel файлаас карго ачаануудыг олноор нь импортлох"""
    user = await get_current_user(
        authorization=request.headers.get("Authorization"),
        session_token_cookie=request.cookies.get("session_token"),
        token=request.query_params.get("token") or request.query_params.get("client_token")
    )
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    pid = user.get("page_id") or database.DEFAULT_PAGE_ID
    file_bytes = await file.read()
    return cargo_service.import_manifest_from_excel_bytes(pid, file_bytes, file.filename)

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
