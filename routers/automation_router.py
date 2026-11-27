"""
Comment-to-DM Automation, Tracked Short Links (/r/{code}), and ROI Analytics Router.
Inspired by noflow.pro workflow & ROI reporting, hardened with multi-tenant RBAC.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import database
from core import security as core_security

router = APIRouter(tags=["Automations & ROI"])


def _validate_safe_url(url: str, *, required: bool = False) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        if required:
            raise HTTPException(status_code=400, detail="target_url шаардлагатай")
        return ""
    lowered = cleaned.lower()
    if lowered.startswith("//"):
        raise HTTPException(status_code=400, detail="Аюултай эсвэл буруу URL формат байна")
    if not (lowered.startswith("https://") or lowered.startswith("http://") or cleaned.startswith("/")):
        raise HTTPException(status_code=400, detail="URL нь https://, http:// эсвэл / -ээр эхлэх ёстой")
    return cleaned


class CommentAutomationCreate(BaseModel):
    page_id: Optional[str] = None
    name: str = Field(..., min_length=1, max_length=120)
    post_id: str = "*"
    keyword_pattern: str = "*"
    public_reply_text: str = "Танд чат руу дэлгэрэнгүй мэдээлэл илгээлээ! ✅"
    dm_message_text: str = Field(..., min_length=1, max_length=2000)
    cta_button_text: str = ""
    cta_url: str = ""
    is_active: int = 1


class CommentAutomationToggle(BaseModel):
    is_active: Optional[int] = None


class TrackedLinkCreate(BaseModel):
    page_id: Optional[str] = None
    title: str = ""
    target_url: str = Field(..., min_length=1, max_length=2048)
    automation_id: Optional[int] = None
    code: Optional[str] = None


def _resolve_existing_page(scoped_page_id: Optional[str], refusal: str) -> str:
    """Phase 56 (F-56-1 / F-56-2): the page to write against, or a 404 that says so.

    `enforce_tenant_scope` hands an admin back the page id they asked for **without an existence
    check**, and both writers below insert into a table whose `page_id` is a foreign key to `pages`
    (`migrations/versions/0003_foreign_keys.py`). Measured live before this change:

        POST /api/automations/comments {"page_id": "p56_never_created", "name": "p56 probe", ...}
            -> HTTP 500 {"detail":"Internal server error","request_id":"25429644f4999e19"}
            -> comment_automations rows written: 0
        POST /api/automations/links    {"page_id": "p56_never_created", "target_url": "https://..."}
            -> HTTP 500 {"detail":"Internal server error","request_id":"e99762e418e3979b"}
            -> tracked_links rows written: 0

    The positive control - the same two bodies against a page that exists - returns 200 and writes
    one row each, so the 500 was about the missing page and not about the payload.

    A 404 rather than a 200 with a `success` flag, because this router's own refusals are already
    `HTTPException(404, "Автоматжуулалт олдсонгүй")` and because both consumers in
    `dashboard.html` branch on `res.ok`; until F-56-7 they said nothing at all on the failure path,
    so a 4xx is what actually reaches the operator.
    """
    target = str(scoped_page_id or database.DEFAULT_PAGE_ID)
    if not database.get_page(target):
        raise HTTPException(status_code=404, detail=f"'{target}' хуудас олдсонгүй - {refusal}.")
    return target


@router.get("/api/automations/comments")
async def list_comment_automations(request: Request, page_id: Optional[str] = None):
    scoped_page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="retention:read",
    )
    items = database.list_comment_automations(page_id=scoped_page_id)
    return {"automations": items}


@router.post("/api/automations/comments")
async def create_comment_automation(request: Request, payload: CommentAutomationCreate):
    scoped_page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.page_id,
        require_auth=True,
        allow_admin_all=False,
        permission="retention:write",
    )
    safe_cta_url = _validate_safe_url(payload.cta_url, required=False)
    target_page_id = _resolve_existing_page(scoped_page_id, "ямар ч дүрэм үүсгэсэнгүй")
    created = database.create_comment_automation(
        page_id=target_page_id,
        name=payload.name,
        dm_message_text=payload.dm_message_text,
        post_id=payload.post_id,
        keyword_pattern=payload.keyword_pattern,
        public_reply_text=payload.public_reply_text,
        cta_button_text=payload.cta_button_text,
        cta_url=safe_cta_url,
        is_active=1 if payload.is_active else 0,
    )
    return {"status": "created", "automation": created}


@router.post("/api/automations/comments/{automation_id}/toggle")
async def toggle_comment_automation(
    automation_id: int,
    request: Request,
    payload: Optional[CommentAutomationToggle] = None,
):
    existing = database.get_comment_automation(automation_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Автоматжуулалт олдсонгүй")

    scoped_page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=existing["page_id"],
        require_auth=True,
        allow_admin_all=False,
        permission="retention:write",
    )
    desired_state = payload.is_active if payload is not None else None
    updated = database.toggle_comment_automation(
        automation_id=automation_id,
        page_id=scoped_page_id,
        is_active=desired_state,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Автоматжуулалт олдсонгүй")
    return {"status": "updated", "automation": updated}


@router.delete("/api/automations/comments/{automation_id}")
async def delete_comment_automation(automation_id: int, request: Request):
    existing = database.get_comment_automation(automation_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Автоматжуулалт олдсонгүй")

    scoped_page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=existing["page_id"],
        require_auth=True,
        allow_admin_all=False,
        permission="retention:write",
    )
    deleted = database.delete_comment_automation(
        automation_id=automation_id,
        page_id=scoped_page_id,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Автоматжуулалт олдсонгүй")
    return {"status": "deleted", "id": automation_id}


@router.get("/api/automations/links")
async def list_tracked_links(request: Request, page_id: Optional[str] = None):
    scoped_page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="retention:read",
    )
    links = database.list_tracked_links(page_id=scoped_page_id)
    return {"links": links}


@router.post("/api/automations/links")
async def create_tracked_link(request: Request, payload: TrackedLinkCreate):
    scoped_page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=payload.page_id,
        require_auth=True,
        allow_admin_all=False,
        permission="retention:write",
    )
    safe_target_url = _validate_safe_url(payload.target_url, required=True)
    target_page_id = _resolve_existing_page(scoped_page_id, "ямар ч холбоос үүсгэсэнгүй")
    if payload.automation_id is not None:
        auto = database.get_comment_automation(payload.automation_id)
        if not auto or str(auto.get("page_id")) != str(scoped_page_id):
            raise HTTPException(status_code=403, detail="Автоматжуулалтын эрх хүрэлцэхгүй байна")
    created = database.create_tracked_link(
        page_id=target_page_id,
        target_url=safe_target_url,
        title=payload.title,
        automation_id=payload.automation_id,
        code=payload.code,
    )
    return {"status": "created", "link": created}


@router.get("/api/analytics/roi")
async def get_roi_analytics(
    request: Request,
    page_id: Optional[str] = None,
    seconds_per_reply: float = 30.0,
    hourly_wage_mnt: int = 15000,
):
    scoped_page_id = await core_security.enforce_tenant_scope(
        request,
        requested_page_id=page_id,
        require_auth=True,
        allow_admin_all=True,
        permission="retention:read",
    )
    if seconds_per_reply <= 0 or seconds_per_reply > 3600:
        raise HTTPException(status_code=400, detail="seconds_per_reply 1-3600 хооронд байх ёстой")
    if hourly_wage_mnt < 0 or hourly_wage_mnt > 10_000_000:
        raise HTTPException(status_code=400, detail="hourly_wage_mnt буруу байна")
    roi = database.get_roi_analytics(
        page_id=scoped_page_id,
        seconds_per_reply=seconds_per_reply,
        hourly_wage_mnt=hourly_wage_mnt,
    )
    return roi
