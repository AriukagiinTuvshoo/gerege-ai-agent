"""
SQLAlchemy Declarative Models for PostgreSQL & SQLite (Alembic Migration Target Metadata).
Unified 100% with the authoritative runtime schema in `database.py`.
"""
from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    func,
    text,
    String,
    Text,
    Float,
    DateTime,
    UniqueConstraint,
    Index,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()

#: Database-side default for every `created_at` / `updated_at` / `sent_at` column.
#:
#: The Python ``default=datetime.utcnow`` alone is not enough: a row inserted by raw
#: SQL that omits the column (many helpers in `database.py` do exactly that) gets
#: ``NULL``. The legacy runtime DDL used ``DEFAULT CURRENT_TIMESTAMP``, so dropping it
#: in favour of migrations silently changed behaviour and made freshly created rows
#: sort and render as "unknown time". Declaring the default on the model keeps both
#: insert paths — ORM and raw SQL — producing a timestamp.
TS_DEFAULT = func.current_timestamp()

#: Referential integrity (P1-06).
#:
#: Every tenant-scoped table references ``pages.page_id``. Before this existed the
#: relations were enforced only by application code: ``database.delete_page()`` walks a
#: hand-maintained list of 12 tables and had already drifted — ``comment_automations``,
#: ``tracked_links``, ``audit_logs`` and ``task_jobs`` rows were never removed, so deleting
#: a tenant stranded them permanently.
#:
#: Delete policy, chosen deliberately:
#:
#: * ``ON DELETE CASCADE`` for ordinary tenant data — deleting a tenant should remove its
#:   messages, invoices, jobs and so on, which is what ``delete_page()`` always intended.
#: * ``audit_logs.page_id`` is ``ON DELETE SET NULL``. The audit trail must outlive the
#:   tenant it describes; cascading it would let anyone erase their own audit history by
#:   deleting a page. The column is already nullable for this reason.
# A ForeignKey object can only be attached to one column, so these are type aliases
# resolved by `_page_fk()` / `_page_fk_nullable()` rather than shared instances.
PageFK = lambda: ForeignKey("pages.page_id", ondelete="CASCADE")          # noqa: E731
PageFKNullable = lambda: ForeignKey("pages.page_id", ondelete="SET NULL")  # noqa: E731



class PageModel(Base):
    __tablename__ = "pages"

    page_id = Column(String(128), primary_key=True)
    name = Column(String(255), nullable=False)
    category = Column(String(64), default="general")
    page_access_token = Column(Text, default="")
    verify_token = Column(String(255), default="agent_verify_secret_token_123")
    gemini_api_key = Column(Text, default="")
    ai_provider = Column(String(64), default="gemini")
    client_username = Column(String(128), nullable=True)
    client_password_hash = Column(Text, nullable=True)
    client_salt = Column(String(128), nullable=True)
    client_magic_token = Column(String(255), nullable=True)
    google_sheets_url = Column(Text, default="")
    qpay_username = Column(String(255), default="")
    qpay_password = Column(Text, default="")
    qpay_invoice_code = Column(String(255), default="")
    ebarimt_enabled = Column(Integer, default=1)
    telegram_bot_token = Column(Text, default="")
    telegram_manager_chat_id = Column(String(128), default="")
    daily_report_time = Column(String(16), default="08:30")
    daily_report_enabled = Column(Integer, default=1)
    monthly_token_limit = Column(Integer, default=100000)
    tokens_used = Column(Integer, default=0)
    knowledge_json = Column(Text, default="{}")
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        # E-02 Phase 8 (R10). The database-enforced username uniqueness invariant.
        #
        # `LOWER(TRIM(client_username))` is the identity the login path, the account
        # failed-login throttle and `resolve_canonical_account()` all use, so the index
        # must be on that exact expression — a unique index on the raw column would allow
        # `alice` and `  ALICE  ` to coexist while login treats them as one identity.
        #
        # The partial predicate excludes NULL / empty / whitespace-only usernames: pages
        # without a client login are not identities and may be arbitrarily many.
        #
        # Declared here as well as in migration `0005` so `core/models.py` stays the single
        # schema authority and drift detection can see that this index is expected.
        Index(
            "uq_pages_client_username_norm",
            func.lower(func.trim(client_username)),
            unique=True,
            postgresql_where=text(
                "client_username IS NOT NULL AND TRIM(client_username) <> ''"
            ),
            sqlite_where=text(
                "client_username IS NOT NULL AND TRIM(client_username) <> ''"
            ),
        ),
    )



class PageLoginNamespaceModel(Base):
    """E-02 Phase 10 (R16): one row per normalized login identifier.

    `normalized_identifier` is the PRIMARY KEY, which is what makes the invariant
    a database rule rather than an application convention: the engine refuses a
    second tenant claiming the same identifier, including under concurrency, with
    no pre-SELECT and no advisory lock. `page_id` records the current owner so the
    projection can be verified against `pages` — not for authentication, which
    still reads `pages` directly.

    Maintained by triggers on `pages` (see `core/login_identity.py`). Never written
    by application code: a manual INSERT here would desynchronise the projection
    from the table it projects, and `namespace_is_correct()` would start refusing
    startup, which is the intended failure mode rather than a bug.
    """

    __tablename__ = "page_login_namespace"

    normalized_identifier = Column(String(255), primary_key=True)
    page_id = Column(
        String(128),
        ForeignKey("pages.page_id", ondelete="CASCADE"),
        nullable=False,
    )

class RegistrationModel(Base):
    __tablename__ = "registrations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), default="100799479495809", index=True)
    name = Column(String(255), nullable=False)
    phone = Column(String(64), nullable=False)
    service = Column(String(255), nullable=True)
    channel = Column(String(64), default="web")
    sender_id = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    status = Column(String(64), default="шинэ")
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_registrations_page_created", "page_id", "created_at"),
        Index("idx_registrations_page_phone", "page_id", "phone"),
    )


class MessageModel(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), default="100799479495809", index=True)
    sender_id = Column(String(255), nullable=False)
    channel = Column(String(64), default="web")
    sender_type = Column(String(32), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_messages_sender_page", "sender_id", "page_id"),
        Index("idx_messages_page_created", "page_id", "created_at"),
    )


class SessionStateModel(Base):
    """
    Conversation state for one customer **within one tenant**.

    Identity is `(page_id, sender_id)`, not `sender_id` alone (finding E-01).

    A single person reaching two businesses produces the same sender ID in both, so keying
    on `sender_id` alone let one tenant's row overwrite the other's — disclosing the customer
    phone and name the first tenant collected, and removing the conversation from the tenant
    that owned it. The composite primary key makes that impossible at the storage layer, so a
    future query cannot reintroduce the leak by forgetting a `WHERE page_id = ?`.
    """
    __tablename__ = "session_states"

    page_id = Column(String(128), PageFK(), primary_key=True)
    sender_id = Column(String(255), primary_key=True)
    channel = Column(String(64), default="web")
    is_human_takeover = Column(Integer, default=0)
    customer_name = Column(String(255), nullable=True)
    customer_phone = Column(String(64), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)


class AuthSessionModel(Base):
    __tablename__ = "sessions"

    session_token = Column(String(255), primary_key=True)
    role = Column(String(32), nullable=False)
    page_id = Column(String(128), PageFK(), nullable=True)
    revoked = Column(Integer, default=0)
    revoked_at = Column(DateTime, nullable=True)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)
    expires_at = Column(DateTime, nullable=False)


class UserMemoryModel(Base):
    __tablename__ = "user_memories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), nullable=False)
    user_id = Column(String(255), nullable=False)
    customer_name = Column(String(255), nullable=True)
    phone = Column(String(64), nullable=True)
    interests = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    last_topic = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        UniqueConstraint("page_id", "user_id", name="uq_user_memories_page_user"),
        Index("idx_user_memories_page_user", "page_id", "user_id"),
    )


class PaymentInvoiceModel(Base):
    __tablename__ = "invoices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    invoice_id = Column(String(128), unique=True, nullable=False)
    page_id = Column(String(128), PageFK(), nullable=False)
    sender_id = Column(String(255), nullable=True)
    channel = Column(String(64), default="web")
    amount = Column(Integer, nullable=False)
    currency = Column(String(16), default="MNT")
    description = Column(Text, nullable=True)
    status = Column(String(32), default="PENDING")
    qr_text = Column(Text, nullable=True)
    qr_image_url = Column(Text, nullable=True)
    deep_links_json = Column(Text, default="[]")
    qpay_invoice_id = Column(String(255), nullable=True)
    provider_payment_id = Column(String(255), nullable=True)
    callback_verified = Column(Integer, default=0)
    ebarimt_lottery = Column(String(64), nullable=True)
    ebarimt_qr = Column(Text, nullable=True)
    paid_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_invoices_page_id", "page_id"),
        Index("idx_invoices_invoice_id", "invoice_id"),
    )


class CargoPackageModel(Base):
    __tablename__ = "cargo_packages"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), nullable=False)
    tracking_code = Column(String(128), nullable=False)
    customer_name = Column(String(255), nullable=True)
    customer_phone = Column(String(64), nullable=True)
    sender_id = Column(String(255), nullable=True)
    channel = Column(String(64), default="web")
    weight_kg = Column(Float, default=0.0)
    price_amount = Column(Integer, default=0)
    status = Column(String(64), default="REGISTERED")
    warehouse_location = Column(String(255), default="УБ Агуулах")
    invoice_id = Column(
        String(128), ForeignKey("invoices.invoice_id", ondelete="SET NULL"), nullable=True
    )
    notified_at = Column(DateTime, nullable=True)
    arrived_at = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        UniqueConstraint("page_id", "tracking_code", name="uq_cargo_page_tracking"),
        Index("idx_cargo_page_tracking", "page_id", "tracking_code"),
        Index("idx_cargo_phone", "customer_phone"),
        Index("idx_cargo_status", "status"),
    )


class AutomatedRuleModel(Base):
    __tablename__ = "automated_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), nullable=False)
    rule_type = Column(String(64), nullable=False)
    delay_hours = Column(Integer, default=2)
    message_template = Column(Text, nullable=False)
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        UniqueConstraint("page_id", "rule_type", name="uq_automated_rule_page_type"),
        Index("idx_rules_page", "page_id"),
    )


class MarketingCampaignModel(Base):
    __tablename__ = "marketing_campaigns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    target_segment = Column(String(64), default="all")
    channel = Column(String(64), default="all")
    status = Column(String(64), default="COMPLETED")
    sent_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_campaigns_page", "page_id"),
    )


class SentFollowupModel(Base):
    __tablename__ = "sent_followups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), nullable=False)
    rule_type = Column(String(64), nullable=False)
    sender_id = Column(String(255), nullable=False)
    channel = Column(String(64), default="web")
    sent_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        UniqueConstraint("page_id", "rule_type", "sender_id", name="uq_sent_followup"),
        Index("idx_sent_followups", "page_id", "rule_type", "sender_id"),
    )


class AppointmentModel(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), nullable=False)
    customer_name = Column(String(255), nullable=False)
    customer_phone = Column(String(64), nullable=False)
    service_name = Column(String(255), nullable=False)
    appointment_date = Column(String(32), nullable=False)
    appointment_time = Column(String(16), nullable=False)
    sender_id = Column(String(255), nullable=True)
    channel = Column(String(64), default="web")
    status = Column(String(64), default="CONFIRMED")
    reminder_sent = Column(Integer, default=0)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        UniqueConstraint(
            "page_id",
            "appointment_date",
            "appointment_time",
            "service_name",
            name="uq_appointment_slot",
        ),
        Index("idx_appointments_page_date", "page_id", "appointment_date"),
        Index("idx_appointments_phone", "customer_phone"),
    )


class NotificationLockModel(Base):
    __tablename__ = "notification_locks"

    idempotency_key = Column(String(255), primary_key=True)
    channel = Column(String(64), default="any")
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)


class TaskJobModel(Base):
    __tablename__ = "task_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    idempotency_key = Column(String(255), unique=True, nullable=True)
    task_name = Column(String(128), nullable=False)
    payload_json = Column(Text, nullable=False)
    status = Column(String(32), default="PENDING")
    attempts = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    timeout_seconds = Column(Integer, default=60)
    next_run_at = Column(DateTime, nullable=True)
    locked_by = Column(String(128), nullable=True)
    locked_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)
    updated_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_task_jobs_status", "status", "created_at"),
    )


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFKNullable(), nullable=True, index=True)
    actor_role = Column(String(64), nullable=True)
    actor_id = Column(String(255), nullable=True)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(255), nullable=True)
    details_json = Column(Text, default="{}")
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_audit_logs_page_created", "page_id", "created_at"),
    )


class CommentAutomationModel(Base):
    __tablename__ = "comment_automations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    page_id = Column(String(128), PageFK(), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    post_id = Column(String(255), default="*")
    keyword_pattern = Column(String(500), default="*")
    public_reply_text = Column(Text, default="Танд чат руу дэлгэрэнгүй мэдээлэл илгээлээ! ✅")
    dm_message_text = Column(Text, nullable=False)
    cta_button_text = Column(String(128), default="")
    cta_url = Column(Text, default="")
    is_active = Column(Integer, default=1)
    trigger_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_comment_auto_page_active", "page_id", "is_active"),
    )


class TrackedLinkModel(Base):
    __tablename__ = "tracked_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(64), unique=True, nullable=False)
    page_id = Column(String(128), PageFK(), nullable=False, index=True)
    automation_id = Column(
        Integer, ForeignKey("comment_automations.id", ondelete="SET NULL"), nullable=True
    )
    title = Column(String(255), default="")
    target_url = Column(Text, nullable=False)
    clicks_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, server_default=TS_DEFAULT)

    __table_args__ = (
        Index("idx_tracked_links_code", "code"),
    )
