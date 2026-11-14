"""Initial enterprise multi-tenant schema (15 authoritative tables)

Revision ID: 0001_initial_enterprise_schema
Revises: None
Create Date: 2026-04-12 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_enterprise_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _existing_tables() -> set:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return set(insp.get_table_names())


def upgrade() -> None:
    existing = _existing_tables()

    if "pages" not in existing:
        op.create_table(
            "pages",
            sa.Column("page_id", sa.String(128), primary_key=True),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("category", sa.String(64), server_default="general"),
            sa.Column("page_access_token", sa.Text(), nullable=True),
            sa.Column("verify_token", sa.String(255), server_default="agent_verify_secret_token_123"),
            sa.Column("is_active", sa.Integer(), server_default="1"),
            sa.Column("knowledge_json", sa.Text(), server_default="{}"),
            sa.Column("gemini_api_key", sa.Text(), server_default=""),
            sa.Column("ai_provider", sa.String(64), server_default="gemini"),
            sa.Column("client_username", sa.String(128), nullable=True),
            sa.Column("client_password_hash", sa.String(255), nullable=True),
            sa.Column("client_salt", sa.String(128), nullable=True),
            sa.Column("client_magic_token", sa.String(255), nullable=True),
            sa.Column("monthly_token_limit", sa.Integer(), server_default="100000"),
            sa.Column("tokens_used", sa.Integer(), server_default="0"),
            sa.Column("google_sheets_url", sa.Text(), server_default=""),
            sa.Column("qpay_username", sa.String(255), server_default=""),
            sa.Column("qpay_password", sa.String(255), server_default=""),
            sa.Column("qpay_invoice_code", sa.String(255), server_default=""),
            sa.Column("ebarimt_enabled", sa.Integer(), server_default="1"),
            sa.Column("telegram_bot_token", sa.Text(), server_default=""),
            sa.Column("telegram_manager_chat_id", sa.String(128), server_default=""),
            sa.Column("daily_report_time", sa.String(32), server_default="08:30"),
            sa.Column("daily_report_enabled", sa.Integer(), server_default="1"),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("ix_pages_client_username", "pages", ["client_username"])
        op.create_index("ix_pages_client_magic_token", "pages", ["client_magic_token"])

    if "registrations" not in existing:
        op.create_table(
            "registrations",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), server_default="100799479495809"),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("phone", sa.String(64), nullable=False),
            sa.Column("service", sa.String(255), nullable=False),
            sa.Column("channel", sa.String(64), server_default="web"),
            sa.Column("sender_id", sa.String(255), nullable=True),
            sa.Column("status", sa.String(64), server_default="Шинэ"),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("idx_registrations_page_created", "registrations", ["page_id", "created_at"])

    if "messages" not in existing:
        op.create_table(
            "messages",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), server_default="100799479495809"),
            sa.Column("sender_id", sa.String(255), nullable=False),
            sa.Column("channel", sa.String(64), server_default="web"),
            sa.Column("sender_type", sa.String(32), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("idx_messages_page_sender", "messages", ["page_id", "sender_id", "created_at"])

    if "session_states" not in existing:
        op.create_table(
            "session_states",
            sa.Column("sender_id", sa.String(255), primary_key=True),
            sa.Column("page_id", sa.String(128), server_default="100799479495809"),
            sa.Column("channel", sa.String(64), server_default="web"),
            sa.Column("is_human_takeover", sa.Integer(), server_default="0"),
            sa.Column("customer_name", sa.String(255), nullable=True),
            sa.Column("customer_phone", sa.String(64), nullable=True),
            sa.Column("updated_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("idx_session_states_page_updated", "session_states", ["page_id", "updated_at"])

    if "sessions" not in existing:
        op.create_table(
            "sessions",
            sa.Column("session_token", sa.String(255), primary_key=True),
            sa.Column("role", sa.String(64), nullable=False),
            sa.Column("page_id", sa.String(128), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("expires_at", sa.String(64), nullable=False),
            sa.Column("revoked", sa.Integer(), server_default="0"),
            sa.Column("revoked_at", sa.String(64), nullable=True),
            sa.Column("ip_address", sa.String(64), nullable=True),
        )
        op.create_index("ix_sessions_page_id", "sessions", ["page_id"])

    if "user_memories" not in existing:
        op.create_table(
            "user_memories",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), nullable=False),
            sa.Column("user_id", sa.String(255), nullable=False),
            sa.Column("customer_name", sa.String(255), nullable=True),
            sa.Column("phone", sa.String(64), nullable=True),
            sa.Column("interests", sa.Text(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("last_topic", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("page_id", "user_id", name="uq_user_memory_page_user"),
        )
        op.create_index("idx_user_memories_lookup", "user_memories", ["page_id", "user_id"])

    if "invoices" not in existing:
        op.create_table(
            "invoices",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("invoice_id", sa.String(128), unique=True, nullable=False),
            sa.Column("page_id", sa.String(128), nullable=False),
            sa.Column("sender_id", sa.String(255), nullable=True),
            sa.Column("channel", sa.String(64), server_default="web"),
            sa.Column("amount", sa.Integer(), nullable=False),
            sa.Column("currency", sa.String(16), server_default="MNT"),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("status", sa.String(64), server_default="PENDING"),
            sa.Column("qpay_invoice_id", sa.String(128), nullable=True),
            sa.Column("provider_payment_id", sa.String(128), nullable=True),
            sa.Column("callback_verified", sa.Integer(), server_default="0"),
            sa.Column("qr_text", sa.Text(), nullable=True),
            sa.Column("qr_image_url", sa.Text(), nullable=True),
            sa.Column("deep_links_json", sa.Text(), server_default="[]"),
            sa.Column("ebarimt_lottery", sa.String(64), nullable=True),
            sa.Column("ebarimt_qr", sa.Text(), nullable=True),
            sa.Column("paid_at", sa.String(64), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("idx_invoices_page_status", "invoices", ["page_id", "status"])
        op.create_index("idx_invoices_sender", "invoices", ["sender_id"])

    if "cargo_packages" not in existing:
        op.create_table(
            "cargo_packages",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), nullable=False),
            sa.Column("tracking_code", sa.String(128), nullable=False),
            sa.Column("customer_name", sa.String(255), nullable=True),
            sa.Column("customer_phone", sa.String(64), nullable=True),
            sa.Column("sender_id", sa.String(255), nullable=True),
            sa.Column("channel", sa.String(64), server_default="web"),
            sa.Column("weight_kg", sa.Float(), server_default="0.0"),
            sa.Column("price_amount", sa.Integer(), server_default="0"),
            sa.Column("status", sa.String(64), server_default="REGISTERED"),
            sa.Column("warehouse_location", sa.String(255), server_default="УБ Агуулах"),
            sa.Column("invoice_id", sa.String(128), nullable=True),
            sa.Column("notified_at", sa.String(64), nullable=True),
            sa.Column("arrived_at", sa.String(64), nullable=True),
            sa.Column("delivered_at", sa.String(64), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("page_id", "tracking_code", name="uq_cargo_page_tracking"),
        )
        op.create_index("idx_cargo_page_tracking", "cargo_packages", ["page_id", "tracking_code"])
        op.create_index("idx_cargo_phone", "cargo_packages", ["customer_phone"])
        op.create_index("idx_cargo_status", "cargo_packages", ["status"])

    if "automated_rules" not in existing:
        op.create_table(
            "automated_rules",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), nullable=False),
            sa.Column("rule_type", sa.String(64), nullable=False),
            sa.Column("delay_hours", sa.Integer(), server_default="2"),
            sa.Column("message_template", sa.Text(), nullable=False),
            sa.Column("is_active", sa.Integer(), server_default="1"),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("page_id", "rule_type", name="uq_automated_rule_page_type"),
        )
        op.create_index("idx_rules_page", "automated_rules", ["page_id"])

    if "marketing_campaigns" not in existing:
        op.create_table(
            "marketing_campaigns",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), nullable=False),
            sa.Column("title", sa.String(255), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("target_segment", sa.String(64), server_default="all"),
            sa.Column("channel", sa.String(64), server_default="all"),
            sa.Column("status", sa.String(64), server_default="COMPLETED"),
            sa.Column("sent_count", sa.Integer(), server_default="0"),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("idx_campaigns_page", "marketing_campaigns", ["page_id"])

    if "sent_followups" not in existing:
        op.create_table(
            "sent_followups",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), nullable=False),
            sa.Column("rule_type", sa.String(64), nullable=False),
            sa.Column("sender_id", sa.String(255), nullable=False),
            sa.Column("channel", sa.String(64), server_default="web"),
            sa.Column("sent_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("page_id", "rule_type", "sender_id", name="uq_sent_followup"),
        )
        op.create_index("idx_sent_followups", "sent_followups", ["page_id", "rule_type", "sender_id"])

    if "appointments" not in existing:
        op.create_table(
            "appointments",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), nullable=False),
            sa.Column("customer_name", sa.String(255), nullable=False),
            sa.Column("customer_phone", sa.String(64), nullable=False),
            sa.Column("service_name", sa.String(255), nullable=False),
            sa.Column("appointment_date", sa.String(32), nullable=False),
            sa.Column("appointment_time", sa.String(16), nullable=False),
            sa.Column("sender_id", sa.String(255), nullable=True),
            sa.Column("channel", sa.String(64), server_default="web"),
            sa.Column("status", sa.String(64), server_default="CONFIRMED"),
            sa.Column("reminder_sent", sa.Integer(), server_default="0"),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.UniqueConstraint("page_id", "appointment_date", "appointment_time", "service_name", name="uq_appointment_slot"),
        )
        op.create_index("idx_appointments_page_date", "appointments", ["page_id", "appointment_date"])
        op.create_index("idx_appointments_phone", "appointments", ["customer_phone"])

    if "notification_locks" not in existing:
        op.create_table(
            "notification_locks",
            sa.Column("idempotency_key", sa.String(255), primary_key=True),
            sa.Column("channel", sa.String(64), server_default="any"),
            sa.Column("expires_at", sa.String(64), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )

    if "task_jobs" not in existing:
        op.create_table(
            "task_jobs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("idempotency_key", sa.String(255), unique=True, nullable=True),
            sa.Column("task_name", sa.String(128), nullable=False),
            sa.Column("payload_json", sa.Text(), server_default="{}"),
            sa.Column("status", sa.String(32), server_default="PENDING"),
            sa.Column("attempts", sa.Integer(), server_default="0"),
            sa.Column("max_retries", sa.Integer(), server_default="3"),
            sa.Column("timeout_seconds", sa.Integer(), server_default="60"),
            sa.Column("next_run_at", sa.String(64), nullable=True),
            sa.Column("locked_by", sa.String(128), nullable=True),
            sa.Column("locked_at", sa.String(64), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("updated_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("idx_task_jobs_status", "task_jobs", ["status", "created_at"])

    if "audit_logs" not in existing:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("page_id", sa.String(128), nullable=True),
            sa.Column("actor_role", sa.String(64), nullable=True),
            sa.Column("actor_id", sa.String(255), nullable=True),
            sa.Column("action", sa.String(128), nullable=False),
            sa.Column("resource_type", sa.String(64), nullable=True),
            sa.Column("resource_id", sa.String(255), nullable=True),
            sa.Column("details_json", sa.Text(), server_default="{}"),
            sa.Column("ip_address", sa.String(64), nullable=True),
            sa.Column("created_at", sa.String(64), server_default=sa.text("CURRENT_TIMESTAMP")),
        )
        op.create_index("idx_audit_logs_page_created", "audit_logs", ["page_id", "created_at"])


def downgrade() -> None:
    existing = _existing_tables()
    for tbl in (
        "audit_logs",
        "task_jobs",
        "notification_locks",
        "appointments",
        "sent_followups",
        "marketing_campaigns",
        "automated_rules",
        "cargo_packages",
        "invoices",
        "user_memories",
        "sessions",
        "session_states",
        "messages",
        "registrations",
        "pages",
    ):
        if tbl in existing:
            op.drop_table(tbl)
