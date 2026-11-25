"""Frozen snapshot of the column types declared in `core/models.py`.

=============================================================================
WHY A FROZEN SNAPSHOT AND NOT `import core.models`
=============================================================================
`init_db()`'s runtime DDL created *every* string column as untyped `TEXT` instead of
the `VARCHAR(n)` the models declare, so a database that was built by running the app
(more precisely: by the old `init_db()`) differs from `models.py` in ~91 columns even
after `0001` runs. The purpose of revision `0002` is to converge those columns onto
`models.py`.

Reading the types from `core.models` at migration time would technically work, but it
would make the migration's behaviour depend on the *current* contents of a file that
keeps changing: adding a column to `models.py` would silently make this historical
migration try to migrate a column that did not exist when it was written. Migrations
must be reproducible snapshots.

So the types are frozen here, and `tests/test_stage_c_schema.py` asserts that this
snapshot still matches `core/models.py`. If someone changes a column type in the
models, that test fails and points at the change, which is exactly when a *new*
migration should be written.

Entry format: ``(table, column, sqlalchemy_type)``.
"""
from __future__ import annotations

import sqlalchemy as sa

# ``TEXT -> VARCHAR(n)`` / ``TEXT -> FLOAT`` / ``TEXT -> TIMESTAMP`` convergence.
# Generated from `compare_metadata(..., compare_type=True)` against a database built
# by the legacy `init_db()`, then frozen.
TEXT_TO_DECLARED_TYPE: list[tuple[str, str, sa.types.TypeEngine]] = [
    # ---- appointments
    ("appointments", "appointment_date", sa.String(32)),
    ("appointments", "appointment_time", sa.String(16)),
    ("appointments", "channel", sa.String(64)),
    ("appointments", "customer_name", sa.String(255)),
    ("appointments", "customer_phone", sa.String(64)),
    ("appointments", "page_id", sa.String(128)),
    ("appointments", "sender_id", sa.String(255)),
    ("appointments", "service_name", sa.String(255)),
    ("appointments", "status", sa.String(64)),
    # ---- audit_logs
    ("audit_logs", "action", sa.String(128)),
    ("audit_logs", "actor_id", sa.String(255)),
    ("audit_logs", "actor_role", sa.String(64)),
    ("audit_logs", "ip_address", sa.String(64)),
    ("audit_logs", "page_id", sa.String(128)),
    ("audit_logs", "resource_id", sa.String(255)),
    ("audit_logs", "resource_type", sa.String(64)),
    # ---- automated_rules
    ("automated_rules", "page_id", sa.String(128)),
    ("automated_rules", "rule_type", sa.String(64)),
    # ---- cargo_packages
    ("cargo_packages", "channel", sa.String(64)),
    ("cargo_packages", "customer_name", sa.String(255)),
    ("cargo_packages", "customer_phone", sa.String(64)),
    ("cargo_packages", "invoice_id", sa.String(128)),
    ("cargo_packages", "page_id", sa.String(128)),
    ("cargo_packages", "sender_id", sa.String(255)),
    ("cargo_packages", "status", sa.String(64)),
    ("cargo_packages", "tracking_code", sa.String(128)),
    ("cargo_packages", "warehouse_location", sa.String(255)),
    ("cargo_packages", "weight_kg", sa.Float()),
    # ---- comment_automations
    ("comment_automations", "cta_button_text", sa.String(128)),
    ("comment_automations", "keyword_pattern", sa.String(500)),
    ("comment_automations", "name", sa.String(255)),
    ("comment_automations", "page_id", sa.String(128)),
    ("comment_automations", "post_id", sa.String(255)),
    # ---- invoices
    ("invoices", "channel", sa.String(64)),
    ("invoices", "currency", sa.String(16)),
    ("invoices", "ebarimt_lottery", sa.String(64)),
    ("invoices", "invoice_id", sa.String(128)),
    ("invoices", "page_id", sa.String(128)),
    ("invoices", "sender_id", sa.String(255)),
    # ---- marketing_campaigns
    ("marketing_campaigns", "channel", sa.String(64)),
    ("marketing_campaigns", "page_id", sa.String(128)),
    ("marketing_campaigns", "status", sa.String(64)),
    ("marketing_campaigns", "target_segment", sa.String(64)),
    ("marketing_campaigns", "title", sa.String(255)),
    # ---- messages
    ("messages", "channel", sa.String(64)),
    ("messages", "page_id", sa.String(128)),
    ("messages", "sender_id", sa.String(255)),
    ("messages", "sender_type", sa.String(32)),
    # ---- notification_locks
    ("notification_locks", "channel", sa.String(64)),
    ("notification_locks", "idempotency_key", sa.String(255)),
    # ---- pages
    ("pages", "ai_provider", sa.String(64)),
    ("pages", "category", sa.String(64)),
    ("pages", "client_magic_token", sa.String(255)),
    ("pages", "client_salt", sa.String(128)),
    ("pages", "client_username", sa.String(128)),
    ("pages", "name", sa.String(255)),
    ("pages", "page_id", sa.String(128)),
    ("pages", "qpay_invoice_code", sa.String(255)),
    ("pages", "qpay_username", sa.String(255)),
    ("pages", "telegram_manager_chat_id", sa.String(128)),
    ("pages", "verify_token", sa.String(255)),
    # ---- registrations
    ("registrations", "channel", sa.String(64)),
    ("registrations", "name", sa.String(255)),
    ("registrations", "page_id", sa.String(128)),
    ("registrations", "phone", sa.String(64)),
    ("registrations", "sender_id", sa.String(255)),
    ("registrations", "service", sa.String(255)),
    ("registrations", "status", sa.String(64)),
    # ---- sent_followups
    ("sent_followups", "channel", sa.String(64)),
    ("sent_followups", "page_id", sa.String(128)),
    ("sent_followups", "rule_type", sa.String(64)),
    ("sent_followups", "sender_id", sa.String(255)),
    # ---- session_states
    ("session_states", "channel", sa.String(64)),
    ("session_states", "customer_name", sa.String(255)),
    ("session_states", "customer_phone", sa.String(64)),
    ("session_states", "page_id", sa.String(128)),
    ("session_states", "sender_id", sa.String(255)),
    # ---- sessions
    ("sessions", "ip_address", sa.String(64)),
    ("sessions", "page_id", sa.String(128)),
    ("sessions", "session_token", sa.String(255)),
    # ---- task_jobs
    ("task_jobs", "idempotency_key", sa.String(255)),
    ("task_jobs", "locked_by", sa.String(128)),
    ("task_jobs", "status", sa.String(32)),
    ("task_jobs", "task_name", sa.String(128)),
    # ---- tracked_links
    ("tracked_links", "code", sa.String(64)),
    ("tracked_links", "page_id", sa.String(128)),
    ("tracked_links", "title", sa.String(255)),
    # ---- user_memories
    ("user_memories", "customer_name", sa.String(255)),
    ("user_memories", "page_id", sa.String(128)),
    ("user_memories", "phone", sa.String(64)),
    ("user_memories", "user_id", sa.String(255)),
]

# Unique constraints that `models.py` names explicitly. The legacy DDL let PostgreSQL
# auto-name them (`<table>_<cols>_key`), which is invisible to name-based drift checks
# but shows up as remove+add churn in type-aware ones.
UNIQUE_CONSTRAINTS: list[tuple[str, str, list[str]]] = [
    ("appointments", "uq_appointment_slot",
     ["page_id", "appointment_date", "appointment_time", "service_name"]),
    ("automated_rules", "uq_automated_rule_page_type", ["page_id", "rule_type"]),
    ("cargo_packages", "uq_cargo_page_tracking", ["page_id", "tracking_code"]),
    ("sent_followups", "uq_sent_followup", ["page_id", "rule_type", "sender_id"]),
    ("user_memories", "uq_user_memories_page_user", ["page_id", "user_id"]),
]

#: PostgreSQL's auto-generated names for the constraints above, used on downgrade.
AUTO_NAMED_UNIQUE: dict[str, str] = {
    "uq_appointment_slot":
        "appointments_page_id_appointment_date_appointment_time_serv_key",
    "uq_automated_rule_page_type": "automated_rules_page_id_rule_type_key",
    "uq_cargo_page_tracking": "cargo_packages_page_id_tracking_code_key",
    "uq_sent_followup": "sent_followups_page_id_rule_type_sender_id_key",
}


#: Columns whose legacy type was *not* `TEXT` but still disagrees with the models.
#: The old runtime DDL declared `weight_kg REAL`; `create_all()` renders `sa.Float`
#: as `FLOAT(53)` = `double precision`. Recorded as (table, column, legacy types to
#: replace, target DDL).
EXTRA_TYPE_FIXES: list[tuple[str, str, tuple[str, ...], str]] = [
    ("cargo_packages", "weight_kg", ("real", "double precision"), "float(53)"),
]
