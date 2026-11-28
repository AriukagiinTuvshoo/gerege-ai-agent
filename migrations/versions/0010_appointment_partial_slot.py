"""0010 — partial unique index on appointments excluding CANCELLED slots (P0-9)

Revision ID: 0010_appointment_partial_slot
Revises: 0009_verify_token_default
"""

from alembic import op
import sqlalchemy as sa


revision = "0010_appointment_partial_slot"
down_revision = "0009_verify_token_default"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute("ALTER TABLE appointments DROP CONSTRAINT IF EXISTS uq_appointment_slot")
        op.execute("DROP INDEX IF EXISTS uq_appointment_slot")
        op.create_index(
            "uq_appointment_slot",
            "appointments",
            ["page_id", "appointment_date", "appointment_time", "service_name"],
            unique=True,
            postgresql_where=sa.text("status != 'CANCELLED'"),
        )
    else:
        with op.batch_alter_table("appointments") as batch_op:
            try:
                batch_op.drop_constraint("uq_appointment_slot", type_="unique")
            except Exception:
                pass
        op.execute("DROP INDEX IF EXISTS uq_appointment_slot")
        op.create_index(
            "uq_appointment_slot",
            "appointments",
            ["page_id", "appointment_date", "appointment_time", "service_name"],
            unique=True,
            sqlite_where=sa.text("status != 'CANCELLED'"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_index("uq_appointment_slot", table_name="appointments")
    if bind.dialect.name == "postgresql":
        op.create_unique_constraint(
            "uq_appointment_slot",
            "appointments",
            ["page_id", "appointment_date", "appointment_time", "service_name"],
        )
    else:
        with op.batch_alter_table("appointments") as batch_op:
            batch_op.create_unique_constraint(
                "uq_appointment_slot",
                ["page_id", "appointment_date", "appointment_time", "service_name"],
            )
