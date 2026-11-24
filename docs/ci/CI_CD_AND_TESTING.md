# PHASE 7 — CI/CD AND AUTOMATED TESTING

**Repository:** `https://github.com/AriukagiinTuvshoo/gerege-ai-agent`  
**Modules:** [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), [`tests/test_enterprise_phases.py`](../../tests/test_enterprise_phases.py), [`tests/test_ai_eval_suite.py`](../../tests/test_ai_eval_suite.py), [`requirements.txt`](../../requirements.txt)

---

## 1. GitHub Actions CI Pipeline Architecture

The CI workflow in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) provisions real **`postgres:16-alpine`** and **`redis:7-alpine`** service containers and executes 6 mandatory verification gates on every push and pull request to `main`:

1. **Syntax & Bytecode Compilation Gate:**
   - Runs `python -m py_compile` across all core application, router, service, worker, and migration modules.
2. **Schema & Declarative Model Consistency Gate:**
   - Runs `database.init_db()` and `models.Base.metadata.create_all()` to verify 100% alignment between all 15 SQLAlchemy models and SQL DDL definitions.
3. **Enterprise & AI Evaluation Suite (SQLite Mode):**
   - Runs `pytest tests/test_enterprise_phases.py tests/test_ai_eval_suite.py -v`.
4. **Module & Security E2E Regression Suites:**
   - Executes `scratch/test_audit_fixes.py`, `scratch/test_fintech_cargo.py`, `scratch/test_appointments_voice.py`, and `scratch/test_executive_retention.py`.
5. **PostgreSQL + Redis Integration & Migration Gate:**
   - Runs `alembic upgrade head` against `postgres:16-alpine`.
   - Runs `python scripts/migrate_sqlite_to_postgres.py --postgres-url "$DATABASE_URL"`.
   - Re-runs `pytest tests/test_enterprise_phases.py tests/test_ai_eval_suite.py -v` against live PostgreSQL + Redis.
6. **Production Container Build Gate:**
   - Runs `docker build -t gerege-ai-agent:ci .` to verify non-root image creation and dependency installation.

---

## 2. Automated Test Coverage Matrix

| Category | Test File | Coverage Details |
|----------|-----------|------------------|
| Unauthenticated Access Rejection (`401`) | `tests/test_enterprise_phases.py` | Verifies `/api/pages`, `/api/leads`, `/api/sessions`, `/api/fintech/*`, `/api/cargo/*`, `/api/executive/*`, `/api/retention/*`, `/api/appointments*`, `/api/admin/*` return `401` without credentials |
| Role-Based Access Control (`403`) | `tests/test_enterprise_phases.py` | Tests all 7 roles (`super_admin`, `admin`, `manager`, `agent`, `warehouse_staff`, `client`, `read_only`) against `ROLE_PERMISSIONS` |
| Cross-Tenant Isolation (`403`) | `tests/test_enterprise_phases.py` | Verifies Tenant A cannot read/modify Tenant B leads, sessions, invoices, cargo, appointments, or rules |
| Session Expiry & Revocation | `tests/test_enterprise_phases.py` | Tests `revoke_session`, `/api/auth/logout`, and automatic session invalidation on password/token rotation |
| Webhook HMAC & Secret Verification | `tests/test_enterprise_phases.py` | Tests Meta `X-Hub-Signature-256`, Telegram `X-Telegram-Bot-Api-Secret-Token`, and ManyChat `X-ManyChat-Secret` fail-closed behavior |
| QPay Payment Verification & Replay Protection | `tests/test_enterprise_phases.py` | Tests `check_qpay_payment_live_detailed` amount/currency mismatch rejection, strict callback verification, and idempotent payment lock |
| Receipt Fraud Prevention | `tests/test_enterprise_phases.py`, `tests/test_ai_eval_suite.py` | Verifies AI vision output alone never marks an invoice `PAID` |
| Backup, Checksum & Restore | `tests/test_enterprise_phases.py` | Tests `create_backup`, `verify_backup` (SHA-256 + integrity check), and `prune_old_backups` |
| Task Queue Atomic Claim, Retry & DLQ | `tests/test_enterprise_phases.py` | Tests `enqueue`, idempotency deduplication, atomic worker claim, retry backoff, and DLQ handling |
| AI Safety & 10-Category Eval Suite | `tests/test_ai_eval_suite.py` | Tests Mongolian FAQ, lead registration, QPay invoice tool, receipt fraud rejection, cargo tracking, appointments, human handoff, prompt injection, secret redaction, and cross-tenant tool refusal |
