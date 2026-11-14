# Test Strategy & Verification Matrix — Gerege AI Agent

## 1. Test Suites Overview

| Suite | File | Scope |
|---|---|---|
| **Enterprise Phases 1–8** | `tests/test_enterprise_phases.py` | 16 integration tests covering RBAC (7 roles), session revocation, fail-closed Meta/Telegram webhooks, QPay provider verification, cross-tenant IDOR, SSRF guard, 15 SQLAlchemy models, migration dry-run, backup/verify API, prompt injection, tool guard, task queue, and `/api/health` + `/api/ready`. |
| **AI Evaluation Suite** | `tests/test_ai_eval_suite.py` | 11 categories testing greeting/FAQ, pricing, registration + persistent user memory, cargo lookup isolation, appointment double-booking guard, QPay invoice generation, receipt upload guard, prompt injection + `CircuitBreaker`, secret leak prevention, user data deletion (`Бүртгэл устгах`), and deterministic CI no-API-key fallback. |
| **20-Scenario Failure & Chaos Suite** | `tests/test_failure_scenarios.py` | 20 failure/chaos tests covering DB outage (`503`), Redis outage fallback, crashed worker stale `PROCESSING` recovery, unhandled exception telemetry + secret redaction, connection pool concurrency, webhook deduplication, job idempotency, invalid/revoked tokens (`401`), cross-tenant `403`, migration conflict abort, corrupted backup & restore rejection, AI retry/timeout, token quota enforcement, `<thought>`/secret sanitization, `413` upload guard, restart persistence, multi-worker atomic claiming race, and graceful worker shutdown. |

## 2. Running the Suites Locally & in CI

```bash
# Run all 3 suites via pytest
pytest tests/test_enterprise_phases.py tests/test_ai_eval_suite.py tests/test_failure_scenarios.py -v

# Or run directly via Python
python tests/test_enterprise_phases.py
python tests/test_ai_eval_suite.py
python tests/test_failure_scenarios.py
```

## 3. Continuous Integration Gate (`.github/workflows/ci.yml`)

Every push and pull request to `main` executes:
1. `py_compile` syntax verification across all application, core, router, and script modules.
2. SQLite schema initialization, SQLAlchemy 15-table creation, and `verify_schema_drift()` (`has_drift == False`).
3. Full 3-suite execution (`test_enterprise_phases.py`, `test_ai_eval_suite.py`, `test_failure_scenarios.py`) in SQLite mode.
4. `scripts/migrate_sqlite_to_postgres.py --dry-run`.
5. Live PostgreSQL 16 + Redis 7 service container verification: `alembic upgrade head`, live `migrate_sqlite_to_postgres.py --postgres-url "$DATABASE_URL"`, and full 3-suite execution against PostgreSQL 16 and Redis 7.
6. Production Docker image build (`docker build -t gerege-ai-agent:ci .`).
