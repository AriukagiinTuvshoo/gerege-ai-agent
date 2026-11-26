# Omnichannel AI Chatbot Agent (Бүртгэл & Борлуулалтын Систем)

Энэхүү систем нь уламжлалт сарын хураамжтай платформуудыг (ManyChat, Chatfuel г.м) бүрэн орлох, **100% таны өөрийн эзэмшлийн (Vendor Lock-in байхгүй), сарын суурь төлбөргүй** AI чатбот платформ юм.

---

## 🌟 Гол давуу талууд
1. **Хэрэглээгээрээ тооцоо хийнэ**: Сарын суурь төлбөр 0₮. Google Gemini Flash (Free Tier) ашигладаг тул өдөр тутам бүрэн үнэгүй ашиглах боломжтой.
2. **Өгөгдөл таны мэдэлд үлдэнэ**: Бүртгэгдсэн бүх харилцагчийн нэр, утас, чат баазад хадгалагдаж, нэг товшилтоор **Excel (.CSV)** болгон татаж авна.
3. **Omnichannel холболт**: Нэг л AI агент таны **Facebook Page**, **Instagram Direct**, **Telegram Bot**, болон **Вэбсайт**-аар нэгэн зэрэг харилцаж бүртгэл авна.

---

## 🧰 Суулгах (Local setup)

### 1. Шаардлага

| Зүйл | Local (development) | Production |
|---|---|---|
| Python | 3.11 эсвэл дээш | **3.12** (`Dockerfile` нь `python:3.12-slim`; `requirements.lock` нь CPython 3.12-т hash-verified) |
| Өгөгдлийн сан | SQLite (файл) — суулгалт шаардлагагүй | **PostgreSQL 16** |
| Redis | Шаардлагагүй (memory / DB fallback) | **ЗААВАЛ** (rate limit + task queue) |
| Docker | Шаардлагагүй | `docker-compose.prod.yml` |

### 2. Virtual environment үүсгэх

**Windows**
```bat
python -m venv .venv
.venv\Scripts\activate
```

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Дараа нь хаж бичилтгүйгээр суулгана:

```bash
pip install -r requirements.txt        # ажиллуулахад шаардлагатай
pip install -r requirements-dev.txt    # зөвхөн тест/CI-д (заавал биш)
```

> Production/Docker build нь `requirements.lock` (hash-verified, CPython 3.12) ашиглана.
> Тэмдэглэл: `.venv/` нь `.gitignore`-д ороогүй тул virtual environment-ийг repo-оос
> **гадна** үүсгэх, эсвэл `git status`-д олон мянган файл харагдахаас сэргийлж
> `.venv/`-ийг өөрөө ignore-д нэмэх нь зүйтэй.

### 3. `.env` үүсгэх

```bat
:: Windows — хуучин .env байвал ДАРЖ БИЧИХГҮЙ
if not exist .env copy .env.example .env
```
```bash
# macOS / Linux — `-n` нь байгаа файлыг дарж бичихгүй
cp -n .env.example .env
```

`.env` нь `.gitignore`-д орсон тул git-д хэзээ ч орохгүй. **Бодит нууц үг, token,
API key-ийг хэзээ ч commit хийхгүй**, мөн issue/лог/скриншотод харуулахгүй.

### 4. Нууц утгуудыг өөрөө үүсгэх

```bash
python -c "import secrets; print(secrets.token_urlsafe(24))"   # ADMIN_PASSWORD
python -c "import secrets; print(secrets.token_urlsafe(48))"   # E02_ACCOUNT_KEY_SECRET (хамгийн багадаа 32 тэмдэгт)
python -c "import secrets; print(secrets.token_urlsafe(32))"   # META_VERIFY_TOKEN / META_APP_SECRET / TELEGRAM_WEBHOOK_SECRET
```

> ### ⚠️ ЧУХАЛ — бэлэн жишээ утга ашиглахгүй
>
> Энэ repository-д хэвлэгдсэн **ямар ч** жишээ/анхдагч утгыг (хоосон утга, `changeme`,
> `<generate: ...>` маягийн placeholder, мөн хуучин нийтлэг default verify token)
> webhook эсвэл нэвтрэлтийн нууц болгон ашиглаж **болохгүй**. Тэдгээр утга нь энэ
> repository-г уншсан хүн бүрт мэдэгдэж байгаа тул нууц биш.
>
> Код үүнийг зүгээр сануулга биш, **fail-closed** байдлаар шалгадаг:
> `ENV=production` эсвэл `STRICT_SECURITY=1` үед ийм утга нь *ашиглах боломжгүй* гэж
> үнэлэгдэж, webhook handshake няцаагдана, шаардлагатай нууц дутвал процесс
> **эхлэхгүй** (`core/security.py`, `core/secret_guard.py`).
>
> `ADMIN_PASSWORD`-г `.env`-д тохируулсны дараа built-in development default бүрэн
> хаагдана. Production-д `ADMIN_PASSWORD` тохируулаагүй бол админ нэвтрэлт fail-closed
> (нэвтрэхгүй) болно.

### 5. Өгөгдлийн сан

**Local (SQLite):**
```dotenv
DB_PATH=/зам/дисposable-local.db
# эсвэл: DATABASE_URL=sqlite:///local.db
# Хоёр хоосон бол repo root-ын leads.db ашиглана (өөрийн дата-г дарж бичихээс сэргийлж
# туршилтын хувьд DB_PATH-г заах нь зүйтэй).
```
Дагаж мөрдөх дараалал: `DB_PATH` → `sqlite:///` төрлийн `DATABASE_URL` → `./leads.db`.

**Production (PostgreSQL):**
```dotenv
DATABASE_URL=postgresql+psycopg2://gerege_app:<password>@host:5432/gerege
DATABASE_OWNER_URL=postgresql+psycopg2://gerege_owner:<password>@host:5432/gerege
```
`DATABASE_OWNER_URL`-ыг зөвхөн `scripts/maintenance.py` (backup/restore) болон
`scripts/provision_roles.py` ашиглана — web/worker процесс түүнийг хэзээ ч авахгүй.
Production-д role-уудыг заавал тусгаарлана:
```bash
python scripts/provision_roles.py --apply     # least-privilege role үүсгэх
python scripts/provision_roles.py --check     # шалгах
```

**Migration:** схем startup дээр автоматаар `alembic upgrade head` хүртэл шинэчлэгдэнэ
(одоогоор `0001` → `0008`). Шалгах:
```bash
alembic current      # 0008_tenant_not_null (head)
alembic heads        # ганц head байх ёстой
```

### 6. Redis

| Горим | `REDIS_URL` | Үр дүн |
|---|---|---|
| Development / test | хоосон байж болно | rate limit нь process-ийн memory (лимит зөвхөн нэг процесс), task queue нь DB fallback |
| **Production** | **ЗААВАЛ бөгөөд хүрэхүйц** | хоосон эсвэл `PING` авахгүй бол startup `RateLimitStoreUnavailable`-аар **зогсоно** (R11) |

---

## ▶️ Ажиллуулах

### Backend (development)

```bash
python main.py
```
Дараа нь хөтөч дээр **`http://127.0.0.1:8000`** — нэвтрэх нууц үг нь `.env`-ийн
`ADMIN_PASSWORD`.

Windows-д `start.bat` мөн адил `python main.py`-ийг дуудна.

> `python main.py` нь dev entrypoint бөгөөд **loopback** (`127.0.0.1`) дээр bind хийж,
> reload асаалттай ирдэг. Түр сүлжээнд нээх шаардлага гарвал `HOST=0.0.0.0` гэж өгнө —
> энэ нь reload-тэй dev серверийг бүх interface дээр нээж байгааг санаарай.

### Container / production зам

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2   # Dockerfile-ын ашигладаг зам
docker compose -f docker-compose.prod.yml up -d            # TLS/ACME, PostgreSQL, Redis, worker
```
Staging-ийн rehearsal: `docker-compose.staging.yml` + `.env.staging.example`.

### Worker & scheduler

```bash
python worker.py
```
Worker нь web серверээс **тусдаа** процесс бөгөөд queue handler, scheduled тайлан,
retention, heartbeat-ийг гүйцэтгэнэ. Олон instance ажиллуулах үед давхардуулахаас
сэргийлж `DISABLE_INLINE_SCHEDULER=1` тохируулна.

### Health endpoint-үүд

| Endpoint | Зориулалт |
|---|---|
| `GET /api/live` | liveness (контейнер/shutdown-ыг шалгах) |
| `GET /api/ready` | readiness — DB + queue + rate-limit store |
| `GET /api/health` | хүн/хамгаалалтын давтамжтай dashboard-д зориулсан хураангуй |
| `GET /api/admin/worker/health` | worker heartbeat + scheduler төлөв (админ эрхтэй) |

### Зогсоох

`Ctrl+C` эсвэл `SIGTERM` — аль аль нь graceful shutdown хийнэ (worker heartbeat
цэвэрлэгдэж, DB engine dispose хийгдэнэ).

---

## 🤖 Google Gemini API түлхүүр (Үнэгүй)

1. [Google AI Studio](https://aistudio.google.com/app/apikey) руу Google хаягаараа нэвтэрч **"Create API key"** дарна.
2. Гарсан түлхүүрээ:
   * Вэб самбар дээрх **"Тохиргоо & Түлхүүр"** хэсэгт оруулах (салбар тус бүрд), эсвэл
   * `.env` файлын `GEMINI_API_KEY=` ард бичих.
3. Түлхүүр байхгүй үед систем ажилласан хэвээр байх бөгөөд `/api/health` нь
   `gemini_ready: false` гэж **үндэслэлтэйгээр** мэдээлнэ (AI хариулт идэвхгүй).

---

## 🔗 Facebook Messenger & Instagram DM холболт

Webhook холбохын тулд сервер нийтийн `https://` хаягтай байх ёстой.

### А. Түр турших (ngrok эсвэл Cloudflare Tunnel)
```bash
ngrok http 8000
```
Windows-д `tunnel.bat` (Cloudflare Tunnel) эсвэл `start_agency.bat` (сервер + tunnel
зэрэг) ашиглаж болно. Гарсан `https://...` хаягийг ашиглана.

### Б. Meta for Developers тохиргоо
1. [Meta for Developers](https://developers.facebook.com/) руу орж App үүсгэнэ.
2. **Messenger** болон **Instagram Graph API** бүтээгдэхүүнийг нэмнэ.
3. **Webhooks** → **Callback URL**: `https://<таны-хаяг>/webhook`
4. **Verify Token**: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
   командоор **өөрөө үүсгэсэн** санамсаргүй утгыг ашиглаж, түүнийгээ `.env`-ийн
   `META_VERIFY_TOKEN=` дээр бичнэ. Meta-д оруулах утга болон `.env`-ийн утга яг ижил
   байх ёстой. Repository-д хэвлэгдсэн бэлэн жишээ утгыг ашиглахгүй (дээрх сануулга).
5. `messages` болон `messaging_postbacks` эрхийг Subscribe хийнэ.
6. Хуудасны **Page Access Token**-оо `.env`-ийн `META_PAGE_ACCESS_TOKEN=` дээр тавина.
7. **`META_APP_SECRET`** (App Dashboard → Settings → Basic) — ирсэн webhook хүсэлтийн
   `X-Hub-Signature-256` гарын үсгийг баталгаажуулахад шаардлагатай. Production болон
   `WEBHOOK_FAIL_CLOSED=1` үед гарын үсэг/нууц байхгүй хүсэлт **403**-аар няцаагдана.

Одоо хэрэглэгч таны Facebook хуудас эсвэл Instagram руу бичих үед AI агент автоматаар
хариулж, дугаарыг нь бүртгэнэ.

---

## 📱 Telegram Bot

```dotenv
TELEGRAM_BOT_TOKEN=<BotFather-оос авсан token>
TELEGRAM_WEBHOOK_SECRET=<өөрөө үүсгэсэн санамсаргүй утга>
TELEGRAM_MANAGER_CHAT_ID=<эзний chat id>
```
`setWebhook` дуудлагад `secret_token`-оор `TELEGRAM_WEBHOOK_SECRET`-ийг өгнө; сервер
түүнийг `X-Telegram-Bot-Api-Secret-Token` header-ээс шалгана. Нууц тохируулаагүй үед
production/fail-closed горимд webhook хүсэлт **403** буцна.

---

## 📚 Баримт бичиг

| Сэдэв | Файл |
|---|---|
| Системийн архитектур | `docs/architecture/SYSTEM_ARCHITECTURE.md` |
| Task queue / worker | `docs/architecture/TASK_QUEUE.md` |
| Аюулгүй байдлын загвар | `docs/security/SECURITY_MODEL.md` |
| Аюулгүй байдлын хэрэгжилт | `docs/security/SECURITY_IMPLEMENTATION.md` |
| Production deployment | `docs/deployment/PRODUCTION_DEPLOYMENT.md` |
| Staging deployment | `docs/deployment/STAGING_DEPLOYMENT.md` |
| Production env template | `docs/deployment/PRODUCTION_ENV_TEMPLATE.env` |
| Backup & restore | `docs/operations/BACKUP_RESTORE.md` |
| Disaster recovery | `docs/operations/DISASTER_RECOVERY.md` |
| Incident response | `docs/operations/INCIDENT_RESPONSE.md` |
| Scheduler тохиргоо | `docs/SCHEDULER-SETUP.md` |
| Alerting тохиргоо | `docs/ALERTING-SETUP.md` |
| Offsite backup | `docs/OFFSITE-BACKUP-SETUP.md` |
| Migration guide | `docs/database/MIGRATION_GUIDE.md` |
| PostgreSQL migration | `docs/database/POSTGRESQL_MIGRATION.md` |
| AI найдвартай байдал | `docs/ai/AI_RELIABILITY_AND_SECURITY.md` |
| CI/CD & тест | `docs/ci/CI_CD_AND_TESTING.md` |

---

## ✅ Production гаргахын өмнөх шалгалт

1. `ENV=production`, `STRICT_SECURITY=1`
2. `ADMIN_PASSWORD`, `E02_ACCOUNT_KEY_SECRET` (≥32), `META_APP_SECRET`,
   `META_VERIFY_TOKEN`, `TELEGRAM_WEBHOOK_SECRET` — бүгд **өөрөө үүсгэсэн** утга
3. `ALLOWED_ORIGINS` (тодорхой origin жагсаалт; `*` хориотой), `APP_ORIGIN`,
   `TRUSTED_PROXIES` (зөвхөн өөрийн proxy-гийн IP)
4. `DATABASE_URL` = PostgreSQL (`gerege_app` role), `DATABASE_OWNER_URL` тусдаа,
   `scripts/provision_roles.py --check` алдаагүй
5. `REDIS_URL` заавал, `PING` авдаг
6. Backup: `BACKUP_ENCRYPTION=1` + `BACKUP_ENCRYPTION_KEY_FILE` (0400),
   `BACKUP_OFFSITE_PATH` (өөр диск/host), `BACKUP_ALERT_WEBHOOK`,
   `BACKUP_RETENTION_DAYS`, `BACKUP_MIN_KEEP`
7. `WEBHOOK_FAIL_CLOSED=1`, `ALLOW_QUERY_TOKEN=0`
8. Тест: `pytest` (бүх suite ногоон), CI workflow амжилттай

> Дутуу эсвэл сул нууцтай үед production процесс **эхлэхгүй** — энэ нь зориудаар
> ингэж хийгдсэн (чийгүй дуугарахгүйгээр зогсох нь "ажиллаж байна гэж итгэх"-ээс дээр).
