# Staging Integration Test Matrix

Phase 36. Every integration in this repository is **mock-verified only**. Phase 33/34
proved the code paths with fakes; nothing has ever talked to a live provider. This matrix
is the plan for closing that gap in staging.

## Read this first

Three rules, because breaking any of them is unrecoverable in a way mocks never are:

1. **Never send a message to a real customer.** Use test accounts you control. A wrong
   `META_PAGE_ACCESS_TOKEN` is how a "test" reaches someone's phone.
2. **Never charge money.** QPay sandbox only. No live merchant credentials in staging.
3. **Never import real customer data.** Staging data is invented.

Every row below marked **[requires real credential]** stops until someone supplies a
sandbox credential and explicitly authorises the live test. That is a deliberate gate, not
an oversight.

## Matrix

| Integration | Credential needed | Test | Expected result | Risk | Live |
|---|---|---|---|---|---|
| **Telegram (send)** | Separate test bot token from @BotFather | Send a message to a test chat via the worker's report path | Telegram API returns `ok: true`; message arrives in the test chat | A wrong token posts to a real audience. Use a bot nobody else holds | **[requires real credential]** |
| **Telegram (blocked-bot path)** | Same | Send to a user who has blocked the bot | HTTP 403 captured, **no token text in the log** (F-34-3 was exactly this leak), job marked failed not dead | Low; this is the safe failure to provoke | **[requires real credential]** |
| **Telegram (webhook in)** | `TELEGRAM_WEBHOOK_SECRET` | POST a signed update to `/api/telegram/webhook` | Accepted; replay of the same update is rejected | Misconfigured secret silently drops all traffic | code-verified |
| **Meta / Facebook webhook** | App secret + verify token from a **development-mode** app | GET verification handshake, then a signed POST | Handshake echoes `hub.challenge`; `X-Hub-Signature-256` verified; unsigned POST rejected | Development-mode app only reaches test recipients | **[requires real credential]** |
| **Instagram** | Same Meta app, IG account linked | Signed webhook POST | Same signature path; event routed to the right page | IG and FB share the app secret — a rotation breaks both | **[requires real credential]** |
| **QPay (create invoice)** | **Sandbox** merchant username/password/invoice code | Create a payment order via the admin API | Invoice URL returned, `https://` (see F-36-3) | Live credentials would move real money | **[requires real credential]** |
| **QPay (callback)** | Same | POST the callback with matching amount/currency | Settled once; replay is idempotent; **wrong amount is rejected** | A callback that trusts its payload is free money | **[requires real credential]** |
| **Google Sheets** | None — public CSV export | Point a page at a published sheet, run a sync | Rows imported, no auth used | A private sheet returns an error rather than silently importing nothing | code-verified |
| **Gemini** | API key (can be the real one; it is a spend risk, not a data risk) | Run one conversation turn | Model reply returned; measure latency and token cost | Cost, not correctness. **Budget must be agreed before the test** | **[requires real credential]** |
| **ManyChat** | Test token | Trigger the flow | Request accepted; 4xx surfaces as a failed job | Low | **[requires real credential]** |
| **Outbound webhooks** | None | Register a listener on a request-bin, fire an event | Delivered, signed, retried on 5xx | An unbounded retry loop against a customer endpoint | code-verified |

## What "code-verified" means here

The behaviour is asserted by a test against a mocked transport: correct URL, correct
signature computation, correct duplicate handling, correct timeout. It does **not** mean the
provider accepts the request. For example, the Meta signature test proves the HMAC matches
what we compute from `META_APP_SECRET`; it cannot prove Meta accepts our app configuration.

## Order of work

1. **Telegram** — smallest surface, easiest to prove end-to-end, and the blocked-bot path
   exercises the Phase 34 leak fix against a live provider.
2. **Meta/Instagram** — the signature path is the security-critical one.
3. **QPay sandbox** — highest consequence; do it after the callback idempotency has been
   observed at least once.
4. **Gemini** — cost measurement, needs an agreed budget.
5. **Google Sheets / ManyChat / webhooks** — lowest risk, last.

## Timeouts already in place

All integrations bound their calls at 10–12 s and the AI path retries at most twice with
exponential backoff. Staging should confirm those bounds hold against real latency, because
a provider that answers in 9 s under load is a different system from one that answers in
200 ms.
