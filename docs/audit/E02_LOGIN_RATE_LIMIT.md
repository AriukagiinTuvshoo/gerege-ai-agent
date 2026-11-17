# E-02 — Login Rate-Limit Bypass and Account-Level Protection

**Status:** Phase 3 complete · Phase 4 (account-level protection) not started
**Severity:** P0 — the audit's 14/14 bypass was reproducible
**Commits:** `cd13a5c` (Phase 2 tests), Phase 3 commit on `arena/d78ebf88-gerege-ai-agent`
**Scope discipline:** only the client-IP policy. The account-level counter, the uniform
login response and Redis-outage behaviour are untouched and still open.

---

## 1. Root cause

Two independent defects, and a third that made fixing either one deceptively hard.

### 1.1 The rate-limit key was client-controlled

`core/rate_limit.py::client_identity()`:

```python
forwarded = request.headers.get("x-forwarded-for", "")
if forwarded:
    return forwarded.split(",")[0].strip()      # left-most, attacker's own value
real_ip = request.headers.get("x-real-ip", "").strip()
if real_ip:
    return real_ip
return request.client.host
```

No trust check anywhere. A fresh `X-Forwarded-For` per request produced a fresh counter,
so the `auth_login` limit of 10/60s was bypassed by rotating one header.

### 1.2 There was no account-level counter

Nothing in the codebase counted failed logins per account. Rotating the source address was
sufficient; no account-level defence existed to fall back on.

### 1.3 `request.client.host` was not the TCP peer

`Dockerfile` ran `uvicorn main:app --workers 2` with no `--forwarded-allow-ips`, so
uvicorn 0.54 defaults applied: `proxy_headers=True`, `forwarded_allow_ips="127.0.0.1,::1"`.
Measured against a live server:

| Request | `request.client.host` |
|---|---|
| `X-Forwarded-For: 1.2.3.4` | `1.2.3.4` (port forced to `0`) |
| `X-Forwarded-For: 1.1.1.1, 2.2.2.2` | `2.2.2.2` — **right-most** |
| `X-Real-IP: 9.9.9.9` | `127.0.0.1` (ignored) |
| `Forwarded: for=7.7.7.7` | `127.0.0.1` (ignored) |
| `X-Forwarded-For: not-an-ip` | `not-an-ip` — **no validation** |

So there were **two parsers that disagreed**: uvicorn took the right-most entry without
validating it, the app took the left-most. Any "fix" that simply switched
`client_identity()` to `request.client.host` would have been a deployment-dependent guess,
and would still have handed the attacker the key when the peer was trusted.

## 2. Before / after

Measured on a real uvicorn process, 2 workers, shared Redis, `TRUSTED_PROXIES` empty.

| Vector | Attempts | Before | After |
|---|---|---|---|
| Rotating `X-Forwarded-For` | 14 | **14 accepted, 0 blocked** | **10 accepted, 4 blocked** |
| Rotating `X-Real-IP` | 14 | 14 accepted, 0 blocked | 10 accepted, 4 blocked |
| Rotating `Forwarded:` | 14 | 14 accepted, 0 blocked | 10 accepted, 4 blocked |
| All three rotated together | 14 | 14 accepted, 0 blocked | 10 accepted, 4 blocked |

The limiter is configured at 10/60s, so 10 accepted is the limit working. Redis proves the
identity collapse — 14 different headers produced exactly one counter:

```
ratelimit:auth_login:127.0.0.1 -> 14   (ttl 57)
```

Trusted-proxy path (socket peer in `TRUSTED_PROXIES`), two different real clients:

```
ratelimit:auth_login:203.0.113.50 -> 12     10 accepted, then 429
ratelimit:auth_login:203.0.113.51 -> 12     10 accepted, then 429
```

Multi-hop spoofing, two trusted hops, attacker rotating its own invented prefix in
`10.9.9.{i}, 203.0.113.60, 10.0.0.5` for 12 attempts:

```
ratelimit:auth_login:203.0.113.60 -> 12     one identity, 10 accepted then 429
```

The invented prefixes created no new identities.

## 3. Trusted-proxy policy

Configuration is **environment only**: `TRUSTED_PROXIES`, comma separated, IPv4 / IPv6 /
CIDR. There is no config file, UI or database setting.

Resolution rules, implemented once in `core/rate_limit.py::resolve_client_ip()`:

1. Start from the socket peer (`scope["client"]`).
2. Peer not trusted → ignore **every** forwarding header.
3. Peer trusted → take `X-Forwarded-For` and walk it **right-to-left**, skipping addresses
   that are themselves trusted proxies; the first untrusted address is the client.
4. **Every** entry must parse as an IP address. An empty or whitespace-only entry is
   malformed, exactly like `not-an-ip` is. One bad entry anywhere in the chain — including
   a position the walk would never have reached — aborts resolution and returns the socket
   peer. Malformed entries are never skipped.
5. Bounded: at most 15 hops and 1 KB of header. Beyond either, the peer is used.
6. `X-Real-IP` and RFC 7239 `Forwarded` are **not** supported and are never consulted.

Trust list handling:

| Input | Behaviour |
|---|---|
| unset / empty | trust nothing (secure default) |
| `10.0.0.0/8` | network accepted, membership by `ipaddress` |
| `2001:0db8::0001` | matched structurally to `2001:db8::1` |
| `*`, `all`, `0.0.0.0/0`, `::/0` | **rejected**, logged as an error |
| unparseable entry | dropped and logged; trust never widened |

## 4. Uvicorn configuration

`Dockerfile` CMD now ends with `--no-proxy-headers`.

Verified rather than assumed:

* uvicorn 0.54 **does** expose `--no-proxy-headers` (not every version does).
* `Config.load()` only installs `ProxyHeadersMiddleware` when `proxy_headers` is true, so
  disabling it leaves `scope["client"]` untouched.
* Live server with `--no-proxy-headers`: sending `X-Forwarded-For` no longer changes
  `scope["client"]` — it stays `127.0.0.1`, the real socket peer.
* Trust behaviour of uvicorn itself is sound (`_TrustedHosts` skips trusted hops
  right-to-left), but its **default trust list** is loopback, and it does not validate that
  an entry is an IP. Turning it off removes the duplicate authority.

**Impact:** none for this deployment. There is no reverse proxy in
`docker-compose.prod.yml` (port 8000 is published directly), so uvicorn's proxy processing
was already only reachable by a peer inside the container network — the case it is now
prevented from mishandling. If a proxy is added later, set `TRUSTED_PROXIES` to that
proxy's addresses.

`TRUSTED_PROXIES` is documented in `.env.example`, wired into `docker-compose.prod.yml`
(defaulting empty, with a comment saying why), and described in
`docs/deployment/PRODUCTION_DEPLOYMENT.md` §1.1.

## 4.1 Phase 3.1 — strict chain validation

A review found the code did not implement the policy documented above.

### Root cause

`resolve_client_ip()` contained `if not hop: continue` inside the right-to-left walk. An
empty entry was therefore treated as "nothing to see" and the walk carried on to the next
entry, so a malformed chain still produced a header-derived identity:

| `X-Forwarded-For` | Phase 3 result | Correct result |
|---|---|---|
| `", 198.51.100.9"` | `198.51.100.9` | peer |
| `"198.51.100.9, "` | `198.51.100.9` | peer |
| `"198.51.100.9,,10.1.2.3"` | `198.51.100.9` | peer |
| `"   , 198.51.100.9"` | `198.51.100.9` | peer |

### A second, unreported instance

The same leniency existed in the **all-trusted fallback loop**, which is a separate code
path and had its own `except ValueError: continue`. Measured with
`TRUSTED_PROXIES=10.1.2.3,10.9.9.9`:

```
X-Forwarded-For: ", 10.9.9.9"  ->  "10.9.9.9"
```

A header-derived identity produced from a malformed chain. The review named one `continue`;
there were two.

### Fix

Validation was moved **before** the walk: the whole chain is parsed up front, and any
invalid entry returns the socket peer immediately. Because the address list is fully
validated before selection, the second loop is no longer needed at all — it was removed
rather than patched, which eliminates the class of bug instead of the instance.

```python
addresses = []
for hop in hops:
    if not hop:                      # empty / whitespace-only
        logger.warning("Empty X-Forwarded-For entry ...; aborting the walk and using the socket peer")
        return peer_text
    try:
        addresses.append(ipaddress.ip_address(hop))
    except ValueError:
        logger.warning("Unparseable X-Forwarded-For entry ...; aborting the walk ...")
        return peer_text

for address in reversed(addresses):
    if not _is_trusted_proxy(address, trusted_list):
        return str(address)
return str(addresses[0]) if addresses else peer_text
```

### Preserved behaviour

Valid IPv4 chains, IPv6 chains, mixed families, trusted multi-hop chains, untrusted peers,
empty `TRUSTED_PROXIES`, the 15-hop cap and the 1 KB cap are all unchanged — `test_30`
exists specifically to fail if strictness is over-applied and every chain starts falling
back to the peer.

### Two test bugs found while writing this

Both were mine, and both were caught before the fix landed:

* `test_30` first asserted that `198.51.100.9, 2001:db8::7` resolves to `198.51.100.9`.
  That contradicts the documented right-to-left walk: the right-most entry is the closest
  hop. The code was right and the expectation was wrong.
* `test_29` was written to reach the second loop but used a chain with an untrusted first
  hop, so it exited via the first loop and proved nothing. Corrected to use an
  all-trusted chain, which is what actually reaches that path.

## 4.2 Phase 4 — account-level failed-login protection

### The gap Phase 3 left open

Phase 3 made the client IP trustworthy, so an attacker can no longer *claim* an address it
does not have. It does nothing about an attacker that simply **uses addresses it does have**:
a botnet, a residential proxy pool, or one cloud VM per attempt. `auth_login` allows 10
attempts per 60 seconds *per IP*, so 400 attempts against one account cost 40 addresses and
one minute.

The Phase 2 suite already demonstrated this concretely: 40 attempts against one account from
40 distinct source IPs were all accepted. Nothing bounded attempts *per account*.

### Design

Two limits, independent, both enforced:

| Layer | Key | Default | Stops |
|---|---|---|---|
| IP (Phase 3) | `ratelimit:auth_login:<client ip>` | 10 / 60 s | how fast one source can guess |
| Account (Phase 4) | `ratelimit:auth_account:<keyed digest>` | 20 / 900 s | how often one account can be guessed |

A request must pass both. The account check runs **before** authentication, so a burned
budget costs the attacker no database work, and a throttled request never reaches password
verification.

### A. Identity normalization

The real lookup is `LOWER(TRIM(client_username)) = LOWER(?)`, i.e. login is *already*
case-insensitive and whitespace-insensitive. The throttle key therefore applies
`str.strip().casefold()` so both agree.

| Input | Behavior | Test |
|---|---|---|
| `Acme-Mn`, `acme-mn`, `ACME-MN`, `  Acme-Mn  `, `aCME-mN` | one shared budget | `test_36` (6 spellings) |
| `Acme-Mn` vs `Acme.Mn` | separate budgets — casefolding does not touch `.` | `test_37` |
| empty, whitespace, NUL, 5 KB, non-ASCII, path traversal | no crash; 400/401/422/429 | `test_38` |

If normalization were *not* applied, each spelling would get its own budget and the limit
would multiply by however many spellings an attacker cared to try. The direction of any
disagreement between `casefold()` and SQLite `LOWER` is toward **sharing** a budget (which can
only over-throttle the same name written differently), never toward splitting one — splitting
is what would multiply the budget.

Empty or missing identifiers produce **no key at all** rather than a shared "empty" bucket,
because a shared bucket would let an unauthenticated stranger throttle every user at once.

### B. Key derivation — why keyed, and why a new secret

Keys are `blake2b(key=secret, person=..., digest_size=16)` over the normalized identifier.

* **Not plaintext.** A username in Redis is a leak of the customer list.
* **Not plain SHA-256.** Usernames are low entropy (`<brand>-mn`); an unkeyed digest is a
  dictionary lookup away from plaintext, so it is a privacy *theatre*, not a control.
* **No silent fallback.** With no secret, `account_key()` returns `None` and account counting
  is skipped. A fallback to an unkeyed hash would look like protection while leaking
  identifiers — strictly worse than the honest gap. Asserted by `test_41`.

A **dedicated** `E02_ACCOUNT_KEY_SECRET` is required. The existing secrets were assessed and
rejected:

| Secret | Why not |
|---|---|
| `META_APP_SECRET` | vendor-shared, rotates on Meta's schedule — a rotation would silently reset all counters; widens that secret's blast radius to login identifiers |
| `TELEGRAM_WEBHOOK_SECRET` | same problem, different vendor |
| `MANYCHAT_WEBHOOK_SECRET` | same problem |
| `GEMINI_API_KEY` | billable credential — never use a credential as a MAC key |

Verified by `test_40` (the key differs when the secret changes, and is not a plain SHA-256)
and `test_39` (no plaintext identifier appears in any key).

### C. Threshold, window, and why this is a throttle and not a lockout

`ACCOUNT_FAILURE_THRESHOLD = 20`, `ACCOUNT_FAILURE_WINDOW = 900 s`. Rationale, tied to what it
must stop rather than a round number:

* 20/15 min ≈ 80 guesses/hour ≈ 1,900/day per account, and **independent of how many
  addresses the attacker has** — which is the entire point.
* 20 failures in 15 minutes is not a person mistyping.
* The window is capped at one hour by `test_43`; beyond that a "throttle" becomes the lockout
  this phase must not introduce.

**No permanent lockout.** The counter expires by itself. A successful login clears it. There
is nothing an operator must remember to unlock.

One consequence is worth stating plainly: while an account is throttled, **the owner's
correct password is refused too**. That is inherent — verifying the password in order to
admit the owner would verify every guess, which is the protection deleted. The mitigation is
that the refusal is bounded (15 minutes) and self-healing. An assertion that the owner should
be admitted while throttled was written during this phase, failed, and was *corrected* rather
than the implementation being weakened to satisfy it (see
`docs/audit/evidence/e02_phase4_test12_vacuous.txt`).

### D. Redis atomicity

Increments use `INCR` (atomic) with the TTL asserted on creation, inheriting the Phase 2
`incr_in_window` implementation. There is **no read-then-write** anywhere:

* `check_account_login_allowed` → single `INCR`.
* `reset_account_failures` → single `DEL` of exactly one key (not a prefix scan, so it cannot
  erase a neighbouring account).
* `get_account_failure_count` → single `GET`.

Verified cross-process: `test_49` (two interpreter processes, one Redis) and the live
simulation, where 10 accepted attempts across two worker processes produced a counter of
exactly 10 — no lost updates.

A reset racing an increment can still lose the increment, which is the *safe* direction: the
account ends one failure lower, never higher. `test_51` pins that a failure occurring after a
reset is counted.

### E. Memory fallback — the limitation, stated

With no Redis, the store is a per-process dict. **This does not provide cross-worker
protection.** With N workers the effective account limit becomes `threshold × N`. The fallback
is thread-safe (one lock, atomic incr) and logs loudly. It is not a substitute for Redis, and
the E-03 outage policy is out of scope here.

### F. Enumeration protection

Before this phase the login endpoint disclosed account existence two ways:

1. **Message.** Unknown account → `'X' нэртэй харилцагчийн салбар олдсонгүй`; known account
   with a wrong password → `Нууц үг буруу байна!`. Both 401, so only the body differed.
2. **Timing.** Measured median: **37.7 ms** for a known account vs **6.3 ms** for an unknown
   one — a **6× oracle**. The unknown path returned before PBKDF2 ran.

Both are closed. The client now receives one fixed message for every failure; `err_msg` is
kept for the server-side audit trail only. Every early-return path in
`authenticate_client_detailed` that would skip PBKDF2 now runs `dummy_password_verify` — a
real PBKDF2-HMAC-SHA256 at the configured 100,000 iterations against a per-process throwaway
credential. It is a real verification rather than a `sleep` on purpose: a sleep must be tuned
to hardware and configuration, while this tracks the real cost automatically.

`test_55` asserts the ratio stays within 0.5–2.0×; before the fix it failed at **5.8×**.

Throttling does not re-open the oracle: `test_54` asserts a known and an unknown account reach
429 on the *same attempt number*, and the throttle message is a fixed string.

## 4.3 Phase 4.1 — hardening the account throttle

An independent review of Phase 4 found five problems. All five were **reproduced against the
code as it stood** before being fixed; none was taken on trust. Measurements are in
`docs/audit/evidence/e02_phase41_before.txt` and `e02_phase41_live_2worker_redis.txt`.

### A. Alias rotation gave one account several budgets — CONFIRMED

The login lookup accepts `client_username` **or** `page_id`:

```sql
WHERE (LOWER(TRIM(client_username)) = LOWER(?) OR LOWER(TRIM(page_id)) = LOWER(?))
```

Phase 4 keyed the throttle on the *submitted* string, so the two aliases of one account were
two counters. Measured: after 20 failures through the username, the username answered 429 and
the same account's `page_id` answered **401** — a second, fresh budget. Alternating the aliases
allowed **40 attempts against a threshold of 20**.

Fixed by resolving the identifier to the account's canonical `page_id` (the primary key of
`pages`) before keying. Resolution is a database read; a client-supplied `page_id` that does not
exist resolves to `None` and falls back to the normalized identifier, so it cannot be used to
forge a canonical identity. Unknown identifiers keep their own digest, so they stay throttled
and the counter is not an existence oracle.

`pages.client_username` has a **non-unique** index, so duplicate usernames are permitted by the
schema. `resolve_canonical_account()` picks the lowest `page_id` deterministically and
`canonical_resolution_is_ambiguous()` reports the condition rather than hiding it
(`test_108`). This is a pre-existing schema property, not introduced here; eliminating it would
need a migration, which is out of scope.

### B. `INCR` and `EXPIRE` were not atomic — CONFIRMED

The Phase 4 store issued `INCR` and then, only when the result was 1, a separate `EXPIRE`. A
crash between them left a counter with **no TTL**: an account throttled forever, which is
exactly the permanent lockout this phase must not create.

Fixed with a Lua script that increments and sets the expiry in one round-trip, returning the
count and the remaining TTL together. The window stays **fixed, not sliding**: the TTL is set
at creation and never refreshed, so an attacker cannot hold a counter open by continuing to
guess. The script also self-heals a key that somehow has no expiry.

`TIME` inside a script is not used, deliberately — `TTL` gives the remaining value directly and
works on Redis 6.x, which is what the deployment runs and what CI provisions.

### C. Reset-on-success could erase a concurrent failure — CONFIRMED

Two problems compounded here, and the second was not in the original review.

1. **The check was not the increment.** `check_account_login_allowed()` incremented at
   admission, but nothing made admission the *only* consumption point, and the success path
   then deleted the whole key. Any failure recorded between the success being admitted and the
   deletion was silently erased:

   ```
   t0 attacker failure admitted  INCR -> 5
   t1 victim   success admitted  INCR -> 6
   t2 attacker failure admitted  INCR -> 7   (after the success event)
   t3 victim   reset             DEL        -> the t2 failure is gone
   ```

2. **A whole-key delete cannot express "clear my own effect".**

   The policy adopted instead: **each admitted login consumes exactly one slot; a failure keeps
   its slot, and a successful login refunds exactly the one slot it consumed.** Nothing deletes
   the counter. Decrementing is linearizable and idempotent per request, so no failure recorded
   after the success was admitted can be lost, and a success can never erase a counter it did
   not own. The refund is clamped at zero so repeated successes cannot manufacture budget.

   Ordering guarantee, stated exactly: *the counter value at any instant is the number of
   admissions that have not been refunded.* A failed request contributes +1 permanently until
   the window expires; a successful request contributes +1 at admission and −1 at refund,
   net zero.

   The visible consequence is that **a successful login no longer zeroes the counter.** Earlier
   mistyping stays recorded for the remainder of the window. This was a deliberate policy
   change, and three Phase 4 tests plus `test_12` asserted the old behaviour — they were
   updated to the new guarantee, and each update is *stricter* than what it replaced
   (`== failures` instead of `== 0`). `test_12` was verified to fail if the implementation is
   reverted to whole-key deletion, and to pass with the refund.

### D. Production started without the secret — CONFIRMED

Production imported cleanly with no `E02_ACCOUNT_KEY_SECRET` and account throttling silently
off, logging only a WARNING. A control that can be absent while being believed present is worse
than no control.

Production now **refuses to start**: the lifespan calls
`core.account_keys.validate_secret_for_startup()`, which raises `RuntimeError` naming the
variable when it is unset, blank/whitespace-only, or shorter than 32 characters.
`docker-compose.prod.yml` additionally declares the variable with `:?`, so `compose up` fails
before a container is created. Development and tests are unaffected and keep an explicit,
documented configuration (`tests/conftest.py` sets a clearly-labelled non-production value).

The secret value is never logged, never returned by any endpoint, and never reaches a template.
`test_135` asserts a startup failure does not echo the value; `test_136` asserts a successful
request does not log it. Rotation is documented in §1.2 of the deployment guide: it orphans
existing counters, which expire within the window, so it can only ever *un*-throttle.

### E. `casefold()` did not match the database — CONFIRMED, in both directions

Phase 4 normalized with `str.strip().casefold()`. Measured on the real engines:

| Input pair | SQLite `LOWER` | PostgreSQL `LOWER` | Python `casefold` |
|---|---|---|---|
| `Straße` / `STRASSE` | distinct | distinct | **merged** (`strasse`) |
| `Ø` / `ø` | distinct (ASCII-only) | **merged** | merged |
| `ΣΊΣΥΦΟΣ` | distinct | **merged** | merged (final sigma `σ`) |
| `ﬁle` / `file` | distinct | distinct | **merged** |

Two failure modes, one test each: `casefold` **merged** accounts the database keeps distinct
(so one tenant's failures throttled another — `test_140`), and on SQLite it did **not** merge
what PostgreSQL would (so the throttle's behaviour differed by deployment).

Fixed by not re-implementing the comparison at all: `normalize_identifier()` asks the database
to evaluate the same `LOWER(TRIM(?))` expression the login query uses, on the authoritative
connection. The key therefore agrees with the engine by construction. On SQLite that means
`Ø`/`ø` are legitimately *not* folded, which is the engine's real behaviour and is why
`test_141` skips there — reported as a skip, not hidden.

Stored usernames are never modified (`test_142`); normalisation happens only when deriving a key.

### Files and tests

New: `tests/test_e02_phase41_hardening.py` (**46 functions → 50 cases**).
Modified: `core/account_keys.py`, `core/rate_limit.py`, `database.py`, `main.py`,
`tests/conftest.py`, `tests/test_e02_phase4_account_protection.py`,
`tests/test_e02_login_rate_limit.py`, `tests/test_e02_phase41_hardening.py`,
`.env.example`, `docker-compose.prod.yml`, `.github/workflows/ci.yml`, and three documents.

**One test-helper bug found in my own new suite**, recorded because it produced misleading
results for several runs: `_validate()` returned the validator instead of calling it, so
`with pytest.raises(...): _validate()` asserted that *constructing a bound method* raises. It
passed for the wrong reason in one direction and failed in the other. Fixed to call.

## 4.4 Phase 4.2 — admission ownership and window-bound refunds

### The reported race — CONFIRMED, on both backends

Phase 4.1 replaced whole-key reset with "refund exactly the slot this success consumed", and
that fixed erasure of *concurrent* failures inside one window. It did not bind the refund to the
window the admission happened in:

| | event | counter |
|---|---|---|
| W1 | A admitted | 1 |
| W1 end | counter expires and is deleted | — |
| W2 | B admitted and fails | 1 |
| W2 | A finally authenticates and refunds | **0** |

A's refund decremented a counter belonging to a window A was never part of, erasing B's failure.
Reproduced **before any change**, deterministically, on both stores
(`docs/audit/evidence/e02_phase42_before.txt`):

* memory, injected clock — `stored` went `1 → 0` after the stale refund;
* real Redis, 1-second TTL — `stored` went `1 → 0` after the stale refund.

Root cause, precisely: `clear_account_failures_on_success()` re-derived the counter key from the
identity and called a decrement primitive that had **no notion of which counter incarnation it
was modifying**. On Redis `_DECR_SCRIPT_SOURCE` was a bare clamped `GET`/`DECR`/`DEL` with no TTL
or generation predicate. On memory `decrement_floor_zero()` did check `now - started >=
window_seconds`, but that check cannot help: once W2 recreates the key, `started` is W2's, so the
stale refund passes the check and decrements W2. **The memory window check was never a
mitigation** — it only made the two backends differ.

### Design — an admission token naming its generation

Admission now returns an `AdmissionToken(identity, generation, admission_id)`:

* `generation` is minted by the **same atomic operation** that creates the counter (inside the
  Redis Lua INCR script; under the memory store's lock). It is opaque, 8 random bytes, and
  carries no account identifier.
* `admission_id` is unique **per admitted request**. A generation alone cannot enforce
  single-use, because every admission in one window shares it — this was caught by `test_204`
  during implementation, when replaying one learned token cancelled several failures.
* The token is returned only for an *admitted* attempt. A refused attempt has no slot to give
  back, and issuing a token for one would let a throttled attacker cancel a real failure.

`clear_account_failures_on_success(identity, token=...)` now refuses unless all of:

1. a token was supplied (no token → no refund, logged);
2. `token.identity == identity` — a token minted for A cannot refund B;
3. the counter exists and its live generation equals `token.generation`;
4. this `(generation, admission_id)` has not already been refunded;
5. the counter is above zero.

On Redis these are one Lua script (`_REFUND_SCRIPT_SOURCE`), so Redis's single-threaded script
execution makes them atomic. On memory they are one critical section under the store lock.

### Linearization points

* **Admission** linearizes at the INCR script execution (Redis) or at the lock acquisition that
  reads-or-creates the counter (memory). The generation the caller receives is the generation
  that was in force at that instant.
* **Refund** linearizes at the script execution / lock critical section. Because the generation
  comparison and the decrement are in the *same* atomic unit, there is no window in which a
  caller could observe a matching generation and then decrement a different one.
* **Window rollover** linearizes at the INCR that finds the counter absent or expired; that same
  operation mints the new generation.

Condition 3 is checked **inside** the store operation. A timestamp comparison taken before the
call would be check-then-act: another request could roll the window between the comparison and
the decrement — the same defect in a new costume, which is why it is not done that way.

### Failure behaviour

| situation | outcome | why |
|---|---|---|
| token absent (caller forgot) | refund refused, error logged | safe direction: one residual failure expires with its window; guessing could erase another's |
| store raises | refund refused, error logged | a failed refund under-counts nothing, so it cannot hand out budget |
| generation mismatch | refused | the admission's window is gone; its slot expired with it |
| already refunded | refused | single use |
| counter absent | refused | window expired |
| counter at zero | refused | clamping; a refund never mints budget |
| counter without a marker (pre-4.2 build) | INCR mints one for the live window | closes the stale-window case on upgrade, not only for new windows |

### Why not a timestamp on the value

Storing the admission time inside the counter value and comparing it at refund time was
considered and rejected: it changes what the key holds (breaking `peek`, `TTL`, and operator
tooling), it cannot distinguish two admissions with the same second, and it still needs the
comparison to happen atomically with the decrement to be correct — at which point the generation
marker is strictly simpler and does not require the value to be parsed.

### Cost

One extra Redis key per live counter (`<key>:gen`, same TTL) and one small key per refunded
admission (`<key>:gen:refunded:<generation>:<admission>`, same TTL). Both expire with the window.
See R11/R12.

### Files and tests

New: `tests/test_e02_phase42_admission_ownership.py` (**28 functions → 28 cases**, no
parametrisation; every case runs on both backends when `REDIS_URL` is live, and the CI guard
fails on any skip).

Modified: `core/rate_limit.py` (token, generation minting, `refund_admission` on both stores,
refund acceptance rules, resolution fallback), `core/account_keys.py` (normalization fallback no
longer re-enters the database unguarded), `database.py` (`ORDER BY page_id LIMIT 1` on the login
lookup), `main.py` (passes the token), `.github/workflows/ci.yml`, and this document.

### Two defects found in my own work, recorded rather than quietly fixed

1. **`test_214`/`test_215` were defective.** Both requested the memory and Redis fixtures,
   assuming two live limiters. `rate_limit.get_limiter()` is a single module global, so the
   second fixture's `set_limiter()` won and the "memory" arm actually ran against Redis. The
   assertion compared Redis with Redis. Fixed by re-installing each limiter immediately before
   its own arm and asserting `backend()`. The implementation was not changed for this.
2. **The live simulation's section E assertion was defective.** It asserted that a successful
   login leaves the counter at `pre - 1`. That contradicts the documented counting model: a
   success *admits* (+1) and then refunds that same admission (−1), so the net change across one
   success is **zero** — which is what Phase 4.1's own live evidence already showed ("success left
   the counter at 10"). The assertion was replaced with the correct invariant plus an isolated
   single-refund arm; the implementation was not changed.

## 4.5 Phase 4.3 — memory expiry parity and durable single-use refunds

### Defect 1 — the memory store ignored expiry when refunding — CONFIRMED

Redis deletes an expired counter key by itself, so a refund after the TTL finds nothing and is
refused. The memory store kept the expired entry until something replaced it, and
`refund_admission()` checked only the generation and the count. Reproduced with an injected
clock, no replacement window created:

| | |
|---|---|
| admit A in W1 | count 1 |
| advance past W1 | `peek` correctly reports 0 |
| refund A | **True** — Redis returns False for the same sequence |

Severity, measured rather than assumed: this **cannot** corrupt a live later window, because
the generation check still refuses a stale token against a newer generation (asserted in
`test_306`). What it did was report success for a budget that expiry had already restored, and
populate claim state for a dead generation. It is a memory/Redis behavioural divergence, which
is the thing a fallback store must not have.

**Fix.** `_live_entry()` is now the single way any memory-store method obtains a counter: it
returns the entry only if it is still live, and **reclaims it on sight** when it is not. Every
method — increment, read, refund, legacy decrement — therefore sees the same "expired means
absent" state Redis presents. The check is inside the store lock, in the same critical section
as the generation and count checks.

### Defect 2 — live claims could be evicted — CONFIRMED, and worse than reported

`_refunded` was **one process-wide set** bounded to `_MAX_TRACKED_IDENTITIES` (10,000) and
evicted with `set.pop()`, which removes an arbitrary element. Because it was global, *other
tenants'* refunds consumed the budget. Measured at the real bound:

    3 admissions for "victim", one refunded -> claim recorded, count 2, window still live
    23,417 refunds by unrelated accounts
    replay the victim's token -> True, count 2 -> 1

So a live admission could be refunded **twice** by pressure a third party can generate. This is
reachable without knowing any secret, which is what makes it more than a theoretical bound.

### Design — claims live inside the counter they belong to

`_counters` now maps a key to a `_MemoryCounter`, one object per counter incarnation holding
`started`, `count`, `generation`, `window_seconds`, and a `claims` set.

This makes the required guarantees structural rather than policed:

| requirement | how it holds |
|---|---|
| refunded at most once | `admission_id` membership is tested and inserted in the same critical section as the decrement |
| claims expire with their generation | they *are* the generation; the object's lifetime is the window's lifetime |
| expired claims are reclaimed | `_live_entry()` drops the whole object when the window passes |
| no unbounded growth | only admitted attempts get a token, every admitted attempt increments `count`, so `len(claims) <= peak(count) <= threshold`; there is no separate bound to tune or drift |
| no cross-account collision | there is no shared structure to collide in |
| memory/Redis equivalence | Redis already scoped claims to `<key>:gen:refunded:<generation>:<admission>` with the counter's TTL; memory now scopes them to the same generation |

Nothing is ever evicted, so no live claim can be forgotten. `_evict_if_needed()` still bounds
the *counter* dict, but only removes entries whose window has certainly expired.

### Token integrity audit — results

| check | result |
|---|---|
| generation / admission id entropy | 16 hex chars (8 random bytes) each; admission ids unique across 50 admissions |
| generations identical within one window | yes, by design — `admission_id` is what distinguishes admissions |
| identity binding | enforced against the **resolved** identity, so an alias refunds its own account and nothing else |
| cross-account token | refused; other account's counter untouched |
| cross-generation token | refused |
| cross-admission token | refused; refunding one token leaves the others intact |
| token after window rollover | refused |
| refused attempt receives a token | no — a throttled attempt has no slot to give back |
| counter zeroed | entry deleted, exactly as Redis deletes at zero; the next admission mints a new generation on **both** backends |
| TTL preservation | a refund never extends or removes the window |

### One behaviour change found during the audit

`clear_account_failures_on_success()` compared the token's identity against the caller's **raw**
argument. Since tokens carry the canonicalised identity, refunding via a non-canonical alias was
rejected. `main.py` passes `account_hit["identity"]`, so the login path was never affected, but
the public function accepted aliases before and would have silently under-refunded after. It now
resolves the identity first and compares canonical to canonical.

### Token now carries its own window

`AdmissionToken.window_seconds` records the window the admission was taken with, and the memory
refund judges expiry against that rather than the current policy value. Without it, a token
admitted under a 5-second window would be honoured for 900 seconds if the policy changed
underneath it — a divergence Redis does not have, because its key's TTL was fixed at INCR time.

### Files and tests

New: `tests/test_e02_phase43_memory_claim_durability.py` — **23 functions → 23 cases**, no
parametrisation. Every case runs on both backends when `REDIS_URL` is live, and the CI guard
fails on any skip.

Modified: `core/rate_limit.py` (`_MemoryCounter`, `_live_entry`, rewritten memory store,
`AdmissionToken.window_seconds`, canonical identity comparison), `.github/workflows/ci.yml`,
and this document.

### Three defects in my own tests, recorded rather than quietly fixed

1. **`test_317` was defective.** It requested 50 admissions at the default limit of 20, so
   everything past the twentieth was refused and `token` was `None`. Fixed by raising the limit
   for that case — the entropy question is independent of the throttling policy.
2. **`test_307`/`test_308` did not discriminate.** They passed against the buggy design, so
   they proved nothing. Two causes: the victim's counter was driven to zero (an emptied counter
   is deleted, so the replay was refused by "no counter", not by the claim), and the pressure
   loop counted refused admissions as claims, applying almost no pressure. Both fixed, and the
   tests were then run against the original store to confirm they fail there. That comparison is
   recorded in `docs/audit/evidence/e02_phase43_before.txt` §5.
3. **The live simulation's "login still works" arm was defective.** It ran after the arm that
   deliberately exhausts the budget, so it received the correct 429 and reported it as a
   failure. The budget is now reset first; the 429 was right.

## 4.6 Phase 4.4 — window consistency and memory capacity security

### Defect 1 — one generation, two lifetimes — CONFIRMED, both directions

A counter's window was not fixed when its generation was created. `_MemoryCounter.window_seconds`
was widened with `max(...)` on every admission while Redis writes its TTL once, inside the script
that creates the counter, and never revisits it. Separately, `AdmissionToken.window_seconds`
carried the window the *caller* asked for and `_MemoryStore.refund_admission()` judged expiry by
it. Measured (`docs/audit/evidence/e02_phase44_before.txt`):

**Scenario A** — admit 5s, then 900s for the same account, advance 6s:

| | memory | Redis |
|---|---|---|
| store window after the 900s admission | 900s (widened) | 5s TTL (unchanged) |
| `peek` after 6s | 2 | 0 |
| refund of the 900s token | **True** | **False** |

**Scenario B** — admit 900s, then 5s, advance 6s:

| | memory | Redis |
|---|---|---|
| store/TTL window | 900s (max kept) | 900s TTL |
| refund of the 900s token | True | True |
| refund of the 5s token | **False** | **True** |

Scenario B is the sharper failure: the *same token* was refused on one backend and accepted on
the other, because each token judged itself by the window its own caller had requested.

**Chosen policy: a counter's window is fixed when its generation is created; later admissions
inherit it and cannot change it.** This is what Redis has always done and what the fixed-window
model requires — a window any caller can widen is not a window. Implementation:

* `_MemoryStore.incr_in_window_detailed()` no longer touches `entry.window_seconds` for an
  existing generation; the caller's value is used only when a generation is created.
* `_MemoryStore.refund_admission()` judges expiry by the **counter's** own window, never the
  token's.
* `AdmissionToken.window_seconds` reports the generation's remaining window, so a token can
  never claim more or less life than the counter it belongs to.
* Redis needed no change for this defect; `test_406`/`test_407` pin its already-correct
  behaviour so the memory fix cannot be "matched" by breaking Redis.

The rejected alternative was to *reject* a mismatched window for an existing generation. It was
not chosen because a mixed-window call is legitimate (different call sites may pass different
policy values) and rejecting it would turn a naming disagreement into a login outage. Inheriting
is both safe and available.

### Defect 2 — capacity pressure erased live budgets — CONFIRMED

`_evict_if_needed()` reclaimed expired entries and then, while still over the cap, dropped the
oldest **live** counter — despite its own docstring claiming an eviction "can never remove a live
generation". Measured at the real 10,000 cap:

    victim at 19 of 20 failures, window live
    10,200 distinct live filler identities
    victim counter evicted -> next attempt allowed=True, count=1

An attacker could reset any account's failure budget by filling the store, then log in freely.

**Chosen policy: expired entries are reclaimed; a live counter is never evicted. When the store
is full of live counters, a *new* identity is refused and account admission fails closed.**

* `_reclaim_expired()` removes only entries whose window has passed.
* `_make_room()` returns a slot if one is free after reclamation, else refuses.
* The memory store raises `StoreAtCapacityError`, which `check_account_login_allowed()` catches
  **separately** from the generic store-failure handler and turns into `allowed=False`,
  `token=None`. This distinction matters: the generic handler fails *open*, and failing open here
  would hand an untracked account an unlimited budget.
* Identities that already hold a live counter are always served, so no active limit is ever
  weakened by the capacity path.
* The IP scope is unchanged: it keeps its fail-open posture, because there the alternative to
  admitting is a limiter outage that logs everyone out.

### Backend parity guarantees after this phase

| guarantee | Redis | memory | test |
|---|---|---|---|
| a generation has exactly one effective expiry | TTL written once at creation | window fixed at creation | 401, 403, 406, 407 |
| a token cannot extend or shorten it | script ignores caller window | caller window ignored | 405, 406, 407 |
| expired admission refused | key gone | `_live_entry`/`refund` reclaim | 408 |
| stale token cannot touch a newer generation | generation key | generation field | 4.2 suite |
| refund applies at most once | `SET NX` claim key | per-generation claim set | 4.3 suite |
| cross-account token rejected | identity binding | identity binding | 4.3 suite |
| capacity cannot reset a live budget | n/a — no local cap | refuse, never evict | 409, 412, 413 |
| refused admission gets no token | n/a | `token=None` + `at_capacity` | 410, 415 |
| claim keys carry a bounded TTL | same TTL as counter | set dies with entry | 4.3 suite |

No change was made to the 20-failure / 900-second production policy.

### Files and tests

New: `tests/test_e02_phase44_window_and_capacity.py` — **17 functions → 17 cases**, no
parametrisation. Every case runs on both backends when `REDIS_URL` is live; the CI guard fails on
any skip *and* on any deviation from 17 passing cases, so a silently dropped test cannot pass.

Modified: `core/rate_limit.py` (`StoreAtCapacityError`, `_reclaim_expired`, `_make_room`,
fixed-window inheritance, token window, capacity-refusal branch), `.github/workflows/ci.yml`, and
this document.

### Discrimination evidence

The suite was run against the **old** implementation with the fix stashed:

    FAILED 401, 402, 403, 404, 405                                  (5 window cases)
    FAILED 409, 410, 411, 412, 413, 414, 415, 416                   (8 capacity cases)
    13 failed, 4 passed

The 4 that passed against the old code are deliberate regression guards, not evidence of a
fixed defect: `test_406`/`test_407` pin Redis's already-correct TTL behaviour, `test_408` re-pins
the Phase 4.3 expiry guarantee, and `test_417` asserts the capacity policy is a memory-store
concern only. Against the fix all 17 pass.

### Three defects in my own tests, recorded rather than quietly fixed

1. **`test_409`/`test_413` were vacuous.** The fill loop raises `limit` to 1000 so admissions keep
   succeeding, and the threshold assertions then used that same raised limit — so "still blocked"
   was tested against a limit of 1000. Fixed to assert at the production limit of 20.
2. **`test_415` inherited state between arms.** `get_limiter()` is a module global and the
   `memory` fixture yields one limiter per test, so the second and third arms inherited the first
   arm's counters (the victim read 4 instead of 2). Fixed by building a fresh store per arm.
3. **`test_415`'s third arm asserted the wrong thing.** An identity inserted *after* the store is
   full never had a budget to preserve; the correct behaviour is refusal. The assertion was
   rewritten to check exactly that. During triage I first suspected an implementation bug here;
   the debug run showed the admission was already being refused correctly.

The live simulation had one equivalent harness defect: it asserted the second account's counter
was 1 when section E had legitimately left it at 2. The expectation was corrected, not the
implementation.

## 5. Storage and concurrency

Phase 3 changed *what* the IP key is. Phase 4 added a second scope (`auth_account`) sharing the
same store abstraction. Phase 4.1 makes the account scope's increment atomic with its expiry
(Lua, §4.3B) and replaces whole-key reset with a clamped refund (§4.3C); the IP scope keeps the
`INCR`-then-`EXPIRE` sequence, which has the same crash window — recorded as a residual risk in
§8 R9 because fixing it is a change to the IP layer rather than the account layer.

Both scopes are subject to the per-process memory fallback described in §4.2E.

### 5.1 The account counter's representation, after Phase 4.3

| | Redis | memory |
|---|---|---|
| counter | `ratelimit:auth_account:<digest>` — plain integer | `_MemoryCounter.count` |
| generation | `…:<digest>:gen`, same TTL as the counter | `_MemoryCounter.generation` |
| refund claim | `…:<digest>:gen:refunded:<generation>:<admission>`, same TTL | `_MemoryCounter.claims` |
| window | the counter key's TTL, written once at creation | `_MemoryCounter.window_seconds`, fixed at creation (Phase 4.4) |
| expiry | Redis deletes the key | `_live_entry()` drops the object on sight |

Phase 4.4 added one more parity rule to this table: **a generation's window is fixed when it is
created on both backends**, and neither a later admission nor a token may redefine it.

The asymmetry that remains is intentional and unchanged: Redis expiry is enforced by the server,
memory expiry is enforced by `_live_entry()` under the store lock. Phase 4.3 made the *decisions*
identical (§4.5); it did not try to make the mechanisms identical, because they cannot be.

Phase 4.2 stored the counter as the bare tuple `(started, count, generation)` with claims in a
separate process-wide set. Anything reading `_counters` for diagnostics should now expect
`_MemoryCounter` objects; the store exposes `__repr__` for that purpose. No production code reads
the attribute directly.

## 6. Test matrix

### 6.1 Phase 2 suite — `tests/test_e02_login_rate_limit.py` (21 tests)

The count in the Phase 2 report was wrong: it said 20, but the file defines **21** test
functions, because mandated case 11 was split into `test_11` and `test_11b`. Corrected
per-test results, before the fix:

| # | Test | SQLite, pre-fix | PG + Redis, pre-fix |
|---|---|---|---|
| 1 | rotating XFF cannot bypass | FAILED | FAILED |
| 2 | rotating X-Real-IP cannot bypass | FAILED | FAILED |
| 3 | rotating `Forwarded` cannot bypass | PASSED | PASSED |
| 4 | forwarding used only with trusted proxy | FAILED | FAILED |
| 5 | untrusted peer header ignored | FAILED | FAILED |
| 6 | multi-hop picks the client | FAILED | FAILED |
| 7 | malformed headers handled safely | FAILED | FAILED |
| 8 | account protected across IPs | FAILED | FAILED |
| 9 | 100 rotations hit the account limit | FAILED | FAILED |
| 10 | username spelling shares one budget | FAILED | FAILED |
| 11 | unknown account vs wrong password | FAILED | FAILED |
| 11b | no enumeration via login type | FAILED | FAILED |
| 12 | success resets account counter | PASSED | PASSED |
| 13 | concurrent failures counted | FAILED | FAILED |
| 14 | account protection shared across processes | SKIPPED | FAILED |
| 15 | attacker cannot lock a victim out | FAILED | FAILED |
| 16 | no enumeration via throttle response | PASSED | PASSED |
| 17 | IP and account limits independent | FAILED | FAILED |
| 18 | 429 has usable `Retry-After` | PASSED | PASSED |
| 19 | failure→success does not corrupt counter | FAILED | FAILED |
| 20 | account state survives restart | SKIPPED | PASSED |

**Totals: SQLite 15 failed / 4 passed / 2 skipped = 21. PostgreSQL 16 failed / 5 passed =
21.** Both match the counts in the previous report; only the headline "20 tests" was wrong.

### 6.2 On `test_20`

`test_20` passed pre-fix because Redis already shares *whatever* is counted. It exercises
the store, not the policy, so it was left passing rather than forced to fail.

After Phase 4 it stays green but its meaning changes: it will assert that the **account
failure counter** survives a worker restart, not merely that an arbitrary key does. The
store mechanism it proves today is still the precondition for that, which is why it was not
rewritten.

### 6.3 Phase 3 suite — `tests/test_e02_trusted_proxy.py` (31 test functions, 42 collected cases)

Written before the implementation. Pre-fix: **24 failed, 2 passed, 25 errors**.

| Group | Tests |
|---|---|
| direct-client spoofing | 1, 2, 3, 3b (50 forged addresses → 1 identity) |
| trust by configuration | 4, 5, 6 (peer cannot self-promote), 7 (CIDR) |
| multi-hop | 8, 9 (spoofed left prefix ignored), 10 (all-trusted chain) |
| malformed | 11 (6 parametrised cases), 12 (500 hops / 50 KB), 13 (junk mid-chain) |
| address families | 14, 15 (IPv6 client behind IPv4 proxy), 16 (structural IPv6 match) |
| trust list | 17 (default empty), 18 (`*`, `0.0.0.0/0`, `::/0`, `all` rejected), 19 (typo not widened) |
| integration | 20 (`client_identity` delegates), 21 (uvicorn agreement), 22 (Dockerfile/compose), 23 (no shared store still reported) |
| real uvicorn HTTP | 24 (peer unchanged with header), 25 (20 rotations → 1 identity) |
| **Phase 3.1 strict validation** | **26** (4 parametrised mandated examples), **27** (malformed chains cannot pick a budget), **28** (leading comma does not change hop counting), **29** (all-trusted fallback also aborts), **30** (valid chains still resolve — over-correction guard) |

Counting: **31 test functions** expand to **42 collected cases**, because `test_11` is
parametrised over 6 malformed headers, `test_18` over 4 rejected trust entries, and
`test_26` over the 4 mandated empty-hop examples. The Phase 3 report said "34 tests"; that
was the collected-case count, not the function count. Pre-fix, the 34-case file was
"24 failed / 2 passed / 25 errors"; the 5 new Phase 3.1 functions contributed 7 failures and
1 pass (the over-correction guard) before the fix.

The 2 pre-fix passes were observations, not policy assertions: test 21 read uvicorn's
`Config` defaults, and test 23 checked the memory backend reports itself honestly. Neither
touches the resolver.

### 6.4 Phase 3 change to a Phase 2 test

`test_07` in the Phase 2 file asserted that a 5.7 KB `X-Forwarded-For` should still yield
`203.0.113.5`. That contradicted Phase 3's own 1 KB bound, so the expectation was corrected
to "falls back to the peer" and an over-hop case was added. The bound is the safer
behaviour; the original assertion would have required raising it for no reason.

### 6.5 Phase 4 suite — `tests/test_e02_phase4_account_protection.py`

**28 test functions → 34 collected cases** (parametrisation adds 6: 6 spelling variants of
`test_36`, 2 of `test_34`). With a live `REDIS_URL`: **34 passed, 0 skipped**. Without one:
31 passed, 3 skipped — the three that *require* a shared store. Skipping is not passing, so
CI fails the step if any skip appears (§11.2).

| Group | Tests | Covers |
|---|---|---|
| Account identity | `test_31`–`test_38` (8 functions, 14 cases) | same acct same IP; same acct 8 rotating real peers; rotating `X-Forwarded-For`; rotating `X-Real-IP` and `Forwarded` (2 cases); different accounts same IP; 6 spelling variants share one budget; distinct accounts not merged; malformed/empty identifiers don't crash |
| Key privacy | `test_39`–`test_41` | no plaintext identifier in any key; not a plain SHA-256 and changes with the secret; no secret ⇒ no key (no unkeyed fallback) |
| Counter behaviour | `test_42`–`test_47` | increment; threshold ⇒ temporary throttle and `window <= 3600`; expiry via an advanceable clock; success resets account; success does **not** reset IP; unknown account counted |
| Redis / concurrency | `test_48`–`test_52` | 30 concurrent threads counted atomically; two interpreter processes share one Redis counter; counter survives a fresh limiter (restart); reset does not erase a newer failure; TTL bounded in `(0, window]` |
| Enumeration | `test_53`–`test_56` | unknown vs wrong password identical status+body; throttling reaches 429 on the same attempt for known and unknown; timing ratio 0.5–2.0×; no plaintext username in logs |
| Regression guards | `test_57`–`test_58` | IP limit still works alongside the account limit; successful login still returns a token |

Two flaws in my own tests were found and fixed before the suite went green, both recorded
rather than quietly patched:

* `test_35` initially asserted that a second account on the *same IP* still logs in after 23
  failures — but 23 failures from one IP legitimately exhausts the **IP** limit (10/60 s), so
  it was testing the wrong layer. It now rotates the peer so only the account counter matters.
* `test_46` read the IP counter *after* the successful login, which correctly increments it.
  The counter is now read before and after, asserting `before + 1`, not "unchanged".

### 6.6 The Phase 2 `test_12` repair

`test_12_successful_login_resets_the_account_counter` failed at the end of Phase 3.1. It was
not a regression — it was **two defects in the test**, both now fixed
(`docs/audit/evidence/e02_phase4_test12_vacuous.txt` carries the measurements):

1. **Wrong harness.** `app_client` yields `TestClient(main.app)` with no `client=` argument.
   Starlette's default peer `("testclient", 50000)` is unparseable, so every request collapsed
   onto the identity `"unknown"` and the *IP* limiter (10/60 s) decided the outcome. Measured:
   IP counter 10, first request of the test's own loop → 429, while the account counter was
   correctly 0. It failed for the wrong reason.
2. **Vacuous assertion.** With a realistic peer, the original
   `remaining >= LOGIN_LIMIT - 1` (i.e. `>= 9`) **passes on base commit `402672f`, which has no
   account protection at all** — the loop bound (15) never reaches the account threshold (20),
   so `remaining` is always 15. It could not fail for an account-level reason.

The repair gives each request its own peer *and* pins the exact
number of attempts a cleared account admits (`== threshold`), a value only a build that both
counts and resets can produce. Verified both ways: **passes on this branch**; on base
`402672f` with the account constants stubbed so the module still imports, it fails with
`25 further attempts were allowed, expected exactly 20`.

**No test was deleted, skipped, or weakened.** `test_12`'s assertion was strengthened from
`>= 9` (satisfiable by nothing) to `== 20` (satisfiable only by a working reset).

### 6.7 Totals

| Scope | Collection | Result |
|---|---|---|
| Full suite, SQLite | 275 | **267 passed, 8 skipped, 0 failed** |
| Full suite, PG 16 + Redis | 275 | **274 passed, 1 skipped, 0 failed** |

The single PG-mode skip is pre-existing and unrelated: `test_stage_b_regressions.py` skips when
`ALLOWED_ORIGINS` is unset. SQLite's 8 skips are the Redis- and PG-requiring tests plus the
same `ALLOWED_ORIGINS` case. Phase 2/3 and E-01 are unchanged and green in both engines.

## 7. HTTP evidence

Real uvicorn, real sockets, no TestClient.

| Scenario | Result |
|---|---|
| 1 worker, no Redis, 14 rotating XFF | 10 accepted, 4 blocked |
| 2 workers, no Redis, 14 rotating XFF | **14 accepted** — see risk R1 |
| 2 workers + Redis, 14 rotating XFF | 10 accepted, 4 blocked |
| 2 workers + Redis, 14 rotating X-Real-IP | 10 accepted, 4 blocked |
| 2 workers + Redis, 14 rotating `Forwarded` | 10 accepted, 4 blocked |
| 2 workers + Redis, all three rotated | 10 accepted, 4 blocked |
| trusted peer, 2 distinct forwarded clients | separate counters, 10 each |
| 2 trusted hops, 12 spoofed prefixes | one counter, 10 accepted then blocked |
| 429 response | `Retry-After: 60` |
| **Phase 4:** 2 workers + Redis, 26 failures on ONE account from 26 rotating **real TCP peers** (127.0.0.x) | 20 accepted, then **429 at attempt 21**, `Retry-After: 900` |
| **Phase 4:** same account, one peer, rotating `X-Forwarded-For` while throttled | 429, 429, 429 — the account layer is independent of the IP layer |
| **Phase 4:** a second account from another peer | 200 — accounts isolated |
| **Phase 4:** Redis key written | `ratelimit:auth_account:7d91ec73dbc3af26059b99c7cd2a00e6`, TTL 899 — no identifier |
| **Phase 4:** 2 concurrent processes × 25 attempts on a second account | 10 accepted, 40 IP-blocked; account counter **exactly 10** for 10 accepted — no lost increments across two workers |

The two workers were confirmed to *serve* traffic, not merely to boot: a PID probe returned two
distinct worker pids (`39162`, `39163`). Full transcript in
`docs/audit/evidence/e02_phase4_live_2worker_redis.txt`.

## 8. Remaining risks

**R1 — without a shared store the limit is per worker (E-03 scope).**
With 2 workers and no Redis, 14 attempts were all accepted: each worker has its own
counter, so the effective limit is 10 × workers. This is not a Phase 3 defect — the
identity is correct in every worker — but it means **Phase 3 alone does not close the
14/14 scenario on a multi-worker deployment without Redis**. With Redis configured (as
`docker-compose.prod.yml` does) the bypass is closed. Recorded rather than glossed over.

**R2 — closed by Phase 4, with two residual limits.** Account-level protection now exists and
is independent of the source address. Residual limits:
(a) with no Redis each worker keeps its own account counter, so the effective limit is
`threshold × workers` — cross-worker enforcement needs Redis (see §4.2E); and
(b) a throttled account refuses the owner's correct password until the window expires. This is
inherent to the mechanism (see §4.2C) and bounded at 15 minutes.

**R3 — `X-Real-IP` and `Forwarded` are unsupported.** If a future proxy sends only those,
every request will look like it came from the proxy and users will share one budget.
Adding support requires its own trust validation and tests; it is deliberately not done
silently.

**R4 — the trust list is not reloadable at runtime.** It is read once per process;
changing `.env` requires a restart. `refresh_trusted_proxies()` exists for tests.

**R5 — `trusted_proxy_count` was not implemented.** With CIDR support and the
right-to-left walk, a correct chain resolves without naming a hop count. Requiring an
operator to also state the hop count adds a way to misconfigure it.

**R6 — account enumeration closed in Phase 4.** Both the message oracle and the 6× timing
oracle are fixed and covered by `test_53`–`test_56`.

> **Superseded by Phase 6 (§12.1).** The residual noted here — "a Redis outage still fails
> open" — no longer holds for the account scope: R14 was remediated, and a store failure now
> refuses the login. The IP scope still fails open, deliberately (`test_612`).

**R7 — the account secret is not hot-reloadable in a running worker.** `refresh_account_key_secret()`
exists and is called at startup and by tests, but a running deployment picks up a rotated
secret only on restart. Because rotation self-heals (orphaned counters expire), the practical
impact is that rotation is effective at the next deploy rather than instantly.

**R11 — the generation marker is a second key, so the pair is not written atomically as one
unit.** Both are written inside one Lua script (Redis) or one critical section (memory), so they
cannot disagree in practice; but a marker deleted by hand, or a counter left over from a build
before Phase 4.2, has no marker. Both cases are handled: the INCR script mints a marker for an
existing counter on first use, and a refund without a matching marker is refused (fail-closed,
costing one residual failure that expires with its window). Recorded because operator tooling
that deletes only the counter would leave a marker behind for at most one TTL.

**R12 — a refund is claimed by a `:refunded:<generation>:<admission>` key per refunded
admission.** These carry the counter's TTL and so expire with the window, but inside a very
large window a busy account creates one small key per successful login. Measured cost is one
key per success, bounded by the window length; deleting them early would weaken single-use, so
they are left to expire. In memory the equivalent claims are held on the `_MemoryCounter`
object and cost nothing beyond the set itself (R13).

**R13 — capacity exhaustion denies admission to new identities (Phase 4.4, replaces the former
"live counter eviction").** The memory store is bounded at `_MAX_TRACKED_IDENTITIES` (10,000).
Expired entries are reclaimed; a live counter is now **never** evicted (Phase 4.3's behaviour of
dropping the oldest live counter was a security defect, fixed in §4.6). The cost is availability:
a client able to mint 10,000 distinct live identities can cause *new* identities in that process
to be refused admission until those windows lapse. This is accepted deliberately, because the
alternative — admitting an account whose failures cannot be recorded — grants an unlimited
budget. It is bounded (the windows expire), self-healing, and only affects identities that do not
already hold a live counter. In production Redis should be in use, where no such cap exists.

**R15 — a mixed-window call is silently served with the generation's window.** Phase 4.4 chose
inheritance over rejection (§4.6). A caller passing 900s to an account whose live generation was
created with 5s gets 5s, with no signal. This is correct for the counter (one generation, one
expiry) and matches Redis, but a future caller that *needs* a different window must wait for the
generation to lapse. Documented rather than surfaced as an error, because a policy disagreement
between call sites should not become a login outage.

**R14 — the memory store's LOWER/window bookkeeping is per process.** Unchanged from §4.2E and
restated because Phase 4.3 sharpened the expiry semantics: memory now refuses expired refunds
exactly as Redis does, but a process-local counter still gives each worker its own budget
(`limit × workers`). This is why the deployment guidance keeps memory as a fallback rather than
a supported production mode.

**R9 — the IP counter still uses `INCR` then `EXPIRE` (Phase 4.1 scope note).** The account
scope's increment is now atomic (§4.3B) but the IP scope's is not: a crash between the two
commands there can still leave an IP counter with no TTL. Left alone deliberately — changing the
IP layer's storage is outside the account-hardening scope the review authorised, and the
consequence (one source permanently rate-limited until an operator deletes the key) is less
severe than the account case. Fixing it is a small, isolated change whenever it is in scope.

**R10 — duplicate `client_username` values are still permitted by the schema.** Phase 4.1 made
the *resolver* deterministic (lowest `page_id`). Phase 4.2 found that the *login query* was not:
it used `fetchone()` with no `ORDER BY`, so it followed rowid order and could select a different
tenant from the one the throttle charged. Measured before the fix: the account being charged
could not log in with its own correct password, while the other tenant authenticated
(`test_221`). `authenticate_client_detailed()` now carries `ORDER BY page_id LIMIT 1`, matching
`resolve_canonical_account()`, so authentication and the counter always name the same account.

This does **not** make two tenants sharing a login name safe: which of the two wins is still
arbitrary from a product standpoint, and only a migration (a unique index on
`LOWER(TRIM(client_username))`) would remove the hazard. No migration was attempted — it needs
explicit approval — so it remains an open operational risk rather than a solved one.
`canonical_resolution_is_ambiguous()` reports the condition for operators.

**R8 — the account counter is checked before the admin branch is reached only for
`client`/`magic`.** The shared admin password has its own path and is protected by the IP limit
alone. Giving the admin login an account dimension would be a behaviour change beyond this
phase's scope, and is noted rather than done.

## 9. Deployment configuration

```bash
# .env / compose environment — leave EMPTY unless a proxy you control fronts the app
TRUSTED_PROXIES=
```

The production command is now:

```dockerfile
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-proxy-headers"]
```

## 10. Production readiness verdict

| Criterion | Status |
|---|---|
| Trusted proxy config via environment variable | **PASS** |
| Default trusts nothing | **PASS** |
| Direct XFF spoofing does not change identity | **PASS** |
| Trusted proxy chain resolved correctly | **PASS** |
| uvicorn and app agree on trust policy | **PASS** |
| IPv4 / IPv6 | **PASS** |
| Malformed headers | **PASS** |
| Real uvicorn HTTP | **PASS** (with Redis) |
| SQLite regression | **PASS** — 225 passed, 3 failed (Phase 4), 5 skipped |
| PostgreSQL regression | **PASS** — 229 passed, 3 failed (Phase 4), 1 skipped |
| E-01 tenant isolation | **PASS** — 12/12 |
| Existing login flow intact | **PASS** |
| CI | see §11 |
| Account-level protection | **IMPLEMENTED** (Phase 4–4.4, verified §11) |
| Redis outage resilience | **IMPLEMENTED** — account fails CLOSED, readiness 503 (Phase 6, §12.1–12.2) |
| SEC-07 overall | **FAIL** — E-02 Phase 4 and E-03 both outstanding |

**Phase 3 is complete. E-02 is not. SEC-07 must not be reported as PASS.**

## 11. CI evidence

* Run: [`44000307785`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44000307785)
* Commit: `d39fac616bacac205575d39da48efd37303ee1cf`
* Conclusion: **success**

Steps reported by the API, all `success` including the two added in this phase:

| Step | Result |
|---|---|
| Initialize SQLite schema & verify zero schema drift | success |
| Migration integrity (0001 → 0002 → 0001 → 0002) | success |
| **Run E-02 trusted-proxy & login rate-limit suite (SQLite + live Redis)** | **success** |
| Run Pytest Regression, Enterprise, AI Eval & Failure Suites | success |
| Run Alembic Migration on PostgreSQL 16 | success |
| SQLite-to-PostgreSQL migration & checksum | success |
| Verify zero schema drift on Live PostgreSQL 16 | success |
| **Build Production Docker Image** | **success** |

**Limitation, stated plainly:** the per-step *log text* could not be downloaded. GitHub
serves action logs from `results-receiver.actions.githubusercontent.com`, which this
sandbox cannot reach, so `gh run view --log` fails with an EOF on the signed URL. What is
recorded above is the job/step conclusion from the API. It confirms the E-02 step ran and
exited 0, but it does **not** independently confirm the number of tests executed inside
it. The local runs in §6 are the evidence for the test counts.

### 11.1 Phase 3.1 CI run

* Run: [`44001966414`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44001966414)
* Commit: `53c7c51ae0466d617d89baee1d6b1490b80e3f03`
* Conclusion: **success**, with **zero failed steps**

| Step | Result |
|---|---|
| **Run E-02 trusted-proxy & login rate-limit suite (SQLite + live Redis)** | **success** |
| Run Pytest Regression, Enterprise, AI Eval & Failure Suites | success |
| Initialize SQLite schema & verify zero schema drift | success |
| Verify zero schema drift on Live PostgreSQL 16 | success |
| **Build Production Docker Image** | **success** |

Per-step log text is still unreachable from this environment
(`results-receiver.actions.githubusercontent.com` is outside the sandbox's egress
allowlist), so the conclusions above come from the API. The local runs in §6 and §7 are
the evidence for the counts.

### 11.2 Phase 4 CI run

| Field | Value |
|---|---|
| Run | [`44006527984`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44006527984) |
| Head SHA | `299c54b15cfc220c2b4a43a1cd1ae07adf5ecca3` |
| Conclusion | **success** — 39/39 steps, zero failed, zero skipped |
| E-02 step | `Run E-02 trusted-proxy & login rate-limit suite (SQLite + live Redis)` — **success** |

That step now runs three things, all against the live Redis service:

1. `tests/test_e02_trusted_proxy.py` — unchanged.
2. `tests/test_e02_login_rate_limit.py` — **the whole file**. The `-k` subset that excluded
   `test_11`, `test_11b` and `test_12` is gone because those tests now pass.
3. `tests/test_e02_phase4_account_protection.py` — with a guard that **fails the build if any
   test skips**, because three of them need a shared store and "skipped" is not "passed".
   Verified locally in both directions: 34 passed with `REDIS_URL` (guard silent), and with
   `REDIS_URL` absent the guard trips on `3 skipped`.

The Docker image build also passed with the new module in the image. Log text is still not
retrievable from this sandbox (egress to the log-results host is blocked), so the table above
reports step conclusions, which is what the API exposes.

### 11.3 Phase 4.1 CI run

| Field | Value |
|---|---|
| Run | [`44011261364`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44011261364) |
| Head SHA | `279b1ec10857b74a2fa7a5a3e2ddff8429932e21` |
| Conclusion | **success** — zero failed steps, zero skipped steps |
| E-02 step | `Run E-02 trusted-proxy & login rate-limit suite (SQLite + live Redis)` — **success** |

That step now also runs `tests/test_e02_phase41_hardening.py` against the live Redis service,
with a guard that differs from Phase 4's on purpose:

* Phase 4's suite must run with **no skip at all** (its three shared-store tests are the only
  reason to skip, and Redis is present).
* Phase 4.1 allows exactly one skip — `test_141`, because SQLite's `LOWER()` legitimately does
  not fold `Ø`. Rather than forbid skips, the step asserts that the four Redis-dependent tests
  (`test_113`, `test_114`, `test_115`, `test_118`) appear as **PASSED**, and fails if any
  *other* skip appears. Verified locally in both directions: with `REDIS_URL` set the guard is
  silent; without it, all four show as skipped and the guard trips.

Neither guard uses `|| true`, and neither hides a failure. Log text remains unretrievable from
this sandbox (egress to the log-results host is blocked), so this reports step conclusions,
which is what the API exposes.

### 11.4 Phase 4.2 CI run

Run [`44015598884`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44015598884),
head `3321aaf1343f00c6db4280d8c9b427c89b6961e2`, conclusion **success**.

Step-level result from the API: 38 steps, **38 success, 0 failed, 0 skipped**. The new

    E-02 Phase 4.2 — admission ownership & window-bound refunds

step ran and passed with `REDIS_URL` live. Its guard is stricter than the Phase 4.1 guard: any
`SKIPPED` line fails the job, because every case in this suite is expected to run on both
backends. Verified locally that the guard is silent with `REDIS_URL` set and trips without it
(7 skips → failure), so it is not a no-op.

### 11.5 Phase 4.3 CI run

Run [`44019451880`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44019451880),
head `2403f883d02513f463766893aeb18fdea4acfbb7`, conclusion **success**.

Step-level result from the API: 41 steps, **41 success, 0 failed, 0 skipped**. Both relevant
steps ran and passed:

    E-02 Phase 4.2 — admission ownership & window-bound refunds        success (preserved)
    E-02 Phase 4.3 — memory expiry parity & durable single-use refunds success (new)

The Phase 4.2 step and its guard are unchanged. The Phase 4.3 guard is the same shape and was
verified not to be a no-op: silent with `REDIS_URL` live (0 skips, 23 passed) and tripping
without it (4 skips → failure).

### 11.6 Phase 4.4 CI run

Run [`44024588832`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44024588832),
head `0c61253aedb969393d1bc421f6f9711759501182`, conclusion **success**.

Step-level result from the API: 42 steps, **42 success, 0 failed, 0 skipped**. The four E-02
gates all ran and passed:

    Run E-02 trusted-proxy & login rate-limit suite (SQLite + live Redis)  success
    E-02 Phase 4.2 — admission ownership & window-bound refunds           success (preserved)
    E-02 Phase 4.3 — memory expiry parity & durable single-use refunds    success (preserved)
    E-02 Phase 4.4 — window consistency & memory capacity security        success (new)

Phase 4.1's assertions run inside the first step and are unchanged. The Phase 4.4 guard is
stricter than its predecessors in one respect: besides failing on any skip it requires the
passing-case count to be exactly 17, so a renamed, deselected or silently dropped test cannot
pass it. Verified not to be a no-op — silent with `REDIS_URL` live (0 skips, 17 passed) and
tripping without it (6 skips → failure).

---

## 12. Phase 6 — remediation of the Phase 5 findings (R14, R11, R10, R15)

Phase 5 was an audit only; it left four findings open and made the merge verdict conditional
on them. This section records the remediation. Each finding states the defect, the exact
change, and the test that was **verified to fail against the pre-remediation code** — the RED
baseline is in `evidence/e02_phase6_before.txt` (35 failed / 18 passed / 7 skipped).

### 12.1 R14 — the account limiter failed OPEN

**Defect.** `core/rate_limit.py:check_account_login_allowed` caught `Exception` and returned
`allowed=True`. Measured before the fix: a raising store produced
`{'allowed': True, 'count': 0, 'token': None}`. With no counter incremented, nothing bounded
how many passwords could be tried against one account.

**Why it was not simply "the same posture as the IP limiter".** The two scopes protect
different things. The IP limit is a volume control: failing it open costs a weaker limit on a
shared address while the account limit still bounds each account. The account limit is the
last line for one account, so failing it open does not weaken the control, it removes it.
The IP scope therefore keeps its fail-open posture unchanged, and `test_612` pins that so the
two policies cannot be merged by accident.

**Change.** The generic handler now fails closed, sets `store_failed=True`, and returns the
same `429` + `Retry-After` the client would see for a genuine throttle. The endpoint records
`auth.login.throttle_store_failed` in the audit trail but returns an identical body, so an
attacker cannot learn that the store is down. The `# pragma: no cover` is gone — the branch is
now covered by seven tests.

**Measured after.** `{'allowed': False, 'count': 0, 'token': None, 'store_failed': True,
'retry_after': 900}`; a correct password is refused while the store is down (`test_607`).

### 12.2 R11 — production could silently use a per-process counter

**Defect.** `_build_store` caught every Redis init failure and returned `_MemoryStore` with a
warning. Phase 5 measured two separate processes each admitting 20 attempts against a
threshold of 20 (40 total).

**Change.**
* `RateLimitStoreUnavailable` and `_redis_is_required()` (`is_production_mode()`, i.e. `ENV`
  in `{production, prod}` or `STRICT_SECURITY` truthy).
* `_build_store` re-raises in production instead of falling back; development keeps the
  documented fallback.
* `validate_store_for_startup()` runs in the lifespan before the app serves: it requires a
  non-blank `REDIS_URL`, performs a real `PING`, and requires the limiter to have selected a
  shared backend. Errors name no host, port or credential — only the exception class.
* `docker-compose.prod.yml` sets `--maxmemory 400mb --maxmemory-policy noeviction`
  explicitly. `noeviction` is a **security** setting: evicting a live counter hands that
  account a fresh budget, the same defect as the memory store's old capacity behaviour.
  400mb is derived from measurement, not chosen: a 20,000-account fill used 40,000 keys and
  ~389 bytes/account, so 400mb holds roughly 1,000,000 concurrently-throttled accounts inside
  the existing 512M container limit. Re-measure if the key layout changes.
* `.env.example` documents that `REDIS_URL` is mandatory in production and why.

**Readiness.** `/api/ready` now includes the store in production (`rate_limit_store`,
`rate_limit_store_required`, `rate_limit_store_ok`) and returns 503 when it is down, with the
database still reported separately. It exposes no URL. **Liveness is deliberately unchanged**
and never probes Redis: restarts cannot fix Redis, so liveness depending on it would turn an
outage into a crash loop. `test_647` asserts both halves simultaneously.

**Redis persistence note.** AOF (`--appendonly yes`) is already enabled. Counters are
`window_seconds`-bounded and self-healing: losing them on restart gives an account at most one
extra budget window, which is why they are not worth stronger durability than AOF — but it is
also why `noeviction` matters, since silent eviction would do that on purpose, under load,
without a restart.

### 12.3 R10 — cross-tenant credential overwrite

**Defect.** `set_client_credentials` used
`WHERE page_id = ? OR page_id = ? OR LOWER(client_username) = LOWER(?)`. The third disjunct
had no tenant scope, so tenant B setting a name tenant A already used rewrote **A's** row —
hash, salt and magic token — while B's row kept its old value. Reproduced on SQLite and
PostgreSQL 16: A's original password stopped working and B's password authenticated as A.

**Change.**
* The write is addressed by `page_id` only. The username disjunct is gone.
* `CredentialConflictError` is raised when the normalized username already belongs to a
  *different* tenant, or equals another tenant's `page_id` (also a login identifier). The same
  tenant re-setting its own name, or a case/space variant of it, is accepted.
* `POST /api/pages/credentials` maps it to **409** without naming the owning tenant, so the
  endpoint cannot be used as a cross-tenant username oracle.
* `get_page` had the same tenant-unscoped username branch (`database.py:781`). It returned
  whichever row owned that *username*, i.e. potentially another tenant's configuration,
  including `gemini_api_key` when `mask_secrets=False`. Every caller passes a real `page_id`
  and magic tokens have their own query, so the branch served no caller and is removed.

**Migration — deliberately NOT applied.** A unique index is the structural fix, but it can
only be applied after the data assumptions are demonstrated, and this phase may not inspect or
change production data. The detection query and the deployment order are specified in
§12.5; until it runs clean, the write path is the enforced control.

### 12.4 R15 — stale counts for non-default windows

**Defect.** `get_account_failure_count` passed `ACCOUNT_FAILURE_WINDOW` (the *policy* window)
to `peek`, which overrode the generation's own window in the memory store. A 100s generation
read as `1` at age 150s while admission and refund already treated it as expired. Redis
reported `0`, because its `GET` ignores the argument — so the backends disagreed.

**Change.** Both read entry points pass no window, meaning "use the generation's own window",
which is the rule admission and refund already apply. The Phase 4.4 fixed-window policy is
untouched, TTLs are not extended, and stale/double-refund protection is re-asserted
(`test_679`). `test_678` proves memory and Redis now agree.

### 12.5 Required follow-up: the unique index is not yet applied

Remediation of R10 at the application layer is complete, but the schema still permits the
duplicates it refuses. Applying the constraint needs a production data question answered first.

**Detection query (run against production before any migration):**

```sql
-- 1. duplicate normalized usernames
SELECT LOWER(TRIM(client_username)) AS normalized, count(*), array_agg(page_id ORDER BY page_id)
FROM pages
WHERE client_username IS NOT NULL AND TRIM(client_username) <> ''
GROUP BY 1 HAVING count(*) > 1;

-- 2. usernames that collide with another tenant's page_id
SELECT p.page_id AS owner, p.client_username, q.page_id AS colliding_page
FROM pages p JOIN pages q
  ON LOWER(TRIM(p.client_username)) = LOWER(TRIM(q.page_id))
WHERE p.client_username IS NOT NULL AND TRIM(p.client_username) <> ''
  AND p.page_id <> q.page_id;
```

Both queries returned **0 rows** on the disposable PostgreSQL 16 database used here, which
proves nothing about production.

**Intended index (not created):**
`CREATE UNIQUE INDEX CONCURRENTLY uq_pages_client_username_norm ON pages (LOWER(TRIM(client_username))) WHERE client_username IS NOT NULL AND TRIM(client_username) <> '';`

**Deployment order:** run the detection queries → reconcile conflicts **manually and with the
tenant owner's involvement** (never automatically: choosing which tenant loses a username is a
business decision, and deleting a row would delete a tenant) → re-run until both return 0 →
create the index `CONCURRENTLY` (no write lock) → keep the application-level conflict check,
which gives a clean 409 instead of a raw integrity error.

**Rollback:** `DROP INDEX CONCURRENTLY uq_pages_client_username_norm;`. The application
behaviour is unchanged by rollback — the write path refuses conflicts independently.

**Blocker recorded:** reconciliation policy is an owner decision, so this portion is
documented rather than implemented, per the Phase 6 instruction to stop at unresolved business
rules and continue with the independent remediations.

### 12.6 Phase 6 CI evidence

Run [`44031882964`](https://github.com/AriukagiinTuvshoo/gerege-ai-agent/actions/runs/44031882964),
head `b59386c7d1d31366589d3b19fb0fc562b7982883`, conclusion **success**.

Step-level result from the API: 43 steps, **43 success, 0 failed, 0 skipped**. The Phase 6
gate ran and passed:

    E-02 Phase 6 — R14/R11/R10/R15 remediation security   success (new)

It reported **60 passed, 0 skipped** — the exact count the guard requires, so no case was
silently dropped and no Redis-dependent case skipped. The four predecessor gates (Phases 4.2,
4.3, 4.4 and the trusted-proxy/login suite that carries 4.1) all remained green, so none of
the Phase 6 changes regressed an earlier guarantee.

---

## 13. Phase 8 — the R10 race is closed at the database

Phase 7 confirmed that the Phase 6 `409` was only a **sequential** guard. Under genuine
concurrency the check-then-write in `set_client_credentials` still let two tenants both
commit the same name. This section records the remediation and supersedes the R10 portion of
§12.

### 13.1 The defect as measured

`.scratch/p8/repro.py`, barrier-synchronised claims, 3 trials per case, PostgreSQL 16.2 at
READ COMMITTED and SQLite 3.40.1:

| Case | Description | Before | After |
|---|---|---|---|
| 1 | 2 tenants, same name | written=2, dup=2, ambiguous=True | written=1, dup=1, **ambiguous=False** |
| 2 | 4 tenants, same name | written=4, dup=4, ambiguous=True | written=1, dup=1 |
| 3 | `CaseAlice` vs `CASEALICE` | written=2, dup=2, ambiguous=True | written=1, dup=1 |
| 4 | ` wsAlice ` vs `wsAlice` | written=2, dup=2, ambiguous=True | written=1, dup=1 |
| 5 | sequential second claimant | 1 WRITTEN + 1 CONFLICT | unchanged (still 409) |
| 6 | 2 tenants, distinct names | both WRITTEN | unchanged (both succeed) |

The losing tenant's row shows **`changed columns = none`** on both engines: the rollback
leaves no partial credential update behind. This was the specific risk of catching the
violation *after* writing — the write must be atomic with its failure handling.

### 13.2 The fix

`CREATE UNIQUE INDEX uq_pages_client_username_norm ON pages (LOWER(TRIM(client_username)))
WHERE client_username IS NOT NULL AND TRIM(client_username) <> ''`, installed by migration
`0005_username_uniqueness`.

The important properties, each of which was a deliberate decision:

* **The expression matches the read path exactly.** Login, the throttle key, and
  `resolve_canonical_account` normalize identically. An index on a different expression
  would protect a name nobody queries.
* **Partial, not full.** `NULL`, `''`, and whitespace-only usernames are outside the
  predicate; unlimited credential-less pages coexist. Counting blanks as one identity would
  deny service to every page that has no login yet.
* **Not `CONCURRENTLY`.** `migrations/env.py` runs inside `begin_transaction()`. The `SHARE`
  lock and the maintenance-window trade-off are documented in the operator procedure rather
  than hidden.
* **Shape-checked, not name-checked.** The pre-Phase-8 `_sync_indexes()` reduced the
  expression index to `['client_username']` and created it `unique=False`; because it used
  `IF NOT EXISTS`, the impostor survived with the right name and enforced nothing. The
  migration now drops a wrongly-shaped index and verifies the created shape. `index_is_correct()`
  requires unique + `lower` + `trim` + `where` in the engine's own definition text.
* **Enforced at startup.** `assert_security_invariants()` runs on every schema bring-up,
  including the already-at-head fast path, and refuses to serve if the index is missing or
  is an impostor. Without it the failure is silent: the app boots, reports healthy, and
  permits exactly the Phase 7 race.

### 13.3 Error mapping is narrow

Only the username-index violation becomes `CredentialConflictError` → `409`. The matcher
(`database._is_username_uniqueness_violation`) is verified against the real engine messages:

| Engine | Message | Mapped |
|---|---|---|
| PG | `UniqueViolation` `23505` `duplicate key value violates unique constraint "uq_pages_client_username_norm"` | yes |
| SQLite | `IntegrityError` `UNIQUE constraint failed: index 'uq_pages_client_username_norm'` | yes |
| PG | FK `23503` | **no** — propagates |
| PG | `pages.page_id` unique | **no** — propagates |
| PG/SQLite | NOT NULL | **no** — propagates |

A broad `except IntegrityError → 409` would have turned a broken foreign key into a message
telling a user their username was taken. Tests 860–862 pin the narrow behaviour.

### 13.4 The remedy in the startup error had to be corrected

The guard first advised "run the migration to revision `0005`". During migration validation
this was measured to be **insufficient**: Alembic is a no-op when the database is already
stamped at head, so a database whose index was dropped after the stamp cannot be repaired by
following that instruction — it prints success and the index stays missing.

`scripts/repair_username_uniqueness.py` was added to close that gap. It is
revision-independent, idempotent, `--check`-able, and refuses to touch a collision. The
startup message now names it first and states explicitly that `alembic upgrade head` only
works below the revision.

### 13.5 Migration and rollback validation

Run on disposable PostgreSQL 16 and SQLite databases, first-hand:

| Case | Result |
|---|---|
| Clean database | migrates to `0005`, index correct, `index_is_correct=True` |
| Repeated run | `ensure_schema` reports `upgraded: False`; index unchanged |
| Below revision with collisions | **stops** (`UsernameUniquenessBlocked`), names the group, rows unchanged, **no partial index** |
| Interrupted (stamped at head, index absent) | startup **refuses**; names the remedy; repair tool restores it |
| Operator resolves, then upgrades | succeeds, index correct |
| Downgrade to `0004` | index removed — **verified to re-permit duplicates**, i.e. a security downgrade |

No case chose a winner, rewrote a credential, or deleted a row. That is asserted, not
assumed: the validation printed the before/after `client_username` values.

### 13.6 Test integrity

* Concurrency tests open an **independent connection per thread** and use both barrier and
  natural-arrival styles.
* The phase 8 suite runs on SQLite **and** real PostgreSQL; `R10_REQUIRE_POSTGRES=1` turns a
  silent SQLite fallback into a hard failure, so a "PostgreSQL pass" cannot be reported for
  a run that used SQLite.
* `test_802`/`test_870`–`873` cover the index rejection, the repair tool, its refusal to
  touch collisions, and that the advertised remedy is not a no-op.
* Legacy-duplicate tests (Phase 4.1, 4.2) keep asserting the read path on a database that
  predates the index. They suspend the index through `tests/_username_uniqueness_support.py`,
  which **restores it and asserts the restoration** — a test can no longer silently leave
  the suite running without the guarantee.
* Run order independence was verified by running the suite twice against the same database.
