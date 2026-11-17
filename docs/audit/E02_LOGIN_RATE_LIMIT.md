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

## 5. Storage and concurrency

Phase 3 changed *what* the IP key is. Phase 4 added a second scope (`auth_account`) sharing the
same store abstraction. Phase 4.1 makes the account scope's increment atomic with its expiry
(Lua, §4.3B) and replaces whole-key reset with a clamped refund (§4.3C); the IP scope keeps the
`INCR`-then-`EXPIRE` sequence, which has the same crash window — recorded as a residual risk in
§8 R9 because fixing it is a change to the IP layer rather than the account layer.

Both scopes are subject to the per-process memory fallback described in §4.2E.

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
oracle are fixed and covered by `test_53`–`test_56`. Residual: a Redis outage still fails
open, which is E-03 scope and unchanged here.

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
they are left to expire.

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
| Account-level protection | **NOT IMPLEMENTED** (Phase 4) |
| Redis outage resilience | **NOT TESTED** / fail-open (E-03) |
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
