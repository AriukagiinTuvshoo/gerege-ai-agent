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
4. Every entry must parse as an IP address. An unparseable entry aborts the walk and the
   socket peer is used — a value the parser cannot understand never becomes an identity.
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

## 5. Storage and concurrency

Unchanged by this phase. The limiter remains a fixed-window `INCR` on Redis when
`REDIS_URL` is reachable, with a per-process memory fallback. Phase 3 only changes *what
the key is*, not how it is stored.

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

### 6.3 Phase 3 suite — `tests/test_e02_trusted_proxy.py` (34 tests)

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

The 2 pre-fix passes were observations, not policy assertions: test 21 read uvicorn's
`Config` defaults, and test 23 checked the memory backend reports itself honestly. Neither
touches the resolver.

### 6.4 Phase 3 change to a Phase 2 test

`test_07` in the Phase 2 file asserted that a 5.7 KB `X-Forwarded-For` should still yield
`203.0.113.5`. That contradicted Phase 3's own 1 KB bound, so the expectation was corrected
to "falls back to the peer" and an over-hop case was added. The bound is the safer
behaviour; the original assertion would have required raising it for no reason.

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

## 8. Remaining risks

**R1 — without a shared store the limit is per worker (E-03 scope).**
With 2 workers and no Redis, 14 attempts were all accepted: each worker has its own
counter, so the effective limit is 10 × workers. This is not a Phase 3 defect — the
identity is correct in every worker — but it means **Phase 3 alone does not close the
14/14 scenario on a multi-worker deployment without Redis**. With Redis configured (as
`docker-compose.prod.yml` does) the bypass is closed. Recorded rather than glossed over.

**R2 — E-02 is not finished.** Account-level protection does not exist. Rotating the source
address still allows unlimited attempts *per account*, bounded only by the per-IP limit.
The Phase 2 tests 8, 9, 10, 15, 17, 19 still fail, and SEC-07 remains **FAIL**.

**R3 — `X-Real-IP` and `Forwarded` are unsupported.** If a future proxy sends only those,
every request will look like it came from the proxy and users will share one budget.
Adding support requires its own trust validation and tests; it is deliberately not done
silently.

**R4 — the trust list is not reloadable at runtime.** It is read once per process;
changing `.env` requires a restart. `refresh_trusted_proxies()` exists for tests.

**R5 — `trusted_proxy_count` was not implemented.** With CIDR support and the
right-to-left walk, a correct chain resolves without naming a hop count. Requiring an
operator to also state the hop count adds a way to misconfigure it.

**R6 — account enumeration is still trivial** (Phase 4), and Redis outage still fails open
(E-03). Neither is changed here.

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
