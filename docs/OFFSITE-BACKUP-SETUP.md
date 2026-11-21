# Offsite backup setup — and how to earn `VERIFIED`

> **Status: the mechanism works and is tested. NO real provider is configured. Offsite is
> NOT VERIFIED.** Everything below describes how to get there, not where you are.

---

## 1. Status values, and what each one actually asserts

Only these four exist. They are not a ladder to be climbed optimistically.

| Status | Assertion | How it is reached |
|---|---|---|
| `OFFSITE_NOT_CONFIGURED` | no usable `BACKUP_OFFSITE_URL` | default |
| `OFFSITE_CONFIGURED` | a provider object was constructed and validated | `status()` |
| `OFFSITE_VERIFIED` | an object was uploaded, downloaded back, and its SHA-256 matched **locally recorded** bytes | `verify_against_record()` |
| `OFFSITE_FAILED` | an attempted operation failed | any failure path |

`CONFIGURED` is not `VERIFIED`. A key check the design forbids: the digest is supplied by the
caller from the local record and is **never** read from the object's own metadata. Verifying a
remote file against a digest stored next to it proves only that the storage is self-consistent
— not that the bytes are yours.

`status()` returns `CONFIGURED` and never claims `VERIFIED`. That is deliberate.

---

## 2. Configuration

| Variable | Required | Meaning |
|---|---|---|
| `BACKUP_OFFSITE_URL` | yes | `https://<endpoint>/<bucket>/<prefix>` |
| `BACKUP_OFFSITE_ACCESS_KEY` | yes | credential |
| `BACKUP_OFFSITE_SECRET_KEY` | yes | credential |
| `BACKUP_OFFSITE_REGION` | no (`us-east-1`) | signing region |
| `BACKUP_OFFSITE_ALLOW_INSECURE_LOOPBACK` | **tests only** | `1` permits plain `http` to a **loopback** host. Refused in production, ignored for any non-loopback host, requires exactly `1`. |

Credentials belong in the maintenance environment file (mode 0600), never in a unit file,
never in git. Use a key scoped to that one prefix with only:

```
s3:PutObject, s3:GetObject, s3:DeleteObject
```

No `ListBucket` unless you want retention to work on the remote side; no bucket-wide wildcard.

### Why HTTPS is mandatory

Plain `http` is refused with `BACKUP_OFFSITE_URL must use https://; refusing plaintext
transport`. A backup crossing a network in the clear is worse than one that never left the
host.

The loopback opt-in exists for one reason: the only way to verify this code against a real S3
implementation without a cloud account is a local S3-compatible server, and every such server
is plain HTTP. It cannot be widened — verified against a remote host, a `10.0.0.5` address, and
`ENV=production`, all refused.

---

## 3. What is verified locally (and by which test)

Run against a local S3-compatible server with the literal credentials `test`/`test`.
`tests/test_e07_phase24_offsite_integration.py` skips itself if real AWS credentials are
present in the environment, so it cannot accidentally bill an account.

| Behaviour | Result |
|---|---|
| Upload then list then download round trip | bytes identical |
| `download_verified` against a supplied digest | verified |
| Same-size corruption (different bytes, same length) | **detected** — `downloaded digest does not match the expected sha256` |
| Truncation | detected |
| Missing object | reported as failure, not as absence |
| Verification without a digest | refused |
| Upload of a non-existent source | clean failure |
| Listing past 1000 objects | complete (1005 objects returned) |
| Delete | removes exactly one object, no others |
| Loopback opt-in against a remote host | refused |

---

## 4. Earning `VERIFIED` on a real provider

Follow this in order. Each step produces evidence; without all of it, the provider stays
`NOT VERIFIED`.

1. **Create a bucket and a scoped credential.** Confirm the credential cannot list the whole
   account — try and watch it fail.
2. **Configure** `BACKUP_OFFSITE_URL` with `https://`. Confirm status is `CONFIGURED`, not
   `VERIFIED`:
   ```bash
   python scripts/maintenance.py status        # offsite: CONFIGURED
   ```
3. **One real backup with offsite enabled.**
   ```bash
   python scripts/maintenance.py backup-run --label offsite-verify
   ```
   The status file must show the upload succeeded. Capture it.
4. **Independently confirm the object exists** in the provider's console or CLI —
   not through this code, which is the thing being tested.
5. **Download it back and verify the digest.** The digest must come from the local
   `.sha256` sidecar or the manifest, not from object metadata.
6. **Prove detection works, then undo it.** Corrupt the remote object in a way that does not
   change its size, re-run verification, and confirm it fails with a digest mismatch. Restore
   the object (re-upload) afterwards.
7. **Record all six artefacts.** Commit nothing containing credentials.

Only then is the provider `VERIFIED`. Write the date, the endpoint host, and the archive name
into the operations log — not the credentials.

---

## 5. Restoring from offsite

Offsite is a second copy, not a different restore path. To recover:

1. Download the object to a machine that has the key file, preserving the `.sha256` and
   `.meta.json` sidecars.
2. Verify before restoring:
   ```bash
   python scripts/maintenance.py verify <archive>.enc
   ```
3. Place it in `BACKUP_DIR` and restore normally. See
   [DISASTER_RECOVERY.md](operations/DISASTER_RECOVERY.md).

The archive must live **inside** `BACKUP_DIR`. A symlink pointing elsewhere is refused (F-1,
Phase 24) — that check exists because a link to arbitrary SQL was, before the fix, accepted and
executed by `psql`.

---

## 6. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `OFFSITE_NOT_CONFIGURED` with an error about `https` | plain `http` to a non-loopback host |
| `transport failure: URLError` | endpoint unreachable or DNS |
| `http 403` on upload | credential lacks `PutObject` on that prefix |
| `downloaded digest does not match` | genuine corruption, or a different archive under the same name |
| `downloaded size mismatch` | truncated upload or a partial multipart |
| retention deleting nothing | objects were never verified; retention refuses to delete an unverified copy |

**Retention never deletes an object it could not verify.** If remote space is not shrinking,
that is the reason — check verification before blaming retention.

---

## 7. What remains unproven

| Claim | Status |
|---|---|
| Pagination, digest verification, corruption detection | **tested** locally |
| HTTPS enforcement, loopback opt-in boundaries | **tested** |
| Upload/download against a real S3 implementation | **tested** against a local S3-compatible server |
| Works against the provider you intend to use | **NOT VERIFIED** |
| Credentials scoped correctly for that provider | **NOT VERIFIED** |
| Restore from a real offsite copy | **NOT VERIFIED** |

Offsite does not yet protect you from losing this host.
