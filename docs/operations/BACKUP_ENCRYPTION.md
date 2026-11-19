# Backup encryption architecture

A backup is a complete copy of every tenant's data: page access tokens, Gemini API keys,
QPay credentials, Telegram bot tokens, password hashes, and customer phone numbers. It
must be unreadable to anyone who obtains the file, and it must be *provably* unmodified.

This document describes the format, the key, and how to recover with it. It replaces the
Phase 16 arrangement, which used `openssl enc -aes-256-cbc` — confidentiality only, no
authentication.

## Why the algorithm changed

| | Phase 16 (`openssl enc`) | Phase 18 |
|---|---|---|
| Cipher | AES-256-CBC | AES-256-GCM |
| Integrity | none (gzip CRC32 only) | GCM authentication tag |
| Tamper detection | **no** — a flipped bit decrypted to garbage | **yes** — decryption fails |
| Wrong key | detected by padding, sometimes | always detected |
| Truncation | sometimes detected | always detected |
| Metadata protection | none | header bound as AAD |
| Streaming | yes | yes (1 MiB frames) |

The decisive fact: **`openssl enc` cannot do authenticated encryption.** In OpenSSL 3.0
`openssl enc -ciphers` lists `-chacha20` but no Poly1305 and no GCM, so there is no way to
build AEAD on that path. The primitive is taken from the Python `cryptography` package
(AESGCM), which is a vetted implementation of a standard construction. No cryptography is
invented in this repository.

`age` would also have been acceptable, but it is not a dependency, is not present in the
runtime image, and would add an external binary to the deployment surface.

## Container format (version 1)

```
magic        8 bytes    b"GEREGE-B"
version      1 byte     0x01
header_len   2 bytes    big-endian
header       N bytes    UTF-8 JSON, key-ordered, ASCII
frame*                  [frame_len 4][nonce 12][ciphertext frame_len][tag 16]
terminator              [frame_len = 0][nonce 12][tag 16]
```

Header fields: `cipher`, `created_at`, `format`, `original_name`, `original_size`,
`version`. The header is passed as **additional authenticated data** to every frame, so
`original_size` and `version` cannot be altered without authentication failing.

* `frame_len` counts the ciphertext bytes following its nonce. Without an explicit length
  the final frame is indistinguishable from the start of the terminator; that bug was
  found and fixed during development.
* Each frame carries a fresh 12-byte random nonce. It is written in the clear and
  authenticated as part of the ciphertext.
* The zero-length terminator proves the stream was not truncated. Trailing bytes after it
  are rejected rather than ignored.

**Unsupported versions are rejected by name** (`unsupported encrypted archive version N`)
rather than being guessed at, which is what makes a future format change safe.

## Key

* 32 bytes. Either raw binary or a base64 encoding of 32 bytes (the documented generator
  is `head -c 32 /dev/urandom | base64`).
* Anything else is refused. A wrong-length key is almost always the wrong *file*, and
  stretching it through a KDF would silently produce archives that a later version cannot
  read.
* Stored as a **file**, never an environment value, so it cannot leak through
  `docker inspect` or a process listing.
* Never written beside the archive, never copied offsite, never included in the metadata.

| Environment | Value |
|---|---|
| `BACKUP_ENCRYPTION_KEY_FILE` | path to the key (container: `/run/secrets/backup.key`) |
| `BACKUP_ENCRYPTION` | `on` (default) or `off` for development only |

Generate it once, on the maintenance host:

```bash
sudo install -d -m 0700 /etc/gerege
head -c 32 /dev/urandom | base64 | sudo tee /etc/gerege/backup.key >/dev/null
sudo chmod 0400 /etc/gerege/backup.key
```

**Store a copy in your secret manager.** Losing this file makes every archive unreadable.
That is the point, and it is also the operational risk.

> Compose note: `docker-compose.prod.yml` mounts the key from `./secrets/backup.key` to
> `/run/secrets/backup.key`. `secrets/` is gitignored. If you keep the key at
> `/etc/gerege/backup.key` instead, point the compose volume at that path — the two must
> agree, and Phase 17 found the documentation and Compose disagreeing.

## Key rotation

Rotating the key does **not** re-encrypt existing archives. The procedure is:

1. Generate a new key file, e.g. `/etc/gerege/backup.key.new`.
2. Take a fresh backup with the **new** key, and verify it:
   `python scripts/maintenance.py verify <archive>`.
3. Confirm you can restore it into a disposable database (see
   [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md)). **Do not switch until this passes.**
4. Move the old key to `/etc/gerege/backup.key.old` and the new one into place.
5. Keep the old key for at least `BACKUP_RETENTION_DAYS`, because archives encrypted with
   it still exist and are still restorable with it. `restore` uses whichever key
   `BACKUP_ENCRYPTION_KEY_FILE` points at, so to restore an old archive, point it at the
   old key file.

There is no automatic re-encryption. Archives are self-describing, so any archive can be
identified by its header regardless of which key produced it.

## Integrity verification

Three independent checks, in order:

1. **SHA-256 of the ciphertext**, stored in `<archive>.enc.sha256` (and mirrored at
   `<archive>.sql.gz.sha256`). This detects corruption of the stored bytes — bit rot, a
   truncated transfer, a half-written object. It is verified *before* decrypting.
2. **GCM authentication**, which runs during decryption and proves the plaintext is
   exactly what was encrypted, under a key the attacker does not have.
3. **gzip and SQL structure**, which prove the plaintext is a plausible dump.

Only (2) is a security property. (1) is availability, (3) is sanity. `verify` returns
nonzero if any of them fails, and never reports a corrupted archive as valid.

## Legacy archives

Phase 16 archives begin with `Salted__` and are still readable via
`backup_crypto.decrypt_legacy_openssl`. They carry **no authentication tag**; a successful
decrypt only means the padding was well formed. `maintenance.py verify` reports these as
`legacy-openssl`, `authenticated: false`. Re-take any archive you intend to rely on.

## What encryption does not protect

* **Availability.** The runtime containers mount the backup directory read-write. The key
  is not mounted into `web`/`worker`, so they cannot decrypt an archive — but they could
  delete it. Keep `BACKUP_OFFSITE_PATH`/`BACKUP_OFFSITE_URL` configured so a deletion is
  not total loss.
* **A compromised maintenance container.** That container holds both the owner credential
  and the key. Nothing inside the application boundary is designed to survive that.
