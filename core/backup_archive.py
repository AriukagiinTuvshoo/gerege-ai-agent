"""Archive resolution: one place that knows an archive may be encrypted (Phase 18).

Phase 17's CRITICAL-1 was a seam problem. ``create_backup`` produced ``.sql.gz``;
``backup_automation`` then encrypted it into ``.sql.gz.enc`` and deleted the plaintext.
Everything else — ``list_backups``, ``verify_backup``, ``restore_backup`` — still matched
only the plaintext suffixes, so the shipped product could create artifacts it could not
read. The fix is not to add ``.enc`` to three suffix checks and hope; it is to funnel
every reader through this module, so "what is this file and how do I get plaintext out
of it" has exactly one answer.

Resolution rules
----------------
* ``<name>.enc`` with this repository's magic  → authenticated archive, decrypt to a
  private temp file.
* ``<name>.enc`` with ``Salted__``             → Phase 16 legacy, decrypt via openssl,
  flagged as **unauthenticated**.
* ``<name>.enc`` with neither magic            → reject. Never guess.
* ``<name>.sql.gz`` / ``<name>.db.gz``         → plaintext archive, use in place.

Callers get a :class:`ResolvedArchive` and use it as a context manager. The plaintext
temp file is created with 0600 inside a 0700 directory and is destroyed on exit.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from core import backup_crypto
from core.backup_staging import StagingDir

ENCRYPTED_SUFFIX = ".enc"
PLAINTEXT_SUFFIXES = (".sql.gz", ".db.gz")


def is_encrypted_name(name: str) -> bool:
    return name.endswith(ENCRYPTED_SUFFIX)


def is_plaintext_name(name: str) -> bool:
    return name.endswith(PLAINTEXT_SUFFIXES)


def is_archive_name(name: str) -> bool:
    return is_encrypted_name(name) or is_plaintext_name(name)


def encryption_format(path: str) -> str:
    """Return ``authenticated``, ``legacy-openssl`` or ``unknown`` for an ``.enc`` file."""
    if backup_crypto.is_authenticated_archive(path):
        return "authenticated"
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return "unknown"
    if head.startswith(b"Salted__"):
        return "legacy-openssl"
    return "unknown"


def encrypted_size(path: str) -> int:
    return os.path.getsize(path)


class ArchiveError(Exception):
    """Raised when an archive cannot be turned into restorable plaintext."""


class ResolvedArchive:
    """A restorable plaintext view of an archive, encrypted or not.

    Attributes
    ----------
    name          the on-disk filename that was resolved
    plaintext_path what the restore code should read (temp file when encrypted)
    engine        ``postgresql`` or ``sqlite`` inferred from the inner filename
    format        ``authenticated`` | ``legacy-openssl`` | ``plaintext``
    """

    def __init__(self, name: str, plaintext_path: str, engine: str, fmt: str,
                 staging: Optional[StagingDir] = None, authenticated: bool = True) -> None:
        self.name = name
        self.plaintext_path = plaintext_path
        self.engine = engine
        self.format = fmt
        self.authenticated = authenticated
        self._staging = staging

    def __enter__(self) -> "ResolvedArchive":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._staging is not None:
            self._staging.cleanup()
        return False


def _engine_of(inner_name: str) -> str:
    if inner_name.endswith(".db.gz"):
        return "sqlite"
    return "postgresql"


def assert_contained(directory: str, name: str) -> str:
    """Return the joined path, or raise if it resolves outside ``directory``.

    Phase 24 (F-1). `resolve()` guarded only the encrypted path; `verify_backup` and the
    plaintext restore path joined `BACKUP_DIR + name` directly and followed symlinks
    without question, so a symlink to a valid dump elsewhere on the filesystem was accepted
    and executed by `psql`. Reproduced on a disposable database.

    `realpath` rather than `islink`: a link pointing *inside* the directory is harmless and
    refusing it would break legitimate layouts.
    """
    clean = os.path.basename(name)
    path = os.path.join(directory, clean)
    real_directory = os.path.realpath(directory)
    real_path = os.path.realpath(path)
    try:
        contained = os.path.commonpath([real_directory, real_path]) == real_directory
    except ValueError:
        # Different drives / an unmergeable path pair: treat as escaping.
        contained = False
    if not contained:
        raise ArchiveError(
            f"archive {clean} resolves to {real_path}, which is outside the backup "
            f"directory {real_directory}; refusing to use it. Backups must live inside "
            "BACKUP_DIR - a link pointing elsewhere could substitute arbitrary SQL."
        )
    return path


def resolve(directory: str, name: str, key_file: Optional[str] = None) -> ResolvedArchive:
    """Turn ``directory/name`` into a plaintext view, decrypting when necessary.

    Raises :class:`ArchiveError` with an operator-facing message on every failure path;
    the message never contains key material or a DSN.
    """
    clean = os.path.basename(name)
    path = os.path.join(directory, clean)
    if not os.path.exists(path):
        raise ArchiveError(f"archive not found: {clean}")

    # Phase 24 (F-1): refuse an archive whose real path escapes the backup directory.
    assert_contained(directory, clean)

    if is_plaintext_name(clean):
        return ResolvedArchive(clean, path, _engine_of(clean), "plaintext")

    if not is_encrypted_name(clean):
        raise ArchiveError(
            f"unsupported archive type: {clean} (expected .sql.gz, .db.gz or .enc)"
        )

    if not key_file:
        raise ArchiveError(
            f"{clean} is encrypted but no key file is configured; "
            "set BACKUP_ENCRYPTION_KEY_FILE"
        )
    if not os.path.exists(key_file):
        raise ArchiveError(
            f"encryption key file not found: {os.path.basename(key_file)}"
        )

    fmt = encryption_format(path)
    inner_name = clean[: -len(ENCRYPTED_SUFFIX)]
    if not is_plaintext_name(inner_name):
        raise ArchiveError(f"encrypted archive has an unrecognised inner name: {clean}")

    staging = StagingDir(directory, prefix=".restore-")
    staging.__enter__()
    try:
        out = staging.path(inner_name)
        if fmt == "authenticated":
            try:
                backup_crypto.decrypt_file(path, out, key_file)
            except backup_crypto.EncryptionError as exc:
                raise ArchiveError(str(exc)) from exc
            return ResolvedArchive(clean, out, _engine_of(inner_name), "authenticated",
                                   staging, authenticated=True)
        if fmt == "legacy-openssl":
            try:
                backup_crypto.decrypt_legacy_openssl(path, out, key_file)
            except backup_crypto.EncryptionError as exc:
                raise ArchiveError(str(exc)) from exc
            return ResolvedArchive(clean, out, _engine_of(inner_name), "legacy-openssl",
                                   staging, authenticated=False)
        raise ArchiveError(
            f"{clean} is not a recognised encrypted archive (unknown magic); refusing to guess"
        )
    except Exception:
        staging.cleanup()
        raise


def sidecar_paths(directory: str, name: str) -> Dict[str, str]:
    """The sidecar files that belong to an archive, wherever they live.

    ``create_backup`` names them ``<archive>.sha256`` and ``<archive>.meta.json``. When
    the archive is later encrypted, the sidecars keep pointing at the plaintext name
    (that is deliberate: the checksum is of the plaintext), so pruning an ``.enc`` must
    also remove the sidecars named after its inner archive. Phase 17 found ``prune``
    building ``<archive>.enc.json`` instead of ``<archive>.meta.json``, which orphaned
    every sidecar it ever touched.
    """
    base = os.path.join(directory, name)
    names = {base + ".sha256", base + ".meta.json", base + ".json"}
    if is_encrypted_name(name):
        inner = base[: -len(ENCRYPTED_SUFFIX)]
        names |= {inner + ".sha256", inner + ".meta.json"}
    return {name: name for name in sorted(names) if os.path.exists(name)}


def describe(directory: str, name: str) -> Dict[str, Any]:
    """Non-failing summary used by ``list`` and by monitoring."""
    path = os.path.join(directory, os.path.basename(name))
    info: Dict[str, Any] = {
        "filename": os.path.basename(name),
        "encrypted": is_encrypted_name(name),
        "exists": os.path.exists(path),
    }
    if not info["exists"]:
        return info
    info["size_bytes"] = os.path.getsize(path)
    if info["encrypted"]:
        info["format"] = encryption_format(path)
        info["authenticated"] = info["format"] == "authenticated"
        inner = os.path.basename(name)[: -len(ENCRYPTED_SUFFIX)]
        info["engine"] = _engine_of(inner)
    else:
        info["format"] = "plaintext"
        info["authenticated"] = False
        info["engine"] = _engine_of(os.path.basename(name))
    return info
