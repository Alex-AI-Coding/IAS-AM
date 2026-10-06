"""Verified encrypted isolation, no-clobber restore, and explicit vault deletion.

The OS account is trusted. This is not a kernel sandbox or a defense against
an administrator changing filesystem objects between operations.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
from threading import RLock
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from antivirus.config.settings import QUARANTINE_DIR, MAX_FILE_BYTES
from antivirus.model.quarantine_item import QuarantineItem
from antivirus.repository.quarantine_repository import QuarantineRepository
from antivirus.services.vault_key import windows_protect

MAGIC = b"PREMIERE-VAULT\x01"
CHUNK_SIZE = 65536


class QuarantineError(ValueError):
    """An actionable failure that leaves surviving copies and evidence intact."""


class QuarantineService:
    def __init__(self, directory=None, max_bytes=MAX_FILE_BYTES):
        self.directory = Path(directory or QUARANTINE_DIR).absolute()
        self.payload_directory = self.directory / "payloads"
        self.max_bytes = max_bytes
        if max_bytes <= 0:
            raise ValueError("Quarantine size limit must be positive.")
        self._lock = RLock()
        self._ensure_directory()
        index = self.directory / "index.db"
        if index.is_symlink() or (index.exists() and index.stat().st_nlink > 1):
            raise QuarantineError("The quarantine catalogue must not be linked.")
        self.repository = QuarantineRepository(index)
        if os.name != "nt":
            index.chmod(0o600)

    @staticmethod
    def _reject_links(path):
        for part in (path, *path.parents):
            if part.is_symlink() or (
                hasattr(part, "is_junction") and part.is_junction()
            ):
                raise QuarantineError(
                    "Linked paths and junctions are not supported for quarantine actions."
                )

    def _ensure_directory(self):
        self._reject_links(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._reject_links(self.payload_directory)
        self.payload_directory.mkdir(exist_ok=True, mode=0o700)
        if os.name != "nt":
            self.directory.chmod(0o700)
            self.payload_directory.chmod(0o700)

    @contextmanager
    def _read_regular(self, path, single_link=True):
        self._reject_links(path)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink > 1):
            raise QuarantineError(
                "Only regular files with one filesystem link are supported."
            )
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or self._identity(
                before
            ) != self._identity(opened):
                raise QuarantineError(
                    "The file changed while it was being opened. Scan it again."
                )
            yield stream, opened

    @staticmethod
    def _identity(info):
        return (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    @staticmethod
    def _exclusive_file(path):
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        return os.fdopen(descriptor, "wb")

    def _key(self):
        self._ensure_directory()
        path = self.directory / (
            "vault-key.dpapi" if os.name == "nt" else "vault-key.bin"
        )
        if not path.exists():
            if any(item.state != "deleted" for item in self.repository.items()):
                raise QuarantineError(
                    "The quarantine key is missing. Restore its protected backup; a new key cannot recover these files."
                )
            key = os.urandom(32)
            protected = windows_protect(key) if os.name == "nt" else key
            try:
                with self._exclusive_file(path) as stream:
                    stream.write(protected)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                pass
        with self._read_regular(path) as (stream, info):
            if info.st_size > 16384:
                raise QuarantineError("The quarantine key file is invalid.")
            protected = stream.read()
        key = windows_protect(protected, decrypt=True) if os.name == "nt" else protected
        if len(key) != 32:
            raise QuarantineError(
                "The quarantine key is invalid. Existing files were left intact."
            )
        if os.name != "nt":
            path.chmod(0o600)
        return key

    def _payload(self, entry_id):
        if not isinstance(entry_id, str) or not re.fullmatch(r"[0-9a-f]{32}", entry_id):
            raise QuarantineError("Invalid quarantine item identifier.")
        self._ensure_directory()
        return self.payload_directory / (entry_id + ".qvault")

    def _get(self, entry_id):
        self._payload(entry_id)
        try:
            return self.repository.get(entry_id)
        except KeyError as exc:
            raise QuarantineError(str(exc)) from exc

    def items(self):
        with self._lock:
            self._ensure_directory()
            return self.repository.items()

    def _encrypt(self, source, payload, item, key):
        nonce = os.urandom(12)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(item.authenticated_metadata())
        digest = hashlib.sha256()
        total = 0
        with self._exclusive_file(payload) as output:
            output.write(MAGIC + nonce)
            for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
                total += len(chunk)
                if total > self.max_bytes:
                    raise QuarantineError(
                        "File grew beyond the quarantine limit. Scan it again."
                    )
                digest.update(chunk)
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)
            output.flush()
            os.fsync(output.fileno())
        if total != item.file_size or digest.hexdigest() != item.sha256:
            raise QuarantineError(
                "File contents changed since detection. The original was kept; scan it again."
            )

    def _decrypt(self, item, key, output=None):
        payload = self._payload(item.entry_id)
        digest = hashlib.sha256()
        total = 0
        with self._read_regular(payload) as (source, info):
            expected = len(MAGIC) + 12 + item.file_size + 16
            if not 0 <= item.file_size <= self.max_bytes or info.st_size != expected:
                raise QuarantineError(
                    "The encrypted file is missing, incomplete, or has an invalid size."
                )
            if source.read(len(MAGIC)) != MAGIC:
                raise QuarantineError("The encrypted file format is invalid.")
            nonce = source.read(12)
            source.seek(-16, os.SEEK_END)
            tag = source.read(16)
            source.seek(len(MAGIC) + 12)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(item.authenticated_metadata())
            remaining = item.file_size
            while remaining:
                chunk = source.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise QuarantineError("The encrypted file was truncated.")
                remaining -= len(chunk)
                plaintext = decryptor.update(chunk)
                digest.update(plaintext)
                total += len(plaintext)
                if output:
                    output.write(plaintext)
            try:
                final = decryptor.finalize()
            except InvalidTag as exc:
                raise QuarantineError(
                    "Integrity verification failed. The encrypted file or its evidence was changed."
                ) from exc
            digest.update(final)
            total += len(final)
            if output:
                output.write(final)
            if self._identity(info) != self._identity(os.fstat(source.fileno())):
                raise QuarantineError("The encrypted file changed during verification.")
        if digest.hexdigest() != item.sha256 or total != item.file_size:
            raise QuarantineError(
                "The recovered content does not match the recorded SHA-256."
            )

    def quarantine(self, result):
        with self._lock:
            if not result.is_detected or not result.threats:
                raise QuarantineError(
                    "Quarantine is available only for detected files."
                )
            if not isinstance(result.sha256, str) or not re.fullmatch(
                r"[0-9a-fA-F]{64}", result.sha256
            ):
                raise QuarantineError(
                    "A verified scan hash is required. Scan this file again."
                )
            path = Path(os.path.abspath(os.path.expanduser(result.file_path)))
            if path.resolve().is_relative_to(self.directory.resolve()):
                raise QuarantineError(
                    "Files already inside the vault cannot be quarantined again."
                )
            key = self._key()
            with self._read_regular(path) as (source, info):
                if info.st_size > self.max_bytes:
                    raise QuarantineError(
                        "This file exceeds the configured quarantine limit."
                    )
                now = datetime.now(timezone.utc).isoformat()
                item = QuarantineItem(
                    uuid.uuid4().hex,
                    str(path),
                    result.sha256.lower(),
                    info.st_size,
                    [
                        {
                            "name": str(t.name or "Unknown"),
                            "category": str(t.category or "Unknown"),
                            "severity": str(t.severity or "Unknown"),
                            "source": str(t.source or "unknown"),
                            "description": str(t.description or ""),
                        }
                        for t in result.threats
                    ],
                    added_at=now,
                    updated_at=now,
                )
                payload = self._payload(item.entry_id)
                self.repository.add(item)
                try:
                    self._encrypt(source, payload, item, key)
                    if self._identity(info) != self._identity(
                        os.fstat(source.fileno())
                    ):
                        raise QuarantineError(
                            "The original changed during isolation; it was kept."
                        )
                    self._decrypt(item, key)
                    self.repository.update_state(item.entry_id, "copy_retained")
                except Exception as exc:
                    # Keep an encrypted orphan for diagnosis instead of risking the original.
                    self.repository.update_state(item.entry_id, "incomplete", str(exc))
                    raise
            return self._remove_original(item, info)

    def _remove_original(self, item, expected_info):
        source = Path(item.original_path)
        try:
            self._reject_links(source)
            if self._identity(source.lstat()) != self._identity(expected_info):
                raise QuarantineError(
                    "The original changed before removal; it was kept."
                )
            source.unlink()
        except (OSError, QuarantineError) as exc:
            return self.repository.update_state(
                item.entry_id,
                "copy_retained",
                f"The encrypted copy is held, but original removal was not completed: {exc}",
            )
        try:
            return self.repository.update_state(item.entry_id, "active")
        except (OSError, sqlite3.Error) as exc:
            raise QuarantineError(
                "The original was isolated, but its status could not be saved. "
                "The encrypted copy remains in the vault; refresh Quarantine."
            ) from exc

    def retry_isolation(self, entry_id):
        with self._lock:
            item = self._get(entry_id)
            if item.state != "copy_retained":
                raise QuarantineError("This item does not need an isolation retry.")
            self._decrypt(item, self._key())
            source_path = Path(item.original_path)
            if not source_path.exists() and not source_path.is_symlink():
                return self.repository.update_state(entry_id, "active")
            with self._read_regular(source_path) as (source, info):
                digest = hashlib.sha256()
                total = 0
                for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise QuarantineError(
                            "The original grew beyond the configured limit."
                        )
                    digest.update(chunk)
                if digest.hexdigest() != item.sha256 or total != item.file_size:
                    raise QuarantineError(
                        "The original has changed. It was kept; run a new scan."
                    )
                if self._identity(info) != self._identity(os.fstat(source.fileno())):
                    raise QuarantineError("The original changed during the retry.")
            return self._remove_original(item, info)

    def restore(self, entry_id, destination=None):
        with self._lock:
            item = self._get(entry_id)
            if item.state not in {"active", "copy_retained"}:
                raise QuarantineError("Only a verified held item can be restored.")
            path = Path(
                os.path.abspath(
                    os.path.expanduser(str(destination or item.original_path))
                )
            )
            self._reject_links(path)
            if path.resolve().is_relative_to(self.directory.resolve()):
                raise QuarantineError("Choose a restore location outside the vault.")
            if path.exists() or path.is_symlink():
                raise QuarantineError(
                    "A file already exists at this location. Choose Restore as; existing files are never overwritten."
                )
            if not path.parent.is_dir():
                raise QuarantineError(
                    "The original folder is missing. Choose Restore as and select an existing folder."
                )
            key = self._key()
            self._decrypt(item, key)  # Verify before any plaintext is written.
            temporary = path.parent / (".premiere-restore-" + uuid.uuid4().hex + ".tmp")
            published = False
            try:
                with self._exclusive_file(temporary) as output:
                    self._decrypt(item, key, output)
                    output.flush()
                    os.fsync(output.fileno())
                self._reject_links(path.parent)
                os.link(
                    temporary, path
                )  # Atomic publication with no existing-file replacement.
                published = True
                # Retain an encrypted backup until the user explicitly deletes it.
                return self.repository.update_state(
                    entry_id, "restored", restored_path=str(path)
                )
            except Exception as exc:
                if published:
                    raise QuarantineError(
                        f"The file was restored to {path}, but its status could not be saved. "
                        "The encrypted backup remains."
                    ) from exc
                raise
            finally:
                if temporary.exists():
                    temporary.unlink()

    def delete(self, entry_id):
        with self._lock:
            item = self._get(entry_id)
            if item.state == "deleted":
                return item
            payload = self._payload(entry_id)
            self.repository.update_state(entry_id, "deleting")
            try:
                if payload.exists() or payload.is_symlink():
                    with self._read_regular(payload):
                        pass
                    payload.unlink()
            except Exception as exc:
                self.repository.update_state(entry_id, item.state, str(exc))
                raise
            return self.repository.update_state(entry_id, "deleted")
