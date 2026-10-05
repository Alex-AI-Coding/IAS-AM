import hashlib
import os
import stat
from pathlib import Path
from antivirus.config.settings import MAX_FILE_BYTES


class HashService:
    """Utility for calculating and comparing file hashes."""

    @staticmethod
    def calculate_sha256_from_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def calculate_sha256(path: str, max_bytes: int = MAX_FILE_BYTES) -> str:
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(f"File not found: {path}")

        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(target, flags)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as file_handle:
            if not stat.S_ISREG(os.fstat(file_handle.fileno()).st_mode):
                raise ValueError("Only regular files can be hashed.")
            total = 0
            for chunk in iter(lambda: file_handle.read(65536), b""):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(
                        "File grew beyond the hashing limit during scanning."
                    )
                digest.update(chunk)

        return digest.hexdigest()
