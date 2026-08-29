import hashlib
from pathlib import Path


class HashService:
    """Utility for calculating and comparing file hashes."""

    @staticmethod
    def calculate_sha256_from_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def calculate_sha256(path: str) -> str:
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(f"File not found: {path}")

        digest = hashlib.sha256()
        with target.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(65536), b""):
                digest.update(chunk)

        return digest.hexdigest()
