"""Ed25519 report integrity with an independently trusted public-key check."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from antivirus.config.settings import BASE_DIR
from antivirus.services.report_formatter import ReportFormatter


class ReportSigner:
    def __init__(self, key_directory=None):
        self.key_directory = Path(key_directory or BASE_DIR / "keys")

    @staticmethod
    def canonical_bytes(report: dict) -> bytes:
        return json.dumps(
            report,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def _private_key(self):
        self.key_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.key_directory / "report-signing.pem"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            key = Ed25519PrivateKey.generate()
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("The signing key is not Ed25519.")
        public_path = self.key_directory / "report-public.pem"
        public_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return key

    def sign(self, report) -> dict:
        key = self._private_key()
        data = ReportFormatter.to_dict(report)
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "schema_version": 1,
            "algorithm": "Ed25519",
            "report": data,
            "signature": base64.b64encode(key.sign(self.canonical_bytes(data))).decode(
                "ascii"
            ),
            "public_key": base64.b64encode(public).decode("ascii"),
            "key_fingerprint": hashlib.sha256(public).hexdigest(),
        }

    @classmethod
    def verify(cls, bundle: dict, trusted_public_key: bytes) -> bool:
        """An embedded key alone cannot establish the signer's identity."""
        if not isinstance(bundle, dict):
            return False
        try:
            trusted = serialization.load_pem_public_key(trusted_public_key)
            if not isinstance(trusted, Ed25519PublicKey):
                return False
            public = trusted.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            if (
                bundle.get("algorithm") != "Ed25519"
                or bundle.get("schema_version") != 1
            ):
                return False
            if base64.b64decode(bundle["public_key"], validate=True) != public:
                return False
            if bundle["key_fingerprint"] != hashlib.sha256(public).hexdigest():
                return False
            signature = base64.b64decode(bundle["signature"], validate=True)
            trusted.verify(signature, cls.canonical_bytes(bundle["report"]))
            return True
        except (InvalidSignature, ValueError, TypeError, KeyError):
            return False
