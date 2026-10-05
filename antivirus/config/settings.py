"""Application paths and lightweight environment-file loading."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_environment(env_path: str | Path | None = None) -> None:
    """Load simple ``KEY=value`` entries without an extra dependency.

    Existing environment variables always win. This is intentionally small but
    supports the common quoted values used by the project's optional ``.env``.
    """

    path = Path(env_path) if env_path else PROJECT_ROOT / ".env"
    if not path.is_file():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


load_environment()

BASE_DIR = Path(
    os.getenv("ANTIVIRUS_DATA_DIR", PROJECT_ROOT / "antivirus_data")
).expanduser()
RULE_DIR = Path(__file__).resolve().parents[1] / "detection" / "rules"
THREAT_DB_PATH = BASE_DIR / "threats.db"
SCAN_DB_PATH = BASE_DIR / "scan_history.db"


def positive_int(name: str, default: int) -> int:
    """Reject invalid resource limits early rather than silently disabling them."""
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


MAX_FILE_BYTES = positive_int("ANTIVIRUS_MAX_FILE_BYTES", 256 * 1024 * 1024)
MAX_SCAN_FILES = positive_int("ANTIVIRUS_MAX_SCAN_FILES", 25000)
YARA_TIMEOUT_SECONDS = positive_int("ANTIVIRUS_YARA_TIMEOUT", 10)
