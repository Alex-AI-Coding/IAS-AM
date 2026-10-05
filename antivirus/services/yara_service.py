from __future__ import annotations

from pathlib import Path
from typing import List
from antivirus.config.settings import RULE_DIR, YARA_TIMEOUT_SECONDS

try:
    import yara
except ImportError:  # pragma: no cover - optional dependency
    yara = None


class YaraService:
    """Wrapper around YARA-based educational signature detection."""

    def __init__(self, rule_dir: str = str(RULE_DIR)):
        self.rule_dir = Path(rule_dir)
        self._compiler = None
        self.error_message = None

        if yara is not None:
            try:
                self._load_rules()
            except (OSError, yara.Error) as exc:
                self.error_message = str(exc)

    def _load_rules(self) -> None:
        if not self.rule_dir.exists():
            raise FileNotFoundError(
                f"YARA rule directory does not exist: {self.rule_dir}"
            )

        rule_files = sorted(self.rule_dir.glob("*.yar"))
        if not rule_files:
            raise FileNotFoundError(f"No YARA rule files found in: {self.rule_dir}")

        file_map = {path.stem: str(path) for path in rule_files}
        self._compiler = yara.compile(filepaths=file_map)

    def scan_file(self, file_path: str) -> List[str]:
        return [match["name"] for match in self.scan_file_details(file_path)]

    def scan_file_details(self, file_path: str) -> List[dict]:
        if yara is None:
            raise RuntimeError(
                "YARA is not installed; signature checking is unavailable."
            )

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if self._compiler is None:
            self._load_rules()

        matches = self._compiler.match(str(path), timeout=YARA_TIMEOUT_SECONDS)
        return [
            {
                "name": match.rule,
                "category": match.meta.get("category"),
                "severity": match.meta.get("severity"),
            }
            for match in matches
        ]
