from __future__ import annotations

from pathlib import Path
from typing import List

try:
    import yara
except ImportError:  # pragma: no cover - optional dependency
    yara = None


class YaraService:
    """Wrapper around YARA-based educational signature detection."""

    def __init__(self, rule_dir: str = "antivirus/detection/rules"):
        self.rule_dir = Path(rule_dir)
        self._compiler = None

        if yara is not None:
            self._load_rules()

    def _load_rules(self) -> None:
        if not self.rule_dir.exists():
            raise FileNotFoundError(f"YARA rule directory does not exist: {self.rule_dir}")

        rule_files = sorted(self.rule_dir.glob("*.yar"))
        if not rule_files:
            raise FileNotFoundError(f"No YARA rule files found in: {self.rule_dir}")

        file_map = {path.stem: str(path) for path in rule_files}
        self._compiler = yara.compile(filepaths=file_map)

    def scan_file(self, file_path: str) -> List[str]:
        return [match["name"] for match in self.scan_file_details(file_path)]

    def scan_file_details(self, file_path: str) -> List[dict]:
        if yara is None:
            return []

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if self._compiler is None:
            self._load_rules()

        matches = self._compiler.match(str(path))
        return [
            {"name": match.rule, "category": match.meta.get("category"), "severity": match.meta.get("severity")}
            for match in matches
        ]
