from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class QuarantineService:
    """Handles moving suspicious files into a protected quarantine area."""

    def __init__(self, quarantine_dir: str = "antivirus_data/quarantine", metadata_path: str | None = None):
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_path = Path(metadata_path) if metadata_path else self.quarantine_dir / "metadata.json"
        self.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.metadata_path.exists():
            self.metadata_path.write_text("[]", encoding="utf-8")

    def _read_metadata(self) -> List[Dict[str, Any]]:
        try:
            data = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        return data if isinstance(data, list) else []

    def _write_metadata(self, records: List[Dict[str, Any]]) -> None:
        self.metadata_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    def quarantine(self, source_path: str, threat_name: str, sha256: str | None = None) -> Dict[str, Any]:
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"File not found: {source_path}")

        unique_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        quarantine_path = self.quarantine_dir / f"{unique_id}_{source.name}"

        shutil.move(str(source), str(quarantine_path))

        record = {
            "id": unique_id,
            "original_path": str(source),
            "quarantine_path": str(quarantine_path),
            "sha256": sha256,
            "threat_name": threat_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        entries = self._read_metadata()
        entries.append(record)
        self._write_metadata(entries)
        return record

    def list_quarantined(self) -> List[Dict[str, Any]]:
        return self._read_metadata()

    def restore(self, record_id: str) -> Dict[str, Any]:
        entries = self._read_metadata()
        for entry in entries:
            if entry["id"] == record_id:
                quarantine_path = Path(entry["quarantine_path"])
                original_path = Path(entry["original_path"])
                original_path.parent.mkdir(parents=True, exist_ok=True)
                if quarantine_path.exists():
                    shutil.move(str(quarantine_path), str(original_path))
                    entries.remove(entry)
                    self._write_metadata(entries)
                    return {"restored": True, "path": original_path}
                return {"restored": False, "path": original_path, "reason": "quarantine file missing"}
        return {"restored": False, "path": None, "reason": "record not found"}

    def delete(self, record_id: str) -> bool:
        entries = self._read_metadata()
        for entry in entries:
            if entry["id"] == record_id:
                quarantine_path = Path(entry["quarantine_path"])
                if quarantine_path.exists():
                    quarantine_path.unlink()
                entries.remove(entry)
                self._write_metadata(entries)
                return True
        return False
