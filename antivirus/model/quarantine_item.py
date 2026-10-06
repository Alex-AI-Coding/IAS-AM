"""Persistent quarantine evidence, separate from the original scan verdict."""

from dataclasses import dataclass, field
import json

STATES = {
    "pending": "Preparing",
    "active": "Isolated",
    "copy_retained": "Removal unconfirmed",
    "incomplete": "Needs review",
    "restored": "Restored · backup held",
    "deleting": "Deletion pending",
    "deleted": "Deleted",
}


@dataclass
class QuarantineItem:
    entry_id: str
    original_path: str
    sha256: str
    file_size: int
    threats: list[dict] = field(default_factory=list)
    added_at: str = ""
    state: str = "pending"
    updated_at: str = ""
    restored_path: str = ""
    error_message: str = ""

    @property
    def categories(self):
        return ", ".join(
            dict.fromkeys(t.get("category") or "Unknown" for t in self.threats)
        )

    @property
    def severity(self):
        ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        labels = [str(t.get("severity", "unknown")).casefold() for t in self.threats]
        if not labels or any(label not in ranks for label in labels):
            return "Unknown"
        return max(labels, key=ranks.get).title()

    @property
    def state_label(self):
        return STATES.get(self.state, "Needs review")

    def authenticated_metadata(self):
        # Mutable lifecycle fields deliberately do not alter the cryptographic binding.
        return json.dumps(
            {
                "version": 1,
                "id": self.entry_id,
                "path": self.original_path,
                "sha256": self.sha256,
                "size": self.file_size,
                "threats": self.threats,
                "added_at": self.added_at,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
