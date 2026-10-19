from dataclasses import dataclass, field
from typing import Optional


SEVERITY_RANKS = {"Low": 1, "Medium": 2, "High": 3}


def normalize_severity(value: object) -> str:
    """Keep every displayed and persisted severity in the three-level scale."""
    label = str(value or "").strip().casefold()
    if label == "low":
        return "Low"
    if label == "high" or label == "critical":
        return "High"
    # Unknown engine labels are conservative review findings, not a fourth level.
    return "Medium"


@dataclass
class Threat:
    """Represents a threat identified during scanning."""

    name: str
    category: str
    severity: str = "Medium"
    description: str = ""
    source: str = "unknown"
    hash_value: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
