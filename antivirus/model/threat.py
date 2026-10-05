from dataclasses import dataclass, field
from typing import Optional


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
