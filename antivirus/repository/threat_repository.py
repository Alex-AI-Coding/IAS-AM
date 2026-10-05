import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any

from antivirus.config.settings import THREAT_DB_PATH


class ThreatRepository:
    """Local SQLite repository for known malicious hashes and metadata."""

    def __init__(self, db_path: str | None = None):
        self.db_path = str(db_path or THREAT_DB_PATH)
        self._ensure_parent_directory()
        self._initialize()

    def _ensure_parent_directory(self) -> None:
        parent = Path(self.db_path).parent
        if parent and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)

    def _initialize(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT DEFAULT ''
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def add_threat(
        self,
        name: str,
        category: str,
        sha256: str,
        severity: str = "Medium",
        description: str = "",
    ) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                """
                INSERT OR REPLACE INTO threats (sha256, name, category, severity, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sha256, name, category, severity, description),
            )
            connection.commit()
        finally:
            connection.close()

    def find_by_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        connection = sqlite3.connect(self.db_path)
        try:
            row = connection.execute(
                """
                SELECT sha256, name, category, severity, description
                FROM threats
                WHERE sha256 = ?
                """,
                (sha256,),
            ).fetchone()
        finally:
            connection.close()

        if row is None:
            return None

        return {
            "sha256": row[0],
            "name": row[1],
            "category": row[2],
            "severity": row[3],
            "description": row[4],
        }
