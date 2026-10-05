import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from antivirus.config.settings import SCAN_DB_PATH


class ScanRepository:
    """Stores simple scan-history records in SQLite."""

    def __init__(self, db_path: str | None = None):
        self.db_path = str(db_path or SCAN_DB_PATH)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    file_count INTEGER NOT NULL,
                    threats_found INTEGER NOT NULL,
                    clean_files INTEGER NOT NULL,
                    error_files INTEGER NOT NULL,
                    status TEXT NOT NULL
                )
                """)
            existing_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(scan_history)")
            }
            migrations = {
                "target": "TEXT NOT NULL DEFAULT ''",
                "scan_type": "TEXT NOT NULL DEFAULT 'custom'",
                "duration": "REAL NOT NULL DEFAULT 0",
                "threats": "TEXT NOT NULL DEFAULT '[]'",
                "skipped_files": "INTEGER NOT NULL DEFAULT 0",
                "warnings": "TEXT NOT NULL DEFAULT '[]'",
            }
            for column, declaration in migrations.items():
                if column not in existing_columns:
                    connection.execute(
                        f"ALTER TABLE scan_history ADD COLUMN {column} {declaration}"
                    )
            connection.commit()
        finally:
            connection.close()

    def record_scan(
        self,
        file_count: int,
        threats_found: int,
        clean_files: int,
        error_files: int,
        status: str,
        started_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        target: str = "",
        scan_type: str = "custom",
        duration: float = 0.0,
        threats: Optional[List[Dict[str, Any]]] = None,
        skipped_files: int = 0,
        warnings: list[str] | None = None,
    ) -> Dict[str, Any]:
        import datetime

        started_value = started_at or datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(timespec="seconds")
        completed_value = completed_at or started_value

        connection = sqlite3.connect(self.db_path)
        try:
            cursor = connection.execute(
                """
                INSERT INTO scan_history (
                    started_at,
                    completed_at,
                    file_count,
                    threats_found,
                    clean_files,
                    error_files,
                    status,
                    target,
                    scan_type,
                    duration,
                    threats, skipped_files, warnings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    started_value,
                    completed_value,
                    file_count,
                    threats_found,
                    clean_files,
                    error_files,
                    status,
                    target,
                    scan_type,
                    duration,
                    json.dumps(threats or []),
                    skipped_files,
                    json.dumps(warnings or []),
                ),
            )
            connection.commit()
            row_id = cursor.lastrowid
        finally:
            connection.close()

        return {
            "id": row_id,
            "started_at": started_value,
            "completed_at": completed_value,
            "file_count": file_count,
            "threats_found": threats_found,
            "clean_files": clean_files,
            "error_files": error_files,
            "status": status,
            "target": target,
            "scan_type": scan_type,
            "duration": duration,
            "threats": threats or [],
            "skipped_files": skipped_files,
            "warnings": warnings or [],
        }

    def get_recent_scans(self, limit: int | None = 10) -> List[Dict[str, Any]]:
        connection = sqlite3.connect(self.db_path)
        try:
            rows = connection.execute(
                """
                SELECT id, started_at, completed_at, file_count, threats_found,
                       clean_files, error_files, status, target, scan_type, duration, threats,
                       skipped_files, warnings
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (-1 if limit is None else max(0, int(limit)),),
            ).fetchall()
        finally:
            connection.close()

        records = []
        for row in rows:
            try:
                threats = json.loads(row[11] or "[]")
            except (json.JSONDecodeError, TypeError):
                threats = []
            records.append(
                {
                    "id": row[0],
                    "started_at": row[1],
                    "completed_at": row[2],
                    "file_count": row[3],
                    "threats_found": row[4],
                    "clean_files": row[5],
                    "error_files": row[6],
                    "status": row[7],
                    "target": row[8],
                    "scan_type": row[9],
                    "duration": row[10],
                    "threats": threats,
                    "skipped_files": row[12],
                    "warnings": self._read_list(row[13]),
                }
            )
        return records

    @staticmethod
    def _read_list(value):
        try:
            parsed = json.loads(value or "[]")
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    def clear_history(self) -> int:
        """Delete scan-history rows and return the number removed."""

        connection = sqlite3.connect(self.db_path)
        try:
            count = connection.execute("SELECT COUNT(*) FROM scan_history").fetchone()[
                0
            ]
            connection.execute("DELETE FROM scan_history")
            connection.commit()
            return int(count)
        finally:
            connection.close()
