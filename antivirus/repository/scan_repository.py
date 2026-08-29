import sqlite3
from typing import Any, Dict, List, Optional


class ScanRepository:
    """Stores simple scan-history records in SQLite."""

    def __init__(self, db_path: str = "antivirus_data/scan_history.db"):
        self.db_path = db_path
        self._initialize()

    def _initialize(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            connection.execute(
                """
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
                """
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
    ) -> Dict[str, Any]:
        import datetime

        started_value = started_at or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
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
                    status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (started_value, completed_value, file_count, threats_found, clean_files, error_files, status),
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
        }

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        connection = sqlite3.connect(self.db_path)
        try:
            rows = connection.execute(
                """
                SELECT id, started_at, completed_at, file_count, threats_found, clean_files, error_files, status
                FROM scan_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            connection.close()

        return [
            {
                "id": row[0],
                "started_at": row[1],
                "completed_at": row[2],
                "file_count": row[3],
                "threats_found": row[4],
                "clean_files": row[5],
                "error_files": row[6],
                "status": row[7],
            }
            for row in rows
        ]
