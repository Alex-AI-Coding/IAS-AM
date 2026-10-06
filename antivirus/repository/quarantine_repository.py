"""SQLite quarantine catalogue; payloads and key material are never scan history."""

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import re

from antivirus.model.quarantine_item import QuarantineItem, STATES


class QuarantineRepository:
    def __init__(self, path):
        self.path = str(path)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS quarantine (
                    entry_id TEXT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    threats TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    state TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    restored_path TEXT NOT NULL DEFAULT '',
                    error_message TEXT NOT NULL DEFAULT ''
                )""")
            connection.execute(
                "UPDATE quarantine SET state='incomplete', error_message=? WHERE state='pending'",
                (
                    "Preparation was interrupted. The original was not removed by this step.",
                ),
            )

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _item(row):
        if row is None:
            raise KeyError("Quarantine item was not found.")
        values = dict(row)
        values["threats"] = json.loads(values["threats"])
        if (
            not re.fullmatch(r"[0-9a-f]{32}", values["entry_id"])
            or not re.fullmatch(r"[0-9a-f]{64}", values["sha256"])
            or not isinstance(values["file_size"], int)
            or values["file_size"] < 0
            or values["state"] not in STATES
            or not isinstance(values["threats"], list)
            or not values["threats"]
            or any(
                not isinstance(threat, dict)
                or any(
                    not isinstance(threat.get(key), str)
                    for key in ("name", "category", "severity", "source", "description")
                )
                for threat in values["threats"]
            )
        ):
            raise ValueError(
                "The quarantine catalogue contains invalid evidence. Files were left intact."
            )
        return QuarantineItem(**values)

    def add(self, item):
        values = asdict(item)
        values["threats"] = json.dumps(item.threats)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO quarantine VALUES (:entry_id,:original_path,:sha256,:file_size,"
                ":threats,:added_at,:state,:updated_at,:restored_path,:error_message)",
                values,
            )

    def get(self, entry_id):
        with self._connect() as connection:
            return self._item(
                connection.execute(
                    "SELECT * FROM quarantine WHERE entry_id=?", (entry_id,)
                ).fetchone()
            )

    def items(self):
        with self._connect() as connection:
            return [
                self._item(row)
                for row in connection.execute(
                    "SELECT * FROM quarantine ORDER BY added_at DESC, entry_id"
                )
            ]

    def update_state(self, entry_id, state, error_message="", restored_path=None):
        if state not in STATES:
            raise ValueError("Invalid quarantine state.")
        updated = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                "UPDATE quarantine SET state=?, updated_at=?, error_message=?, "
                "restored_path=COALESCE(?,restored_path) WHERE entry_id=?",
                (state, updated, error_message, restored_path, entry_id),
            )
        return self.get(entry_id)
