"""Connection inventory, not packet capture or a malware verdict."""

from __future__ import annotations

import socket
import psutil


class NetworkMonitorService:
    @staticmethod
    def connections():
        rows = []
        for connection in psutil.net_connections(kind="inet"):
            if not connection.raddr:
                continue
            name = "Unavailable"
            if connection.pid:
                try:
                    name = psutil.Process(connection.pid).name()
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    pass
            address = connection.raddr.ip
            if ":" in address:
                address = f"[{address}]"
            rows.append(
                {
                    "process": name,
                    "pid": connection.pid,
                    "protocol": (
                        "TCP" if connection.type == socket.SOCK_STREAM else "UDP"
                    ),
                    "endpoint": f"{address}:{connection.raddr.port}",
                    "state": connection.status,
                }
            )
        return sorted(rows, key=lambda row: (row["process"].lower(), row["endpoint"]))
