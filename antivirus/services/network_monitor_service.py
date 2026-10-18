"""Connection inventory and explicit process termination for selected connections."""

from __future__ import annotations

import ipaddress
import os
import socket
from datetime import datetime
from functools import lru_cache

import psutil


@lru_cache(maxsize=512)
def _reverse_dns_name(address):
    try:
        return socket.gethostbyaddr(address)[0]
    except (socket.herror, socket.gaierror):
        return "No reverse-DNS name"
    except OSError:
        return "Reverse-DNS lookup failed"


class NetworkMonitorService:
    @staticmethod
    def connections():
        rows = []
        process_cache = {}
        for connection in psutil.net_connections(kind="inet"):
            if not connection.raddr:
                continue
            pid = connection.pid
            if pid not in process_cache:
                process_details = {
                    "process": "Unavailable",
                    "process_create_time": None,
                    "executable_path": "Unavailable",
                    "username": "Unavailable",
                }
                if pid:
                    try:
                        process = psutil.Process(pid)
                        process_details["process"] = process.name()
                        process_details["process_create_time"] = process.create_time()
                        try:
                            process_details["executable_path"] = process.exe()
                        except psutil.AccessDenied:
                            process_details["executable_path"] = "Access denied"
                        try:
                            process_details["username"] = process.username()
                        except psutil.AccessDenied:
                            process_details["username"] = "Access denied"
                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        psutil.ZombieProcess,
                    ):
                        process_details["process"] = "Process unavailable"
                        process_details["executable_path"] = "Process unavailable"
                        process_details["username"] = "Process unavailable"
                process_cache[pid] = process_details

            process_details = process_cache[pid]
            name = process_details["process"]
            process_create_time = process_details["process_create_time"]
            executable_path = process_details["executable_path"]
            username = process_details["username"]
            address = connection.raddr.ip
            local_address = connection.laddr.ip if connection.laddr else "—"
            local_port = connection.laddr.port if connection.laddr else None
            remote_port = connection.raddr.port
            if ":" in address:
                formatted_address = f"[{address}]"
            else:
                formatted_address = address
            if ":" in local_address:
                local_address = f"[{local_address}]"

            remote_host = _reverse_dns_name(address)

            try:
                remote_ip = ipaddress.ip_address(address)
            except ValueError:
                address_scope = "Unrecognized IP address"
            else:
                if remote_ip.is_loopback:
                    address_scope = "Loopback device"
                elif remote_ip.is_link_local:
                    address_scope = "Link-local network"
                elif remote_ip.is_reserved:
                    address_scope = "Special-use address"
                elif remote_ip.is_private:
                    address_scope = "Private network"
                elif remote_ip.is_global:
                    address_scope = "Public internet"
                else:
                    address_scope = "Special-use address"

            if connection.type == socket.SOCK_STREAM:
                protocol = "TCP"
                direction = (
                    "Likely outbound"
                    if connection.status == psutil.CONN_ESTABLISHED
                    and local_port is not None
                    and local_port >= 49152
                    else "Unclear from connection snapshot"
                )
            else:
                protocol = "UDP"
                direction = "Unclear; UDP has no connection handshake"

            rows.append(
                {
                    "process": name,
                    "pid": pid,
                    "protocol": protocol,
                    "local_endpoint": (
                        f"{local_address}:{local_port}"
                        if local_port is not None
                        else "Unavailable"
                    ),
                    "endpoint": f"{formatted_address}:{remote_port}",
                    "remote_host": remote_host,
                    "state": connection.status,
                    "process_create_time": process_create_time,
                    "process_start_time": (
                        datetime.fromtimestamp(process_create_time)
                        .astimezone()
                        .strftime("%Y-%m-%d %H:%M:%S %Z")
                        if process_create_time is not None
                        else "Unavailable"
                    ),
                    "executable_path": executable_path,
                    "username": username,
                    "direction": direction,
                    "address_scope": address_scope,
                    "remote_port": remote_port,
                }
            )
        return sorted(rows, key=lambda row: (row["process"].lower(), row["endpoint"]))

    @staticmethod
    def terminate_processes(connections: list[dict]) -> list[dict]:
        """Terminate each selected connection's owning process at most once."""
        results = []
        seen_pids = set()
        for connection in connections:
            pid = connection.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                results.append(
                    {
                        "pid": pid,
                        "success": False,
                        "message": "The owning process could not be identified.",
                    }
                )
                continue
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            if pid == os.getpid():
                results.append(
                    {
                        "pid": pid,
                        "success": False,
                        "message": "The security application cannot terminate itself.",
                    }
                )
                continue

            expected_create_time = connection.get("process_create_time")
            if expected_create_time is None:
                results.append(
                    {
                        "pid": pid,
                        "success": False,
                        "message": "Process identity is unavailable. Refresh connections and try again.",
                    }
                )
                continue

            try:
                process = psutil.Process(pid)
                if process.create_time() != expected_create_time:
                    results.append(
                        {
                            "pid": pid,
                            "success": False,
                            "message": "The process changed since the connection snapshot. Refresh and try again.",
                        }
                    )
                    continue
                process.terminate()
            except psutil.NoSuchProcess:
                results.append(
                    {
                        "pid": pid,
                        "success": False,
                        "message": "The process has already exited.",
                    }
                )
            except (psutil.AccessDenied, psutil.ZombieProcess) as exc:
                results.append(
                    {
                        "pid": pid,
                        "success": False,
                        "message": f"The process could not be terminated: {exc}",
                    }
                )
            else:
                results.append(
                    {
                        "pid": pid,
                        "success": True,
                        "message": "Termination requested.",
                    }
                )
        return results
