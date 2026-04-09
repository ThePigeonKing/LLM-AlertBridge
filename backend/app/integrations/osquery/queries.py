"""Predefined osquery SQL queries and alert-type-based selection logic."""

from typing import Any

QUERIES: dict[str, str] = {
    "running_processes": (
        "SELECT pid, name, path, cmdline, uid, start_time "
        "FROM processes ORDER BY start_time DESC LIMIT 100"
    ),
    "open_connections": (
        "SELECT pid, local_address, local_port, remote_address, remote_port, "
        "state, protocol FROM process_open_sockets "
        "WHERE state = 'ESTABLISHED' OR state = 'LISTEN'"
    ),
    "listening_ports": (
        "SELECT pid, port, protocol, address FROM listening_ports"
    ),
    "logged_in_users": (
        "SELECT user, host, time, tty, type FROM logged_in_users"
    ),
    "crontabs": (
        "SELECT command, path, minute, hour, day_of_month, month, day_of_week "
        "FROM crontab"
    ),
    "suid_binaries": (
        "SELECT path, username, permissions, directory FROM suid_bin"
    ),
    "file_events": (
        "SELECT target_path, action, time, category "
        "FROM file_events ORDER BY time DESC LIMIT 50"
    ),
}

_ALERT_TYPE_QUERIES: dict[str, list[str]] = {
    "authentication": ["running_processes", "logged_in_users", "open_connections"],
    "syscheck": ["running_processes", "file_events", "crontabs"],
    "web": ["running_processes", "open_connections", "listening_ports"],
    "rootcheck": ["running_processes", "suid_binaries", "crontabs"],
    "audit": ["running_processes", "open_connections", "logged_in_users"],
    "default": ["running_processes", "open_connections", "logged_in_users"],
}

_GROUP_KEYWORDS: dict[str, list[str]] = {
    "authentication": ["ssh", "auth", "login", "authentication"],
    "syscheck": ["syscheck"],
    "web": ["web", "access"],
    "rootcheck": ["rootcheck"],
    "audit": ["audit"],
}


def select_queries_for_alert(normalized_data: dict[str, Any]) -> dict[str, str]:
    """Select relevant osquery queries based on the alert's rule groups."""
    groups = normalized_data.get("rule_groups", [])

    selected_type = "default"
    for group in groups:
        group_lower = group.lower()
        for alert_type, keywords in _GROUP_KEYWORDS.items():
            if any(kw in group_lower for kw in keywords):
                selected_type = alert_type
                break
        if selected_type != "default":
            break

    query_names = _ALERT_TYPE_QUERIES[selected_type]
    return {name: QUERIES[name] for name in query_names}
