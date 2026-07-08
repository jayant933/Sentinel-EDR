"""
network_monitor.py
--------------------
Module 3 - Network Monitoring.

Uses psutil to inspect active outbound network connections and which
process owns each one. Flags processes making an unusually high
number of simultaneous outbound connections.

For deeper packet-level verification during testing/development, the
project README suggests pairing this with Wireshark and Nmap - those
are external tools, not something this module drives directly.
"""

import psutil

OUTBOUND_CONNECTION_THRESHOLD = 10  # flag if a single process has more than this many


def snapshot():
    """
    Returns:
        per_process: dict[pid] -> list of connection dicts
        flagged_pids: set of pids exceeding the outbound connection threshold
    """
    per_process = {}

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # Some OSes require elevated privileges to see all connections.
        connections = []

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        pid = conn.pid
        if pid is None:
            continue

        per_process.setdefault(pid, []).append({
            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
            "status": conn.status,
        })

    flagged_pids = {pid for pid, conns in per_process.items() if len(conns) > OUTBOUND_CONNECTION_THRESHOLD}
    return per_process, flagged_pids


def process_name_for_pid(pid):
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"
