"""
process_monitor.py
--------------------
Module 1 - Process Monitoring.

Uses psutil to continuously watch running processes, their CPU/memory
usage, and flags newly-seen ("unknown") processes and unusually high
resource consumption.
"""

import time
import psutil

# Thresholds - tweak as needed
CPU_HIGH_THRESHOLD = 50.0      # percent
MEM_HIGH_THRESHOLD = 500       # MB

# Processes seen since this monitor started. Anything not in here the
# first time it's observed is treated as "new" for this session.
_known_pids = set()


def snapshot():
    """
    Take one snapshot of all running processes.

    Returns a list of dicts, one per process, and separately flags
    any behavior-of-interest for the behavior engine to score.
    """
    global _known_pids
    results = []
    current_pids = set()

    for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_info", "create_time"]):
        try:
            info = proc.info
            pid = info["pid"]
            current_pids.add(pid)

            cpu = proc.cpu_percent(interval=None)  # non-blocking, relies on caller cadence
            mem_mb = (info["memory_info"].rss / (1024 * 1024)) if info["memory_info"] else 0

            is_new = pid not in _known_pids

            flags = []
            if is_new:
                flags.append("new_process")
            if cpu >= CPU_HIGH_THRESHOLD:
                flags.append("high_cpu")
            if mem_mb >= MEM_HIGH_THRESHOLD:
                flags.append("high_memory")

            results.append({
                "pid": pid,
                "name": info["name"] or "unknown",
                "exe": info["exe"],
                "cpu_percent": round(cpu, 1),
                "memory_mb": round(mem_mb, 1),
                "create_time": info["create_time"],
                "flags": flags,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    _known_pids = current_pids
    return results


def prime():
    """
    Call once at startup to record the current process list as the
    'already known' baseline, so we don't flag every pre-existing
    process on the machine as 'new' the moment the monitor starts.
    Also warms up psutil's internal cpu_percent sampling.
    """
    global _known_pids
    _known_pids = set()
    for proc in psutil.process_iter(["pid"]):
        try:
            proc.cpu_percent(interval=None)
            _known_pids.add(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(1)  # let cpu_percent have a real interval to measure over
