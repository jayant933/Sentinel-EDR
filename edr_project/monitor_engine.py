"""
monitor_engine.py
-------------------
Orchestrates process/file/network monitoring + virus scanning +
behavior scoring on a repeating loop, running in a background thread
so the Flask dashboard stays responsive.

Workflow (matches the project spec):
    Process Monitor -> File Monitor -> Network Monitor ->
    Virus Detection -> Behavior Analysis -> Risk Score -> DB -> Dashboard
"""

import os
import threading
import time

import database
import process_monitor
import file_monitor
import network_monitor
import behavior_engine
import virus_scan

POLL_INTERVAL_SECONDS = 3

# Folders watched by the file monitor. Defaults to the user's home
# directory (read-only-safe, no need for admin/root). Override with
# the EDR_WATCH_PATHS env var (colon or comma separated) if desired.
DEFAULT_WATCH_PATHS = [os.path.expanduser("~")]


class MonitorEngine:
    def __init__(self, watch_paths=None):
        self.watch_paths = watch_paths or DEFAULT_WATCH_PATHS
        self._stop_event = threading.Event()
        self._thread = None
        self._observer = None

    def start(self):
        database.init_db()
        database.seed_known_hashes(virus_scan.DEFAULT_KNOWN_HASHES)

        process_monitor.prime()
        self._observer = file_monitor.start_watching(self.watch_paths)

        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as e:
                # Never let one bad tick kill the monitoring thread.
                database.log_event(None, "monitor_engine", "process", f"Monitor tick error: {e}", 0)
            time.sleep(POLL_INTERVAL_SECONDS)

    def _tick(self):
        # 1. Process monitor
        processes = process_monitor.snapshot()
        active_pids = set()

        for proc in processes:
            active_pids.add(proc["pid"])
            if proc["flags"]:
                added = behavior_engine.score_process_flags(proc["pid"], proc["name"], proc["flags"])
                if added:
                    row = next(
                        (r for r in database.get_all_process_risk() if r["pid"] == proc["pid"]),
                        None,
                    )
                    if row:
                        behavior_engine.raise_alert_if_needed(proc["pid"], proc["name"], row["risk_score"])

            # 4. Basic virus detection - hash the executable if we haven't
            # meaningfully flagged this process yet and it has a resolvable path.
            if proc.get("exe"):
                result = virus_scan.scan_file(proc["exe"])
                if result.get("malicious"):
                    behavior_engine.score_virus_result(proc["pid"], proc["name"], result)

        # 2. File monitor
        file_events = file_monitor.drain_events()
        behavior_engine.score_file_bursts(file_events)

        # 3. Network monitor
        per_process_conns, flagged_pids = network_monitor.snapshot()
        if flagged_pids:
            behavior_engine.score_network_flags(flagged_pids, per_process_conns)

        # Housekeeping: drop tracked processes that have exited
        database.cleanup_stale_processes(active_pids)
