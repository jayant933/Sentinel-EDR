"""
behavior_engine.py
--------------------
Module 5 - Behavior Analysis Engine.

Combines signals from process_monitor, file_monitor, network_monitor
and virus_scan into a single per-process risk score, following the
scoring table from the project spec:

    Unknown Process          -> +20
    High CPU Usage           -> +20
    Rapid File Modification  -> +30
    Multiple Network Conns   -> +30
    Known Malware Hash       -> risk_score forced to 100 (High)

    0-30  -> Low
    31-60 -> Medium
    61-100 -> High
"""

import time
import database
import notifier
import email_alerts

POINTS = {
    "new_process": 20,
    "high_cpu": 20,
    "high_memory": 15,
    "rapid_file_mod": 30,
    "many_network_conns": 30,
}

REASON_LABELS = {
    "new_process": "Unknown/new process",
    "high_cpu": "High CPU usage",
    "high_memory": "High memory usage",
    "rapid_file_mod": "Rapid file modification",
    "many_network_conns": "Multiple outbound network connections",
    "known_malware": "Known malware signature match",
}

# Sliding window for "rapid file modification" bursts
FILE_BURST_WINDOW_SECONDS = 10
FILE_BURST_THRESHOLD = 15  # events within the window across watched folders

_file_event_times = []


def score_process_flags(pid, name, flags):
    """Apply process-level flags (new_process, high_cpu, high_memory)."""
    if database.is_whitelisted(name):
        return 0

    total_added = 0
    for flag in flags:
        pts = POINTS.get(flag, 0)
        if pts:
            database.log_event(pid, name, "process", REASON_LABELS[flag], pts)
            database.upsert_process_risk(pid, name, pts, REASON_LABELS[flag])
            total_added += pts
    return total_added


def score_file_bursts(file_events):
    """
    file_events: list of dicts from file_monitor.drain_events()
    Since raw fs events aren't attributed to a PID, a detected burst is
    logged as a system-wide filesystem alert rather than tied to one pid.
    """
    global _file_event_times
    now = time.time()

    for ev in file_events:
        _file_event_times.append(ev["time"])

    # keep only recent timestamps
    _file_event_times = [t for t in _file_event_times if now - t <= FILE_BURST_WINDOW_SECONDS]

    if len(_file_event_times) >= FILE_BURST_THRESHOLD:
        database.log_event(
            None, "filesystem", "file",
            f"Rapid file modification burst: {len(_file_event_times)} events in "
            f"{FILE_BURST_WINDOW_SECONDS}s",
            POINTS["rapid_file_mod"],
        )
        msg = (
            f"Rapid file modification detected: {len(_file_event_times)} changes "
            f"in the last {FILE_BURST_WINDOW_SECONDS}s"
        )
        database.create_alert(None, "filesystem", "Medium", msg)
        notifier.notify("Rapid file modification", msg, "Medium", dedupe_key="filesystem_burst")
        # reset so we don't re-alert every tick while the burst continues
        _file_event_times = []
        return True
    return False


def score_network_flags(flagged_pids, per_process_conns):
    for pid in flagged_pids:
        import network_monitor
        name = network_monitor.process_name_for_pid(pid)
        if database.is_whitelisted(name):
            continue
        n_conns = len(per_process_conns.get(pid, []))
        detail = f"{REASON_LABELS['many_network_conns']} ({n_conns} active)"
        database.log_event(pid, name, "network", detail, POINTS["many_network_conns"])
        database.upsert_process_risk(pid, name, POINTS["many_network_conns"], REASON_LABELS["many_network_conns"])


def score_virus_result(pid, name, scan_result):
    """If a file matches a known malware hash, force risk to High (100)."""
    if scan_result and scan_result.get("malicious"):
        label = scan_result.get("label") or "Unknown signature"
        database.log_event(pid, name, "virus", f"Known malware match: {label}", 100)
        with_score = database.upsert_process_risk(
            pid, name, 100, REASON_LABELS["known_malware"], virus_result=f"Malicious ({label})"
        )
        msg = f"Known malware signature detected: {label}"
        database.create_alert(pid, name, "High", msg)
        notifier.notify(f"Malware detected: {name}", msg, "High", dedupe_key=f"virus_{pid}")
        email_alerts.send_alert(f"Malware detected: {name}", msg, dedupe_key=f"virus_{pid}")
        return with_score
    return None


def score_websites(website_events):
    """
    website_events: list of dicts from domain_monitor.snapshot()
    Classifies each visited domain and stores/updates it in the
    website_activity table (separate from process risk tracking).
    """
    import domain_monitor

    for ev in website_events:
        risk_level, reason = domain_monitor.classify_domain(ev["domain"])
        database.upsert_website(ev["domain"], ev["pid"], ev["process_name"], risk_level, reason)

        if risk_level == "High":
            msg = f"High-risk website contacted: {ev['domain']} (via {ev['process_name']})"
            database.log_event(ev["pid"], ev["process_name"], "network", msg, 30)
            database.create_alert(ev["pid"], ev["process_name"], "High", msg)
            notifier.notify("High-risk website", msg, "High", dedupe_key=f"site_{ev['domain']}")
            email_alerts.send_alert("High-risk website contacted", msg, dedupe_key=f"site_{ev['domain']}")


def raise_alert_if_needed(pid, name, score):
    """Fire a dashboard alert (and desktop notification / email) when a process crosses into Medium/High risk."""
    if score > 60:
        msg = f"{name} (pid {pid}) reached High risk (score {score})"
        database.create_alert(pid, name, "High", msg)
        notifier.notify(f"High risk process: {name}", msg, "High", dedupe_key=f"risk_{pid}")
        email_alerts.send_alert(f"High risk process: {name}", msg, dedupe_key=f"risk_{pid}")
    elif score > 30:
        msg = f"{name} (pid {pid}) reached Medium risk (score {score})"
        database.create_alert(pid, name, "Medium", msg)
        notifier.notify(f"Medium risk process: {name}", msg, "Medium", dedupe_key=f"risk_{pid}")