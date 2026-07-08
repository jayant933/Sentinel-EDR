"""
quarantine.py
--------------
Automatic quarantine SUGGESTION for High/Medium risk processes.

This does not silently kill anything on its own - the dashboard shows
a "Quarantine" button next to risky processes, the user confirms, and
only then does this module attempt to terminate the process.

Includes safety guards so the tool can't be used (accidentally or
otherwise) to kill critical OS processes or itself.
"""

import os
import time
import psutil
import database

# Process names that must never be terminated, regardless of risk score.
# Lowercased, without .exe, for case-insensitive comparison.
PROTECTED_NAMES = {
    "system", "system idle process", "wininit", "winlogon", "csrss",
    "smss", "services", "lsass", "svchost", "explorer", "dwm",
    "systemd", "init", "kernel_task", "launchd",
}

_self_pid = os.getpid()


def _is_protected(pid, name):
    if pid in (0, 4):
        return True
    if pid == _self_pid:
        return True
    clean_name = (name or "").lower().replace(".exe", "").strip()
    if clean_name in PROTECTED_NAMES:
        return True
    return False


def suggest_quarantine(pid):
    """
    Return a dict describing whether quarantining this pid is allowed,
    without actually doing it. Used to power the confirm dialog.
    """
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": pid, "allowed": False, "reason": "Process not found or access denied."}

    if _is_protected(pid, name):
        return {
            "pid": pid, "name": name, "allowed": False,
            "reason": f"'{name}' is a protected system process and cannot be quarantined by this tool.",
        }

    return {"pid": pid, "name": name, "allowed": True, "reason": None}


def quarantine_process(pid, terminate=True):
    """
    Attempt to quarantine (terminate) a process by PID.

    Returns a dict: {"success": bool, "message": str}
    Every attempt - successful or not - is logged to the database so
    it shows up in the event/alert history for auditability.
    """
    check = suggest_quarantine(pid)
    if not check["allowed"]:
        database.log_event(pid, check.get("name", "unknown"), "process",
                            f"Quarantine blocked: {check['reason']}", 0)
        return {"success": False, "message": check["reason"]}

    name = check["name"]

    try:
        proc = psutil.Process(pid)
        if terminate:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()  # escalate if it didn't terminate gracefully

        message = f"Process '{name}' (pid {pid}) was quarantined (terminated) by user action."
        database.log_event(pid, name, "process", message, 0)
        database.create_alert(pid, name, "High", message)
        return {"success": True, "message": message}

    except psutil.NoSuchProcess:
        message = f"Process '{name}' (pid {pid}) had already exited before quarantine."
        database.log_event(pid, name, "process", message, 0)
        return {"success": True, "message": message}

    except psutil.AccessDenied:
        message = f"Access denied - could not terminate '{name}' (pid {pid}). Try running as administrator."
        database.log_event(pid, name, "process", f"Quarantine failed: {message}", 0)
        return {"success": False, "message": message}

    except Exception as e:
        message = f"Unexpected error quarantining pid {pid}: {e}"
        database.log_event(pid, name, "process", message, 0)
        return {"success": False, "message": message}