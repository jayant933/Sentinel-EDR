"""
notifier.py
------------
Sends a desktop (OS-level) notification when the behavior engine
raises a High or Medium risk alert, using `plyer` (cross-platform:
Windows toast, macOS Notification Center, Linux notify-send).

Notifications are intentionally best-effort: if the OS backend isn't
available (e.g. running headless, or plyer has no backend on this
platform), we log to the console instead of crashing the monitor.
"""

import time

try:
    from plyer import notification as _plyer_notification
except ImportError:  # pragma: no cover - plyer should be installed, but don't hard-crash
    _plyer_notification = None

APP_NAME = "SENTINEL EDR"

# Avoid spamming the same pid+level notification repeatedly every poll tick.
_recent_notifications = {}
NOTIFY_COOLDOWN_SECONDS = 60


def notify(title, message, threat_level="Medium", dedupe_key=None):
    """
    Fire a desktop notification. `dedupe_key` (e.g. f"{pid}:{threat_level}")
    is used to avoid re-notifying about the same thing every poll cycle.
    """
    now = time.time()
    if dedupe_key:
        last = _recent_notifications.get(dedupe_key)
        if last and now - last < NOTIFY_COOLDOWN_SECONDS:
            return
        _recent_notifications[dedupe_key] = now

    full_title = f"{APP_NAME} - {threat_level} Risk"

    if _plyer_notification is None:
        print(f"[notifier] (no backend) {full_title}: {message}")
        return

    try:
        _plyer_notification.notify(
            title=full_title,
            message=message,
            app_name=APP_NAME,
            timeout=8,
        )
    except Exception as e:
        # Common on headless/sandboxed environments - never let this take
        # down the monitoring thread.
        print(f"[notifier] failed to send desktop notification: {e}")
        print(f"[notifier] {full_title}: {message}")
