"""
email_alerts.py
-----------------
Sends an email when a High-risk threat is detected, using SMTP.

Settings are read from the database (configured via the dashboard's
"Email Alerts" panel - Settings > enter your email + App Password,
click Save). This means anyone who runs this project on their own
machine can set up alerts to their own inbox entirely through the UI,
no code editing required.

As a fallback (e.g. for scripted/headless setups), it will also read
from `email_config.py` if present and the database has nothing saved
yet - see email_config.example.py for that route.
"""

import smtplib
import time
from email.mime.text import MIMEText

import database

try:
    import email_config as _file_cfg
except ImportError:
    _file_cfg = None

# Avoid spamming the same alert repeatedly.
_recent_emails = {}
EMAIL_COOLDOWN_SECONDS = 300  # 5 minutes


def _get_active_settings():
    """Database settings take priority; falls back to email_config.py."""
    db_settings = database.get_email_settings()
    if db_settings["enabled"] and db_settings["sender_email"]:
        return db_settings

    if _file_cfg is not None and getattr(_file_cfg, "EMAIL_ENABLED", False):
        return {
            "enabled": True,
            "smtp_server": _file_cfg.SMTP_SERVER,
            "smtp_port": _file_cfg.SMTP_PORT,
            "sender_email": _file_cfg.SENDER_EMAIL,
            "sender_app_password": _file_cfg.SENDER_APP_PASSWORD,
            "recipient_email": _file_cfg.RECIPIENT_EMAIL,
        }

    return None


def send_alert(subject, body, dedupe_key=None):
    settings = _get_active_settings()
    if not settings:
        return

    now = time.time()
    if dedupe_key:
        last = _recent_emails.get(dedupe_key)
        if last and now - last < EMAIL_COOLDOWN_SECONDS:
            return
        _recent_emails[dedupe_key] = now

    try:
        msg = MIMEText(body)
        msg["Subject"] = f"[SENTINEL EDR] {subject}"
        msg["From"] = settings["sender_email"]
        msg["To"] = settings["recipient_email"]

        with smtplib.SMTP(settings["smtp_server"], settings["smtp_port"]) as server:
            server.starttls()
            server.login(settings["sender_email"], settings["sender_app_password"])
            server.sendmail(settings["sender_email"], [settings["recipient_email"]], msg.as_string())

        print(f"[email_alerts] sent: {subject}")
    except Exception as e:
        # Never let a broken email config take down the monitoring thread.
        print(f"[email_alerts] failed to send email: {e}")


def send_test_email():
    """Used by the dashboard's 'Send test email' button."""
    settings = _get_active_settings()
    if not settings:
        return {"success": False, "message": "Email alerts are not enabled/configured yet."}
    try:
        msg = MIMEText("This is a test email from your SENTINEL EDR dashboard. If you received this, email alerts are working!")
        msg["Subject"] = "[SENTINEL EDR] Test email"
        msg["From"] = settings["sender_email"]
        msg["To"] = settings["recipient_email"]

        with smtplib.SMTP(settings["smtp_server"], settings["smtp_port"]) as server:
            server.starttls()
            server.login(settings["sender_email"], settings["sender_app_password"])
            server.sendmail(settings["sender_email"], [settings["recipient_email"]], msg.as_string())

        return {"success": True, "message": f"Test email sent to {settings['recipient_email']}!"}
    except Exception as e:
        return {"success": False, "message": f"Failed to send: {e}"}