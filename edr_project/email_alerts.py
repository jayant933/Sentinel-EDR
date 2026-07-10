"""
email_alerts.py
-----------------
Sends an email when a High-risk threat is detected, using SMTP
(works out of the box with Gmail if you set up an "App Password" -
see README for setup steps).

Configuration lives in `email_config.py` (NOT committed to git - see
.gitignore) which you create from `email_config.example.py`. If that
file is missing or EMAIL_ENABLED is False, this module silently does
nothing (never crashes the monitor).
"""

import smtplib
import time
from email.mime.text import MIMEText

try:
    import email_config as cfg
except ImportError:
    cfg = None

# Avoid spamming the same alert repeatedly.
_recent_emails = {}
EMAIL_COOLDOWN_SECONDS = 300  # 5 minutes


def _enabled():
    return cfg is not None and getattr(cfg, "EMAIL_ENABLED", False)


def send_alert(subject, body, dedupe_key=None):
    if not _enabled():
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
        msg["From"] = cfg.SENDER_EMAIL
        msg["To"] = cfg.RECIPIENT_EMAIL

        with smtplib.SMTP(cfg.SMTP_SERVER, cfg.SMTP_PORT) as server:
            server.starttls()
            server.login(cfg.SENDER_EMAIL, cfg.SENDER_APP_PASSWORD)
            server.sendmail(cfg.SENDER_EMAIL, [cfg.RECIPIENT_EMAIL], msg.as_string())

        print(f"[email_alerts] sent: {subject}")
    except Exception as e:
        # Never let a broken email config take down the monitoring thread.
        print(f"[email_alerts] failed to send email: {e}")