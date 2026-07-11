"""
database.py
------------
SQLite database layer for the mini EDR system.

Handles schema creation and all read/write operations used by the
monitoring engine and the Flask dashboard.
"""

import sqlite3
import threading
import time
from contextlib import contextmanager

DB_PATH = "data/edr.db"

# SQLite connections are not thread-safe by default, so each thread
# that talks to the DB gets its own connection via this lock + factory.
_local = threading.local()
_write_lock = threading.Lock()


def _get_conn():
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, timeout=10)
        _local.conn.row_factory = sqlite3.Row
    return _local.conn


@contextmanager
def get_cursor(commit=False):
    conn = _get_conn()
    cur = conn.cursor()
    try:
        yield cur
        if commit:
            with _write_lock:
                conn.commit()
    finally:
        cur.close()


def init_db():
    """Create tables if they do not already exist."""
    with get_cursor(commit=True) as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                pid INTEGER,
                process_name TEXT,
                event_type TEXT,        -- process | file | network | virus
                detail TEXT,
                risk_points INTEGER DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS process_risk (
                pid INTEGER PRIMARY KEY,
                process_name TEXT,
                first_seen REAL,
                last_seen REAL,
                risk_score INTEGER DEFAULT 0,
                threat_level TEXT DEFAULT 'Low',
                reasons TEXT DEFAULT '',
                virus_result TEXT DEFAULT 'Clean'
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS known_malware_hashes (
                sha256 TEXT PRIMARY KEY,
                label TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS known_malicious_domains (
                domain TEXT PRIMARY KEY,
                label TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS website_activity (
                domain TEXT PRIMARY KEY,
                process_name TEXT,
                pid INTEGER,
                first_seen REAL,
                last_seen REAL,
                visit_count INTEGER DEFAULT 1,
                risk_level TEXT DEFAULT 'Low',
                reason TEXT DEFAULT ''
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                pid INTEGER,
                process_name TEXT,
                threat_level TEXT,
                message TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                process_name TEXT PRIMARY KEY,
                added_at REAL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                low_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                total_alerts INTEGER DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS email_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER DEFAULT 0,
                smtp_server TEXT DEFAULT 'smtp.gmail.com',
                smtp_port INTEGER DEFAULT 587,
                sender_email TEXT DEFAULT '',
                sender_app_password TEXT DEFAULT '',
                recipient_email TEXT DEFAULT ''
            )
        """)


def seed_known_hashes(hash_map):
    """hash_map: dict of {sha256: label}. Used to preload test signatures."""
    with get_cursor(commit=True) as cur:
        for h, label in hash_map.items():
            cur.execute(
                "INSERT OR IGNORE INTO known_malware_hashes (sha256, label) VALUES (?, ?)",
                (h, label),
            )


def is_known_malware(sha256_hash):
    with get_cursor() as cur:
        cur.execute(
            "SELECT label FROM known_malware_hashes WHERE sha256 = ?",
            (sha256_hash,),
        )
        row = cur.fetchone()
        return row["label"] if row else None


def seed_known_domains(domain_map):
    """domain_map: dict of {domain: label}. Used to preload test signatures."""
    with get_cursor(commit=True) as cur:
        for d, label in domain_map.items():
            cur.execute(
                "INSERT OR IGNORE INTO known_malicious_domains (domain, label) VALUES (?, ?)",
                (d, label),
            )


def is_known_malicious_domain(domain):
    with get_cursor() as cur:
        cur.execute(
            "SELECT label FROM known_malicious_domains WHERE domain = ?",
            (domain,),
        )
        row = cur.fetchone()
        return row["label"] if row else None


def upsert_website(domain, pid, process_name, risk_level, reason):
    now = time.time()
    with get_cursor(commit=True) as cur:
        cur.execute("SELECT * FROM website_activity WHERE domain = ?", (domain,))
        row = cur.fetchone()
        if row is None:
            cur.execute(
                """INSERT INTO website_activity
                   (domain, process_name, pid, first_seen, last_seen, visit_count, risk_level, reason)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                (domain, process_name, pid, now, now, risk_level, reason),
            )
        else:
            cur.execute(
                """UPDATE website_activity
                   SET last_seen = ?, visit_count = visit_count + 1, process_name = ?, pid = ?,
                       risk_level = ?, reason = ?
                   WHERE domain = ?""",
                (now, process_name, pid, risk_level, reason, domain),
            )


def get_all_websites():
    with get_cursor() as cur:
        cur.execute("SELECT * FROM website_activity ORDER BY last_seen DESC")
        return [dict(r) for r in cur.fetchall()]


def log_event(pid, process_name, event_type, detail, risk_points=0):
    with get_cursor(commit=True) as cur:
        cur.execute(
            """INSERT INTO events (timestamp, pid, process_name, event_type, detail, risk_points)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (time.time(), pid, process_name, event_type, detail, risk_points),
        )


def upsert_process_risk(pid, process_name, add_points, reason, virus_result=None):
    """Add risk points to a process's running total and recompute its threat level."""
    now = time.time()
    with get_cursor(commit=True) as cur:
        cur.execute("SELECT * FROM process_risk WHERE pid = ?", (pid,))
        row = cur.fetchone()

        if row is None:
            score = max(0, min(100, add_points))
            reasons = reason
            v_result = virus_result or "Clean"
            cur.execute(
                """INSERT INTO process_risk
                   (pid, process_name, first_seen, last_seen, risk_score, threat_level, reasons, virus_result)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (pid, process_name, now, now, score, _level(score), reasons, v_result),
            )
        else:
            score = max(0, min(100, row["risk_score"] + add_points))
            reasons_set = set(filter(None, row["reasons"].split(";"))) if row["reasons"] else set()
            if reason:
                reasons_set.add(reason)
            reasons = ";".join(sorted(reasons_set))
            v_result = virus_result or row["virus_result"]
            cur.execute(
                """UPDATE process_risk
                   SET last_seen = ?, risk_score = ?, threat_level = ?, reasons = ?, virus_result = ?
                   WHERE pid = ?""",
                (now, score, _level(score), reasons, v_result, pid),
            )
        return score


def _level(score):
    if score <= 30:
        return "Low"
    elif score <= 60:
        return "Medium"
    else:
        return "High"


def create_alert(pid, process_name, threat_level, message):
    with get_cursor(commit=True) as cur:
        cur.execute(
            """INSERT INTO alerts (timestamp, pid, process_name, threat_level, message)
               VALUES (?, ?, ?, ?, ?)""",
            (time.time(), pid, process_name, threat_level, message),
        )


def get_recent_events(limit=50):
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def get_recent_alerts(limit=20):
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def get_all_process_risk():
    with get_cursor() as cur:
        cur.execute("SELECT * FROM process_risk ORDER BY risk_score DESC")
        return [dict(r) for r in cur.fetchall()]


def get_risk_distribution():
    with get_cursor() as cur:
        cur.execute("SELECT threat_level, COUNT(*) as c FROM process_risk GROUP BY threat_level")
        dist = {"Low": 0, "Medium": 0, "High": 0}
        for r in cur.fetchall():
            dist[r["threat_level"]] = r["c"]
        return dist


def cleanup_stale_processes(active_pids):
    """Remove process_risk rows for processes that are no longer running,
    so old exited processes don't clutter the dashboard forever."""
    if not active_pids:
        return
    with get_cursor(commit=True) as cur:
        cur.execute("SELECT pid FROM process_risk")
        tracked = [r["pid"] for r in cur.fetchall()]
        stale = [p for p in tracked if p not in active_pids]
        for p in stale:
            cur.execute("DELETE FROM process_risk WHERE pid = ?", (p,))


# ---------------------------------------------------------------- Whitelist ----

def add_to_whitelist(process_name):
    clean = process_name.strip().lower()
    with get_cursor(commit=True) as cur:
        cur.execute(
            "INSERT OR IGNORE INTO whitelist (process_name, added_at) VALUES (?, ?)",
            (clean, time.time()),
        )
        # A trusted process shouldn't linger in the flagged-process table either.
        cur.execute("DELETE FROM process_risk WHERE LOWER(process_name) = ?", (clean,))


def remove_from_whitelist(process_name):
    clean = process_name.strip().lower()
    with get_cursor(commit=True) as cur:
        cur.execute("DELETE FROM whitelist WHERE process_name = ?", (clean,))


def is_whitelisted(process_name):
    if not process_name:
        return False
    clean = process_name.strip().lower()
    with get_cursor() as cur:
        cur.execute("SELECT 1 FROM whitelist WHERE process_name = ?", (clean,))
        return cur.fetchone() is not None


def get_whitelist():
    with get_cursor() as cur:
        cur.execute("SELECT * FROM whitelist ORDER BY added_at DESC")
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------- Risk history ----

def record_risk_snapshot():
    """Called periodically by the monitor loop to log a point-in-time
    summary of the risk distribution, powering the historical trend chart."""
    dist = get_risk_distribution()
    total_alerts = len(get_recent_alerts(limit=100000))
    with get_cursor(commit=True) as cur:
        cur.execute(
            """INSERT INTO risk_history (timestamp, low_count, medium_count, high_count, total_alerts)
               VALUES (?, ?, ?, ?, ?)""",
            (time.time(), dist.get("Low", 0), dist.get("Medium", 0), dist.get("High", 0), total_alerts),
        )
        # Keep the table from growing forever - retain the most recent 500 points.
        cur.execute("""
            DELETE FROM risk_history WHERE id NOT IN (
                SELECT id FROM risk_history ORDER BY id DESC LIMIT 500
            )
        """)


def get_risk_history(limit=100):
    with get_cursor() as cur:
        cur.execute("SELECT * FROM risk_history ORDER BY id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        return list(reversed(rows))  # chronological order for charting


# ---------------------------------------------------------------- Email settings ----

def get_email_settings():
    with get_cursor() as cur:
        cur.execute("SELECT * FROM email_settings WHERE id = 1")
        row = cur.fetchone()
        if row is None:
            return {
                "enabled": False, "smtp_server": "smtp.gmail.com", "smtp_port": 587,
                "sender_email": "", "sender_app_password": "", "recipient_email": "",
            }
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        return d


def save_email_settings(enabled, smtp_server, smtp_port, sender_email, sender_app_password, recipient_email):
    with get_cursor(commit=True) as cur:
        cur.execute(
            """INSERT INTO email_settings (id, enabled, smtp_server, smtp_port, sender_email, sender_app_password, recipient_email)
               VALUES (1, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   enabled=excluded.enabled, smtp_server=excluded.smtp_server, smtp_port=excluded.smtp_port,
                   sender_email=excluded.sender_email, sender_app_password=excluded.sender_app_password,
                   recipient_email=excluded.recipient_email""",
            (int(enabled), smtp_server, smtp_port, sender_email, sender_app_password, recipient_email),
        )