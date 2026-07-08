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
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                pid INTEGER,
                process_name TEXT,
                threat_level TEXT,
                message TEXT
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
