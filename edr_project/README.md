# SENTINEL — Endpoint Detection & Response (EDR) System

An educational, defensive-security project that monitors a computer in
real time, detects suspicious process/file/network behavior, does
basic signature-based virus detection, calculates a risk score, and
shows everything on a live Flask dashboard.

**This is not a replacement for a real antivirus/EDR product.** It's a
practical demonstration of core EDR concepts.

---

# SENTINEL — Mini Endpoint Detection & Response (EDR) System

An educational, defensive-security project that monitors a computer in
real time, detects suspicious process/file/network behavior, does
basic signature-based virus detection, calculates a risk score, and
shows everything on a live Flask dashboard.

**This is not a replacement for a real antivirus/EDR product.** It's a
practical demonstration of core EDR concepts.

---

## Features

- **Process monitoring** (`process_monitor.py`) — tracks running processes, CPU/memory usage, flags new/unknown processes via `psutil`.
- **File monitoring** (`file_monitor.py`) — watches folders for create/modify/delete/rename bursts via `watchdog`.
- **Network monitoring** (`network_monitor.py`) — flags processes with an unusually high number of outbound connections via `psutil`.
- **Website activity monitoring** (`domain_monitor.py`) — resolves the IPs your browser (Chrome/Edge/Firefox/Brave/Opera) is talking to into website domain names (reverse DNS), then classifies each as Low (known-trusted domain), Medium (unrecognized), or High (matches a known-malicious domain signature). Shown in its own "Website Activity" panel on the dashboard, separate from the process table.
- **Basic virus detection** (`virus_scan.py`) — SHA-256 hashes running executables and compares against a local table of known-malicious hashes (signature-based). Seeded by default with the harmless [EICAR test signature](https://en.wikipedia.org/wiki/EICAR_test_file) so you have something safe to test detection with.
- **Behavior analysis engine** (`behavior_engine.py`) — turns flags into a 0–100 risk score per process (Low / Medium / High) and raises alerts.
- **SQLite database** (`database.py`) — stores every event, per-process risk, and alert history.
- **Flask dashboard** (`app.py`, `templates/`, `static/`) — live-updating view of processes, risk distribution, event log, and alerts.
- **Threat reports** (`report_generator.py`) — one-click **Export CSV** / **Export PDF** buttons on the dashboard generate a report of tracked processes, alerts, and recent events.
- **Desktop notifications** (`notifier.py`) — fires an OS-level notification (Windows toast / macOS Notification Center / Linux notify-send, via `plyer`) whenever a process crosses into Medium/High risk, a known-malware hash matches, or a rapid file-modification burst is detected. Falls back to a console log if no notification backend is available (e.g. headless servers).
- **Quarantine suggestions** (`quarantine.py`) — a "Quarantine" button appears next to Medium/High risk processes on the dashboard. Clicking it asks for confirmation, then terminates the process. Built-in safety guards refuse to quarantine critical OS processes (`system`, `explorer`, `svchost`, `lsass`, etc.) or the EDR tool's own process.
- **Email alerts** (`email_alerts.py` + dashboard "Email Alerts" panel) — sends an email when a High-risk threat is detected (malware match, high-risk website, or High-risk process). Configured entirely through the dashboard UI (enter your email + Gmail App Password, click Save) — no code editing needed. Each person who runs this project locally sets up alerts to their own inbox. See "Email alert setup" below.
- **Whitelist / Trusted Apps** (part of `database.py` + dashboard) — click "Trust" next to any process (or add its name manually in the "Trusted Apps" panel) to stop it from ever being flagged again. Trusted processes are skipped entirely by the behavior engine.
- **Risk trend chart** — the dashboard's "Risk Trend" panel charts Low/Medium/High counts over time (last ~100 samples, taken every poll interval), so you can see whether things are getting better or worse at a glance.
- **Welcome / setup screen** — the first time anyone opens the dashboard, they're asked for their name and email before seeing the monitor. This personalizes the dashboard and pre-fills the Email Alerts recipient - stored locally only, nothing is sent anywhere.



## Project workflow

```
Computer Start → Monitoring Engine Start → Process Monitor → File Monitor
→ Network Monitor → Virus Detection → Behavior Analysis → Risk Score
→ SQLite Database → Flask Dashboard → Alert User
```

---


## Setup

### Windows (PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open in browser:

http://127.0.0.1:5000

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open in browser:

http://127.0.0.1:5000

## Optional: HTTPS for Local Development

If you configure a local SSL certificate (for example, using `mkcert`), you can run the application over HTTPS and access it at:

https://localhost:5000

## Email alert setup (optional)

Email alerts are off by default and are configured per-person, entirely through the dashboard - no code editing required:

1. Run the app and open the dashboard (`http://127.0.0.1:5000`).
2. Scroll to the **"Email Alerts"** panel.
3. If using Gmail: turn on [2-Step Verification](https://myaccount.google.com/security), then create an [App Password](https://myaccount.google.com/apppasswords) (App: "Mail", Device: "Other").
4. In the panel, check "Enable email alerts", enter your email as the sender, paste the 16-character App Password (not your real Gmail password), and set the recipient email (can be the same address).
5. Click **Save**, then **Send test email** to confirm it works.

Settings are stored in your local `data/edr.db` (gitignored, never leaves your machine). Emails are rate-limited to at most one per alert type every 5 minutes to avoid spam.

*(Advanced/scripted setups can alternatively use `email_config.py` - copy `email_config.example.py` and fill it in; the dashboard settings take priority if both are present.)*

## Testing virus detection

The database is seeded with the hash of the standard **EICAR test
string** — an industry-standard, completely harmless file that every
real antivirus is designed to flag. To test detection end-to-end:

```bash
python -c "open('eicar_test.com','w').write(r'X5O!P%@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*')"
```

Making that file executable and running it briefly will cause the
process monitor to hash it and the dashboard will show a **High risk
/ Known malware match** alert. Delete the file afterwards — it's inert
but some antivirus tools will also flag/quarantine it on sight.

## Adding more known-malware hashes

Known-malicious SHA-256 hashes live in the `known_malware_hashes`
table. Add more via `database.seed_known_hashes({sha256: label, ...})`
in `monitor_engine.py`, or insert rows directly.

---

## Project structure

```
edr_project/
├── app.py                # Flask app + API routes
├── monitor_engine.py      # Orchestrates the monitoring loop
├── process_monitor.py     # Module 1
├── file_monitor.py        # Module 2
├── network_monitor.py     # Module 3
├── virus_scan.py          # Module 4
├── behavior_engine.py      # Module 5
├── database.py             # Module 6 (SQLite)
├── templates/
│   └── dashboard.html      # Module 7 (dashboard UI)
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── data/edr.db              # created on first run
└── requirements.txt
```

## Known limitations (by design — this is an educational project)

- File-system events aren't attributed to a specific PID on most OSes without OS-level APIs (ETW/fanotify/auditd), so "rapid file modification" is detected system-wide rather than per-process.
- The malware hash database is a small local table you seed yourself — it is **not** connected to any live threat-intelligence feed.
- Detection is signature + heuristic based, not ML-based (see "Future Scope" for planned extensions).
- Some `psutil` calls (e.g. `net_connections`) may need elevated privileges on some OSes to see all connections.

## Future scope

- Machine-learning based behavior analysis
- Cloud log integration
- Email/desktop notifications
- Automatic quarantine suggestions
- Threat report generation (PDF/CSV)
- Cloud endpoint monitoring

## Goal

This project's objective is **not** to create malware or perform
attacks. It exists to demonstrate endpoint monitoring, basic virus
detection, and behavior-based threat detection concepts for
educational, defensive-security purposes.
