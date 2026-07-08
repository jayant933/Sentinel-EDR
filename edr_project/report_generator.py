"""
report_generator.py
---------------------
Generates downloadable threat reports (CSV and PDF) from the data
already collected in the SQLite database - process risk table, recent
events, and alert history.
"""

import csv
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)

import database


def _fmt_time(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- CSV ----

def generate_csv():
    """Return a CSV report (as a string) with three sections: processes, alerts, events."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow([f"SENTINEL EDR Threat Report - generated {_fmt_time(datetime.now().timestamp())}"])
    writer.writerow([])

    writer.writerow(["-- Process Risk Summary --"])
    writer.writerow(["PID", "Process Name", "Risk Score", "Threat Level", "Reasons", "Virus Scan Result", "First Seen", "Last Seen"])
    for p in database.get_all_process_risk():
        writer.writerow([
            p["pid"], p["process_name"], p["risk_score"], p["threat_level"],
            (p["reasons"] or "").replace(";", ", "), p["virus_result"],
            _fmt_time(p["first_seen"]), _fmt_time(p["last_seen"]),
        ])

    writer.writerow([])
    writer.writerow(["-- Alerts --"])
    writer.writerow(["Time", "PID", "Process Name", "Threat Level", "Message"])
    for a in database.get_recent_alerts(limit=500):
        writer.writerow([_fmt_time(a["timestamp"]), a["pid"] or "-", a["process_name"], a["threat_level"], a["message"]])

    writer.writerow([])
    writer.writerow(["-- Recent Events --"])
    writer.writerow(["Time", "PID", "Process Name", "Event Type", "Detail", "Risk Points"])
    for e in database.get_recent_events(limit=500):
        writer.writerow([_fmt_time(e["timestamp"]), e["pid"] or "-", e["process_name"], e["event_type"], e["detail"], e["risk_points"]])

    return buf.getvalue()


# ---------------------------------------------------------------- PDF ----

def generate_pdf():
    """Return a PDF report (as bytes) summarizing current threat state."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#14181D")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], textColor=colors.HexColor("#555"), spaceAfter=16
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], textColor=colors.HexColor("#14181D"), spaceBefore=18, spaceAfter=8
    )

    elements = []
    elements.append(Paragraph("SENTINEL &mdash; Endpoint Threat Report", title_style))
    elements.append(Paragraph(f"Generated {_fmt_time(datetime.now().timestamp())}", subtitle_style))

    processes = database.get_all_process_risk()
    dist = database.get_risk_distribution()
    alerts = database.get_recent_alerts(limit=25)

    # Summary
    elements.append(Paragraph("Summary", section_style))
    summary_data = [
        ["Tracked processes", str(len(processes))],
        ["Low risk", str(dist.get("Low", 0))],
        ["Medium risk", str(dist.get("Medium", 0))],
        ["High risk", str(dist.get("High", 0))],
        ["Total alerts logged", str(len(database.get_recent_alerts(limit=100000)))],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(summary_table)

    # Process risk table
    elements.append(Paragraph("Process Risk Table", section_style))
    if processes:
        rows = [["PID", "Process", "Score", "Level", "Virus Scan"]]
        for p in processes[:40]:
            rows.append([str(p["pid"]), p["process_name"][:28], str(p["risk_score"]), p["threat_level"], p["virus_result"][:20]])
        t = Table(rows, colWidths=[0.6 * inch, 2.1 * inch, 0.6 * inch, 0.8 * inch, 1.8 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14181D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F4F6")]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDD")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No flagged processes recorded.", styles["Normal"]))

    # Alerts
    elements.append(Paragraph("Recent Alerts", section_style))
    if alerts:
        rows = [["Time", "Process", "Level", "Message"]]
        for a in alerts:
            rows.append([_fmt_time(a["timestamp"]), a["process_name"][:20], a["threat_level"], a["message"][:70]])
        t = Table(rows, colWidths=[1.2 * inch, 1.3 * inch, 0.7 * inch, 2.7 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14181D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F4F6")]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DDD")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No alerts recorded.", styles["Normal"]))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph(
        "Educational defensive-security project - not a replacement for commercial antivirus/EDR software.",
        ParagraphStyle("Footer", parent=styles["Normal"], textColor=colors.HexColor("#888"), fontSize=8)
    ))

    doc.build(elements)
    return buf.getvalue()
