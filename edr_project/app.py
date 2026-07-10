"""
app.py
-------
Module 7 - Dashboard (Flask backend).

Serves the dashboard HTML page and a small JSON API that the
frontend (static/js/dashboard.js) polls to update the charts and
tables in real time.
"""

import os
import time
import psutil
from flask import Flask, jsonify, render_template, Response, request

import database
import report_generator
import quarantine
from monitor_engine import MonitorEngine

app = Flask(__name__)

engine = MonitorEngine()


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/summary")
def api_summary():
    processes = database.get_all_process_risk()
    dist = database.get_risk_distribution()
    high_risk = [p for p in processes if p["threat_level"] == "High"]

    return jsonify({
        "total_running_processes": len(psutil.pids()),
        "tracked_processes": len(processes),
        "active_alerts": len(database.get_recent_alerts(limit=1000)),
        "high_risk_count": len(high_risk),
        "risk_distribution": dist,
    })


@app.route("/api/processes")
def api_processes():
    return jsonify(database.get_all_process_risk())


@app.route("/api/events")
def api_events():
    return jsonify(database.get_recent_events(limit=50))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(database.get_recent_alerts(limit=20))


@app.route("/api/websites")
def api_websites():
    return jsonify(database.get_all_websites())


@app.route("/api/whitelist", methods=["GET"])
def api_get_whitelist():
    return jsonify(database.get_whitelist())


@app.route("/api/whitelist", methods=["POST"])
def api_add_whitelist():
    data = request.get_json(silent=True) or {}
    process_name = (data.get("process_name") or "").strip()
    if not process_name:
        return jsonify({"success": False, "message": "process_name is required"}), 400
    database.add_to_whitelist(process_name)
    return jsonify({"success": True, "message": f"'{process_name}' added to whitelist"})


@app.route("/api/whitelist/<process_name>", methods=["DELETE"])
def api_remove_whitelist(process_name):
    database.remove_from_whitelist(process_name)
    return jsonify({"success": True, "message": f"'{process_name}' removed from whitelist"})


@app.route("/api/history")
def api_history():
    return jsonify(database.get_risk_history(limit=100))


@app.route("/report/csv")
def report_csv():
    csv_data = report_generator.generate_csv()
    filename = f"sentinel_report_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/report/pdf")
def report_pdf():
    pdf_bytes = report_generator.generate_pdf()
    filename = f"sentinel_report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/process/<int:pid>/quarantine_check")
def api_quarantine_check(pid):
    return jsonify(quarantine.suggest_quarantine(pid))


@app.route("/api/process/<int:pid>/quarantine", methods=["POST"])
def api_quarantine(pid):
    result = quarantine.quarantine_process(pid)
    status = 200 if result["success"] else 409
    return jsonify(result), status


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    engine.start()
    app.run(
    debug=False,
    host="127.0.0.1",
    port=5000,
    ssl_context=("localhost+2.pem", "localhost+2-key.pem")
)