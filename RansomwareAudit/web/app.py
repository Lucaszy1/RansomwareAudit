"""Local web dashboard.

Security defaults:
- Binds to 127.0.0.1 (this machine only) and never runs Flask debug mode,
  since the Werkzeug debugger allows remote code execution.
- Every /api/ call needs a token sent in the X-Auth-Token header. A random
  token is generated at startup (or set RA_DASHBOARD_TOKEN) and printed in
  the login URL. Because the token travels in a custom header, other websites
  can't forge requests (CSRF) or reach the API through DNS rebinding.
- Scans and backups are limited to folders under web_dashboard.allowed_scan_roots.
"""
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime

from flask import Flask, jsonify, render_template, request

from RansomwareAudit.backup.manager import BackupManager
from RansomwareAudit.behavior.file_activity import analyze_file_behavior
from RansomwareAudit.config.manager import get_config
from RansomwareAudit.engine.risk_engine import calculate_total_risk
from RansomwareAudit.ml.model import RansomwareMLModel
from RansomwareAudit.quarantine.manager import QuarantineError, QuarantineManager
from RansomwareAudit.scanner.directory_scanner import scan_directory

cfg = get_config()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("RA_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # API bodies are tiny JSON

API_TOKEN = os.environ.get("RA_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)
SCAN_HISTORY_DB = os.environ.get("RA_SCAN_DB", "scan_history.db")
QUARANTINE_DIR = cfg.get("quarantine.quarantine_dir", "quarantine_vault")


def init_scan_db():
    with sqlite3.connect(SCAN_HISTORY_DB) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         scan_path TEXT, timestamp TEXT, risk_level TEXT,
                         total_score REAL, files_scanned INTEGER,
                         flagged_files INTEGER, scan_data TEXT)""")


init_scan_db()


# ---------- guards ----------
def allowed_roots():
    roots = cfg.get("web_dashboard.allowed_scan_roots", ["~"]) or []
    return [os.path.realpath(os.path.expanduser(r)) for r in roots]


def resolve_allowed_path(raw):
    """Return the real path if it's an existing folder under an allowed root, else None."""
    if not raw or not isinstance(raw, str):
        return None
    path = os.path.realpath(os.path.expanduser(raw))
    if not os.path.isdir(path):
        return None
    for root in allowed_roots():
        if path == root or path.startswith(root + os.sep):
            return path
    return None


@app.before_request
def require_token():
    if request.path.startswith("/api/"):
        sent = request.headers.get("X-Auth-Token", "")
        if not hmac.compare_digest(sent, API_TOKEN):
            return jsonify({"success": False, "error": "Unauthorized"}), 401


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ---------- pages ----------
@app.route("/")
def index():
    return render_template("dashboard.html")


# ---------- API ----------
@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True) or {}
    scan_path = resolve_allowed_path(data.get("path"))
    if scan_path is None:
        return jsonify({"success": False,
                        "error": "Path must be an existing folder inside an allowed root"}), 400
    try:
        file_reports = scan_directory(scan_path, cfg, quiet=True)
        behavior_data = analyze_file_behavior(scan_path, cfg)
        risk_summary = calculate_total_risk(file_reports, behavior_data, cfg)
        risk_summary["flagged_files"] = risk_summary["flagged_files"][:100]
        scan_result = {
            "scan_path": scan_path,
            "timestamp": datetime.now().isoformat(),
            "risk_summary": risk_summary,
            "behavior_data": behavior_data,
            "statistics": {"total_files": len(file_reports),
                           "high_risk_files": risk_summary["flagged_count"]},
        }
        with sqlite3.connect(SCAN_HISTORY_DB) as conn:
            conn.execute("""INSERT INTO scans (scan_path, timestamp, risk_level, total_score,
                            files_scanned, flagged_files, scan_data) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                         (scan_path, scan_result["timestamp"], risk_summary["risk_level"],
                          risk_summary["total_score"], len(file_reports),
                          risk_summary["flagged_count"], json.dumps(scan_result)))
        return jsonify({"success": True, "result": scan_result})
    except Exception:
        app.logger.exception("scan failed")
        return jsonify({"success": False, "error": "Scan failed, see server log"}), 500


@app.route("/api/scan-history")
def scan_history():
    with sqlite3.connect(SCAN_HISTORY_DB) as conn:
        rows = conn.execute("""SELECT id, scan_path, timestamp, risk_level, total_score,
                               files_scanned, flagged_files FROM scans
                               ORDER BY timestamp DESC LIMIT 20""").fetchall()
    keys = ["id", "scan_path", "timestamp", "risk_level", "total_score", "files_scanned", "flagged_files"]
    return jsonify([dict(zip(keys, r)) for r in rows])


@app.route("/api/quarantine")
def quarantine_list():
    return jsonify(QuarantineManager(QUARANTINE_DIR).list_quarantined())


@app.route("/api/quarantine/restore", methods=["POST"])
def quarantine_restore():
    data = request.get_json(silent=True) or {}
    qid = data.get("id")
    if not isinstance(qid, str) or not qid:
        return jsonify({"success": False, "error": "Missing id"}), 400
    try:
        QuarantineManager(QUARANTINE_DIR).restore_file(qid)
        return jsonify({"success": True})
    except QuarantineError as e:
        return jsonify({"success": False, "error": str(e)}), 409


@app.route("/api/quarantine/stats")
def quarantine_stats():
    return jsonify(QuarantineManager(QUARANTINE_DIR).get_stats())


@app.route("/api/backups")
def backup_list():
    return jsonify(BackupManager(cfg.get("backup.backup_dir", "ransomware_backups")).list_backups())


@app.route("/api/backup/create", methods=["POST"])
def backup_create():
    data = request.get_json(silent=True) or {}
    source = resolve_allowed_path(data.get("source"))
    if source is None:
        return jsonify({"success": False, "error": "Source must be a folder inside an allowed root"}), 400
    try:
        result = BackupManager(cfg.get("backup.backup_dir", "ransomware_backups")).create_backup(
            source, data.get("name") or None)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    return jsonify({"success": result is not None, "backup": result})


@app.route("/api/ml/status")
def ml_status():
    model = RansomwareMLModel(model_path=cfg.get("machine_learning.model_path", "ransomware_ml_model.pkl"))
    if os.path.exists(model.model_path) and model.load_model():
        return jsonify(model.get_model_info())
    return jsonify({"trained": False, "available": True})


@app.route("/api/stats")
def system_stats():
    with sqlite3.connect(SCAN_HISTORY_DB) as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        risk_dist = dict(conn.execute("SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level").fetchall())
        total_files = conn.execute("SELECT SUM(files_scanned) FROM scans").fetchone()[0] or 0
        total_flagged = conn.execute("SELECT SUM(flagged_files) FROM scans").fetchone()[0] or 0
    return jsonify({
        "total_scans": total_scans,
        "total_files_scanned": total_files,
        "total_flagged": total_flagged,
        "risk_distribution": risk_dist,
        "quarantined_files": QuarantineManager(QUARANTINE_DIR).get_stats()["total_quarantined"],
    })


def main():
    host = os.environ.get("RA_HOST", cfg.get("web_dashboard.host", "127.0.0.1"))
    port = int(os.environ.get("RA_PORT", cfg.get("web_dashboard.port", 5001)))
    shown_host = "localhost" if host in ("127.0.0.1", "0.0.0.0") else host
    print("=" * 60)
    print("  RANSOMWARE AUDIT DASHBOARD")
    print("=" * 60)
    print(f"Open: http://{shown_host}:{port}/#token={API_TOKEN}")
    if host not in ("127.0.0.1", "localhost"):
        print(f"[WARNING] Listening on {host}, reachable from other machines. Token still required.")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
