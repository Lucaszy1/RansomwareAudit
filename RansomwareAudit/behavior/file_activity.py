"""One-shot behavior snapshot used by the main scan.

This only sees the state at scan time (what changed in the last N seconds,
which extensions exist). Real-time, rate-based detection lives in
monitor/watcher.py.
"""
import os
import time
from datetime import datetime, timezone

from RansomwareAudit.config.manager import get_config
from RansomwareAudit.engine.risk_engine import RANSOM_EXTENSIONS, RANSOM_NOTE_HINTS
from RansomwareAudit.scanner.directory_scanner import iter_files


def analyze_file_behavior(path, cfg=None):
    cfg = cfg or get_config()
    window = cfg.get("behavior.time_window_seconds", 60)
    burst_count = cfg.get("behavior.burst_file_count", 20)
    exclude = set(cfg.get("scanner.exclude_directories", []))

    activity = {
        "time_window_seconds": window,
        "total_files": 0,
        "recent_modifications": 0,
        "rapid_modifications": 0,
        "burst_detected": False,
        "suspicious_extensions": [],
        "ransom_notes": [],
    }
    now = time.time()

    for file_path in iter_files(path, exclude):
        try:
            mtime = os.stat(file_path).st_mtime
        except OSError:
            continue
        activity["total_files"] += 1
        name = os.path.basename(file_path).lower()
        ext = os.path.splitext(name)[1]

        if now - mtime <= window:
            activity["recent_modifications"] += 1
        if ext in RANSOM_EXTENSIONS:
            activity["suspicious_extensions"].append(file_path)
        if ext in {".txt", ".html", ".hta", ".rtf"} and any(h in name for h in RANSOM_NOTE_HINTS):
            activity["ransom_notes"].append(file_path)

    if activity["recent_modifications"] >= burst_count:
        activity["burst_detected"] = True
        activity["rapid_modifications"] = activity["recent_modifications"]

    activity["analysis_time"] = datetime.now(timezone.utc).isoformat()
    return activity
