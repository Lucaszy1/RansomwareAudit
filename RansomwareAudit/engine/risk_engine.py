"""Turns per-file facts and behavior signals into risk scores.

Design notes:
- Entropy alone can't tell malicious encryption from a normal .zip or .jpg,
  so high entropy on a format that is *expected* to be compressed counts for
  little, while high entropy on a format that should be readable (txt, csv,
  source code) counts for a lot.
- The overall score uses the worst file plus how widespread the damage is,
  instead of the average, so one encrypted file among thousands of clean
  ones still shows up.
"""
from RansomwareAudit.config.manager import get_config

RANSOM_EXTENSIONS = {".locked", ".encrypted", ".crypto", ".crypt", ".enc", ".ransom",
                     ".cerber", ".locky", ".wnry", ".wncry"}
SCRIPT_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr", ".cmd", ".com", ".jar"}
# Formats that are compressed by design, so high entropy is normal for them.
COMPRESSED_EXTENSIONS = {".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jpg", ".jpeg",
                         ".png", ".gif", ".webp", ".heic", ".mp3", ".mp4", ".mov", ".m4a",
                         ".aac", ".ogg", ".pdf", ".docx", ".xlsx", ".pptx", ".jar", ".apk",
                         ".dmg", ".pkg", ".whl", ".woff", ".woff2", ".pkl", ".aseprite"}
# Formats that should be human-readable text, so near-random bytes are a red flag.
TEXT_EXTENSIONS = {".txt", ".csv", ".md", ".json", ".xml", ".html", ".htm", ".css", ".js",
                   ".py", ".java", ".c", ".cpp", ".h", ".rtf", ".log", ".yaml", ".yml",
                   ".sql", ".ini", ".cfg", ".tex", ".svg"}
RANSOM_NOTE_HINTS = ("decrypt", "ransom", "recover_files", "how_to_restore", "readme_unlock")


def _level(score, cfg):
    if score >= cfg.get("risk.critical", 12):
        return "CRITICAL"
    if score >= cfg.get("risk.high", 8):
        return "HIGH"
    if score >= cfg.get("risk.medium", 4):
        return "MEDIUM"
    return "LOW"


def _real_extension(path, extension):
    """For 'report.docx.encrypted', return '.docx' (the original type)."""
    if extension in RANSOM_EXTENSIONS:
        stem = path[: -len(extension)]
        inner = stem[stem.rfind("."):].lower() if "." in stem.rsplit("/", 1)[-1] else ""
        return inner
    return extension


def score_file(file_report, cfg=None):
    cfg = cfg or get_config()
    score = 0
    reasons = []
    entropy = file_report.get("entropy", 0)
    permissions = file_report.get("permissions", "")
    size = file_report.get("size_bytes", 0)
    extension = (file_report.get("extension") or "").lower()
    path = file_report.get("file", "")
    threshold = cfg.get("scanner.entropy_threshold", 7.5)

    if extension in RANSOM_EXTENSIONS:
        score += 6
        reasons.append(f"Ransomware-style extension ({extension})")

    if entropy >= threshold:
        original = _real_extension(path, extension)
        if original in TEXT_EXTENSIONS:
            score += 6
            reasons.append(f"Near-random bytes in a file that should be text ({original})")
        elif extension in COMPRESSED_EXTENSIONS:
            score += 1
            reasons.append("High entropy, but expected for this compressed format")
        else:
            score += 4
            reasons.append("Very high entropy (likely encrypted or packed)")
    elif entropy >= 6.5 and extension in TEXT_EXTENSIONS:
        score += 2
        reasons.append("Unusually high entropy for a text format")

    if permissions in {"777", "666"}:
        score += 2
        reasons.append("World-writable permissions")

    if extension in SCRIPT_EXTENSIONS:
        score += 2
        reasons.append(f"Executable type ({extension})")

    if size > 50_000_000:
        score += 1
        reasons.append("Large file size")

    return score, reasons


def score_behavior(behavior_report):
    score = 0
    reasons = []

    if behavior_report.get("burst_detected"):
        score += 5
        reasons.append(f"Mass modification burst: {behavior_report.get('rapid_modifications', 0)} "
                       f"files changed in {behavior_report.get('time_window_seconds', 60)}s")

    n_ransom = len(behavior_report.get("suspicious_extensions", []))
    if n_ransom >= 5:
        score += 10
        reasons.append(f"{n_ransom} files with ransomware-style extensions")
    elif n_ransom:
        score += 4
        reasons.append(f"{n_ransom} file(s) with ransomware-style extensions")

    if behavior_report.get("ransom_notes"):
        score += 5
        reasons.append(f"Possible ransom note: {behavior_report['ransom_notes'][0]}")

    return score, reasons


def calculate_total_risk(file_reports, behavior_report, cfg=None):
    cfg = cfg or get_config()
    flagged_files = []
    scores = []
    for f in file_reports:
        if "risk_score" in f and "reasons" in f:
            score, reasons = f["risk_score"], f["reasons"]
        else:
            score, reasons = score_file(f, cfg)
        scores.append(score)
        if score > 0:
            flagged_files.append({"file": f["file"], "score": score, "reasons": reasons,
                                  "level": _level(score, cfg)})

    behavior_score, behavior_reasons = score_behavior(behavior_report)

    top_file_score = max(scores) if scores else 0
    high_risk = sum(1 for s in scores if s >= cfg.get("risk.high", 8))
    spread = high_risk / len(scores) if scores else 0.0
    # Up to +4 for how widespread high-risk files are (40%+ of files gives the full +4).
    spread_bonus = round(min(4.0, spread * 10), 2)

    total_score = round(top_file_score + spread_bonus + behavior_score, 2)

    return {
        "risk_level": _level(total_score, cfg),
        "total_score": total_score,
        "top_file_score": top_file_score,
        "high_risk_fraction": round(spread, 3),
        "behavior_score": behavior_score,
        "behavior_reasons": behavior_reasons,
        "flagged_count": len(flagged_files),
        "flagged_files": sorted(flagged_files, key=lambda x: x["score"], reverse=True),
    }
