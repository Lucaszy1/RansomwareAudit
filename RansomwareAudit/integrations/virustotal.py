"""Hash-only VirusTotal lookup. Files are never uploaded, only their SHA-256."""
import os

from RansomwareAudit.virustotal.scanner import VirusTotalScanner, load_virustotal_config


def get_api_key():
    return os.environ.get("VT_API_KEY") or load_virustotal_config()


def scan_with_virustotal(filepath, api_key=None):
    key = api_key or get_api_key()
    if not key:
        return {"status": "skipped", "reason": "No API key (set VT_API_KEY or virustotal_config.json)"}
    return VirusTotalScanner(key).scan_file(filepath)
