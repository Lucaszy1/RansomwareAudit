"""Plain-language summary mapped loosely to NIST CSF functions.

Everything here is derived from what the scan actually found. It is an
informational summary, not a formal compliance audit.
"""

def generate_compliance_report(scan_results):
    risk = scan_results["risk_summary"]
    behavior = scan_results.get("behavior_analysis", {})
    level = risk["risk_level"]
    flagged = risk.get("flagged_files", [])
    world_writable = sum(1 for f in flagged if any("World-writable" in r for r in f["reasons"]))
    ransom_ext = len(behavior.get("suspicious_extensions", []))

    findings = {
        "detect": f"{risk.get('flagged_count', len(flagged))} files flagged; overall level {level}",
        "protect": (f"{world_writable} flagged files are world-writable"
                    if world_writable else "No world-writable flagged files"),
        "respond": ("Ransomware-style extensions present, isolate the machine and investigate"
                    if ransom_ext else "No ransomware-style extensions found"),
    }
    return {
        "note": "Informational summary derived from this scan, not a formal audit.",
        "risk_level": level,
        "total_score": risk["total_score"],
        "nist_csf_observations": findings,
        "recommendations": get_recommendations(level),
    }


def get_recommendations(risk_level):
    if risk_level == "CRITICAL":
        return ["Disconnect the affected machine from the network",
                "Do not pay or delete anything yet, preserve evidence",
                "Restore from an offline backup made before the incident"]
    if risk_level == "HIGH":
        return ["Review the top flagged files manually",
                "Check flagged hashes against VirusTotal (--virustotal)",
                "Verify a recent offline backup exists"]
    if risk_level == "MEDIUM":
        return ["Review flagged files, many will be benign (archives, installers)",
                "Tighten permissions on world-writable files"]
    return ["No action needed, keep regular backups"]
