from RansomwareAudit.reporting.compliance import generate_compliance_report
from RansomwareAudit.integrations.virustotal import scan_with_virustotal


def generate_enhanced_report(scan_results, include_virustotal=False, include_compliance=True):
    enhanced = {"basic_scan": scan_results}

    if include_compliance:
        enhanced["compliance"] = generate_compliance_report(scan_results)

    if include_virustotal:
        vt_results = []
        for file_data in scan_results["risk_summary"].get("flagged_files", [])[:5]:
            result = scan_with_virustotal(file_data["file"])
            if result:
                vt_results.append({"file": file_data["file"], "virustotal": result})
        enhanced["virustotal_validation"] = vt_results

    return enhanced
