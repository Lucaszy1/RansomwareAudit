import argparse
import csv
import os
import sys

from RansomwareAudit.config.manager import get_config
from RansomwareAudit.scanner.directory_scanner import scan_directory
from RansomwareAudit.behavior.file_activity import analyze_file_behavior
from RansomwareAudit.engine.risk_engine import calculate_total_risk
from RansomwareAudit.reporting.report_generator import generate_json_report, save_report, save_html_report
from RansomwareAudit.reporting.enhanced_report import generate_enhanced_report
from RansomwareAudit.quarantine.manager import QuarantineManager

LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def apply_ml(file_reports, risk_summary, model_path, quiet=False):
    """Add +2 to files the Isolation Forest flags as anomalous (if a model exists)."""
    from RansomwareAudit.ml.model import RansomwareMLModel
    model = RansomwareMLModel(model_path=model_path)
    if not os.path.exists(model_path) or not model.load_model():
        if not quiet:
            print("[*] No trained ML model found, skipping ML (train with RansomwareAudit.ml.trainer)")
        return 0
    flagged = {f["file"]: f for f in risk_summary["flagged_files"]}
    count = 0
    for report in file_reports:
        is_anomaly, anomaly_score = model.predict(report)
        report["ml_anomaly"] = bool(is_anomaly)
        report["ml_anomaly_score"] = round(float(anomaly_score), 3)
        if is_anomaly:
            count += 1
            entry = flagged.get(report["file"])
            if entry is None:
                entry = {"file": report["file"], "score": 0, "reasons": []}
                risk_summary["flagged_files"].append(entry)
                flagged[report["file"]] = entry
            entry["score"] += 2
            entry["reasons"].append(f"ML anomaly (score {anomaly_score:.2f})")
    risk_summary["flagged_files"].sort(key=lambda x: x["score"], reverse=True)
    return count


def main(argv=None):
    cfg = get_config()
    parser = argparse.ArgumentParser(description="RansomwareAudit: ransomware risk scanner")
    parser.add_argument("directory", nargs="?", default=".", help="Directory to scan")
    parser.add_argument("--json", "-j", default="ransomware_risk_report.json", help="JSON report output")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    parser.add_argument("--csv", help="Export flagged files to CSV")
    parser.add_argument("--quarantine", action="store_true",
                        help="Quarantine flagged files scoring at or above --threshold")
    parser.add_argument("--threshold", type=float,
                        default=cfg.get("quarantine.quarantine_threshold", 8),
                        help="Per-file score needed to quarantine (default from config.yaml)")
    parser.add_argument("--dry-run", action="store_true",
                        help="With --quarantine, list what would be quarantined without moving anything")
    parser.add_argument("--ml", action="store_true", help="Add ML anomaly signal (needs a trained model)")
    parser.add_argument("--compliance", action="store_true", help="Include compliance summary")
    parser.add_argument("--virustotal", action="store_true", help="Check top flagged hashes on VirusTotal")
    parser.add_argument("--fail-on", choices=LEVELS,
                        help="Exit with code 2 if the overall risk is at or above this level")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    args = parser.parse_args(argv)
    target = args.directory

    if not os.path.isdir(target):
        print(f"[ERROR] Not a directory: {target}")
        return 1

    if not args.quiet:
        print("=" * 60)
        print("  RANSOMWARE RISK ASSESSMENT")
        print("=" * 60)
        print(f"[+] Scanning: {target}")

    file_reports = scan_directory(target, cfg, quiet=args.quiet)
    behavior_report = analyze_file_behavior(target, cfg)
    risk_summary = calculate_total_risk(file_reports, behavior_report, cfg)

    if args.ml:
        n = apply_ml(file_reports, risk_summary,
                     cfg.get("machine_learning.model_path", "ransomware_ml_model.pkl"), args.quiet)
        if not args.quiet and n:
            print(f"[+] ML flagged {n} anomalous files")

    basic = generate_json_report(target, file_reports, behavior_report, risk_summary)
    report = basic
    if args.compliance or args.virustotal:
        report = generate_enhanced_report(basic, include_virustotal=args.virustotal,
                                          include_compliance=args.compliance)

    if args.quarantine:
        to_quarantine = [f for f in risk_summary["flagged_files"] if f["score"] >= args.threshold]
        qm = None if args.dry_run else QuarantineManager(cfg.get("quarantine.quarantine_dir", "quarantine_vault"))
        done = 0
        for item in to_quarantine:
            if args.dry_run:
                print(f"[dry-run] would quarantine {item['file']} (score {item['score']})")
                continue
            entry = qm.quarantine_file(item["file"], reason=f"Risk score {item['score']}",
                                       metadata={"score": item["score"], "reasons": item["reasons"]})
            if entry:
                done += 1
        if not args.quiet and not args.dry_run:
            print(f"[+] Quarantined {done} of {len(to_quarantine)} files at score >= {args.threshold}")

    save_report(report, args.json)
    if args.html:
        save_html_report(basic, "ransomware_risk_report.html")
        if not args.quiet:
            print("[+] HTML report: ransomware_risk_report.html")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Rank", "File Path", "Risk Score", "Reasons"])
            for i, item in enumerate(risk_summary["flagged_files"], 1):
                writer.writerow([i, item["file"], item["score"], "; ".join(item["reasons"])])
        if not args.quiet:
            print(f"[+] CSV exported: {args.csv}")

    if not args.quiet:
        print(f"\n[+] Risk Level: {risk_summary['risk_level']}")
        print(f"[+] Total Score: {risk_summary['total_score']}")
        print(f"[+] Files Scanned: {len(file_reports)}")
        print(f"[+] Flagged Files: {risk_summary['flagged_count']}")
        for reason in risk_summary["behavior_reasons"]:
            print(f"    ! {reason}")

    if args.fail_on and LEVELS.index(risk_summary["risk_level"]) >= LEVELS.index(args.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
