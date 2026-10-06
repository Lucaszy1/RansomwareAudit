import argparse
from RansomwareAudit.scanner.directory_scanner import scan_directory
from RansomwareAudit.behavior.file_activity import analyze_file_behavior
from RansomwareAudit.engine.risk_engine import calculate_total_risk
from RansomwareAudit.reporting.report_generator import generate_json_report, save_report
from RansomwareAudit.notifications.notifier import NotificationManager, load_notification_config

def main():
    parser = argparse.ArgumentParser(description="Ransomware Audit with Notifications")
    parser.add_argument("target", help="Directory to scan")
    parser.add_argument("--config", default="notification_config.json",
                       help="Notification config file")
    parser.add_argument("--notify-threshold", default="HIGH",
                       choices=['MEDIUM', 'HIGH', 'CRITICAL'],
                       help="Only send notifications for this risk level and above")
    parser.add_argument("--json", default="ransomware_risk_report.json",
                       help="Output JSON file")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("RANSOMWARE AUDIT WITH NOTIFICATIONS")
    print("="*70)
    print(f"[+] Target: {args.target}")
    print(f"[+] Notification threshold: {args.notify_threshold}")
    print()
    
    config = load_notification_config(args.config)
    notifier = NotificationManager(config)
    
    if not config:
        print("[WARNING] No notification config found")
        print("[*] Run: python3 -c 'from RansomwareAudit.notifications.notifier import create_sample_config; create_sample_config()'")
        print()
    
    print("[*] Scanning files...")
    file_reports = scan_directory(args.target)
    print(f"[+] Scanned {len(file_reports)} files")
    
    print("[*] Analyzing behavior...")
    behavior_data = analyze_file_behavior(args.target)
    
    print("[*] Calculating risk...")
    risk_summary = calculate_total_risk(file_reports, behavior_data)
    
    risk_level = risk_summary['risk_level']
    total_score = risk_summary['total_score']
    flagged_count = len(risk_summary.get('flagged_files', []))
    
    print("\n" + "="*70)
    print(f"Risk Level: {risk_level}")
    print(f"Total Score: {total_score:.2f}")
    print(f"Flagged Files: {flagged_count}")
    print("="*70 + "\n")
    
    should_notify = False
    if args.notify_threshold == 'MEDIUM' and risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
        should_notify = True
    elif args.notify_threshold == 'HIGH' and risk_level in ['HIGH', 'CRITICAL']:
        should_notify = True
    elif args.notify_threshold == 'CRITICAL' and risk_level == 'CRITICAL':
        should_notify = True
    
    if should_notify and (config.get('email', {}).get('enabled') or config.get('slack', {}).get('enabled')):
        print("[!] Risk threshold exceeded - Sending notifications...")
        
        subject = f"Ransomware Risk Detected: {risk_level}"
        message = f"""
Ransomware scan completed on: {args.target}

Risk Level: {risk_level}
Total Risk Score: {total_score:.2f}
Files Scanned: {len(file_reports)}
High-Risk Files: {flagged_count}

Immediate action may be required.
Review the full report at: {args.json}
"""
        
        channels = notifier.send_alert(subject, message, risk_level)
        if channels:
            print(f"[+] Notifications sent via: {', '.join(channels)}")
        else:
            print("[WARNING] Failed to send notifications")
    else:
        print("[*] Risk level below notification threshold - no alerts sent")
    
    report = generate_json_report(args.target, file_reports, behavior_data, risk_summary)
    save_report(report, args.json)
    print(f"\n[+] Report saved: {args.json}")

if __name__ == "__main__":
    main()
