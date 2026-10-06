import json
import requests
import socket
import argparse
import os

def submit_scan_to_server(server_url, scan_report, client_id=None, token=None):
    if not client_id:
        client_id = socket.gethostname()
    
    payload = {
        'client_id': client_id,
        'hostname': socket.gethostname(),
        'scan_report': scan_report
    }
    
    try:
        token = token or os.environ.get("RA_SERVER_TOKEN", "")
        response = requests.post(f"{server_url}/api/submit_scan", json=payload, timeout=30,
                                 headers={"X-Auth-Token": token})
        
        if response.status_code == 200:
            result = response.json()
            print(f"[+] Scan submitted successfully")
            print(f"[+] Scan ID: {result.get('scan_id')}")
            return True
        else:
            print(f"[ERROR] Server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to connect to server: {e}")
        return False

def run_scan_and_submit(target_dir, server_url, client_id=None, token=None):
    from RansomwareAudit.scanner.directory_scanner import scan_directory
    from RansomwareAudit.behavior.file_activity import analyze_file_behavior
    from RansomwareAudit.engine.risk_engine import calculate_total_risk
    from RansomwareAudit.reporting.report_generator import generate_json_report
    
    print(f"\n[*] Running scan on: {target_dir}")
    
    file_reports = scan_directory(target_dir)
    print(f"[+] Scanned {len(file_reports)} files")
    
    behavior_data = analyze_file_behavior(target_dir)
    print(f"[*] Behavior analysis complete")
    
    risk_summary = calculate_total_risk(file_reports, behavior_data)
    print(f"[*] Risk assessment complete: {risk_summary['risk_level']}")
    
    report = generate_json_report(target_dir, file_reports, behavior_data, risk_summary)
    
    print(f"\n[*] Submitting scan to server: {server_url}")
    success = submit_scan_to_server(server_url, report, client_id, token)
    
    return success

def main():
    parser = argparse.ArgumentParser(description="Ransomware Audit Network Client")
    parser.add_argument("target", help="Directory to scan")
    parser.add_argument("--server", "-s", required=True, help="Server URL (e.g., http://192.168.1.100:5000)")
    parser.add_argument("--client-id", "-c", help="Client identifier (default: hostname)")
    parser.add_argument("--token", help="Server token (default: RA_SERVER_TOKEN env var)")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("RANSOMWARE AUDIT NETWORK CLIENT")
    print("="*70)
    
    run_scan_and_submit(args.target, args.server, args.client_id, args.token)

if __name__ == '__main__':
    main()
