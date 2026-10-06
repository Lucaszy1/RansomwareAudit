import argparse
import json
from RansomwareAudit.virustotal.scanner import VirusTotalScanner, load_virustotal_config

def main():
    parser = argparse.ArgumentParser(description="VirusTotal File Scanner")
    parser.add_argument("report", help="Path to ransomware_risk_report.json")
    parser.add_argument("--config", default="virustotal_config.json",
                       help="VirusTotal config file")
    parser.add_argument("--top", type=int, default=10,
                       help="Scan top N high-risk files (default: 10)")
    parser.add_argument("--output", default="virustotal_results.json",
                       help="Output file")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("VIRUSTOTAL MALWARE SCANNER")
    print("="*70 + "\n")
    
    api_key = load_virustotal_config(args.config)
    
    if not api_key:
        print("[ERROR] No VirusTotal API key found")
        print("[*] Run: python3 -c 'from RansomwareAudit.virustotal.scanner import create_sample_vt_config; create_sample_vt_config()'")
        return
    
    with open(args.report, 'r') as f:
        report = json.load(f)
    
    flagged_files = report.get('risk_summary', {}).get('flagged_files', [])
    
    if not flagged_files:
        print("[*] No high-risk files to scan")
        return
    
    top_files = [f['file'] for f in flagged_files[:args.top]]
    
    print(f"[*] Scanning top {len(top_files)} high-risk files with VirusTotal")
    print(f"[*] Note: Free API has 4 requests/minute limit\n")
    
    scanner = VirusTotalScanner(api_key)
    results = scanner.scan_files_batch(top_files)
    
    malicious_count = sum(1 for r in results if r.get('malicious', 0) > 0)
    
    print("\n" + "="*70)
    print("VIRUSTOTAL SCAN RESULTS")
    print("="*70)
    print(f"Files Scanned: {len(results)}")
    print(f"Known Malicious: {malicious_count}")
    print(f"Unknown to VT: {sum(1 for r in results if not r.get('found'))}")
    
    if malicious_count > 0:
        print(f"\n[!] CRITICAL: {malicious_count} files detected as malicious!\n")
        for r in results:
            if r.get('malicious', 0) > 0:
                print(f"  {r['file']}")
                print(f"    Detected by {r['malicious']}/{r['total_scans']} engines")
    
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Full results saved to: {args.output}")

if __name__ == "__main__":
    main()
