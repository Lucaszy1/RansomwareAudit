import argparse
from RansomwareAudit.reports.pdf_generator import generate_pdf_from_json

def main():
    parser = argparse.ArgumentParser(description="Generate PDF Report")
    parser.add_argument("json_report", help="Path to JSON report file")
    parser.add_argument("--output", "-o", default="executive_summary.pdf",
                       help="Output PDF file path")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("PDF REPORT GENERATOR")
    print("="*70 + "\n")
    
    output = generate_pdf_from_json(args.json_report, args.output)
    print(f"\n[+] Report saved: {output}")
    print("[*] Open with your PDF viewer")

if __name__ == "__main__":
    main()
