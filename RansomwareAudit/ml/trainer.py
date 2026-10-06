import json
import argparse
from RansomwareAudit.ml.model import RansomwareMLModel

def train_from_report(report_path, model_path="ransomware_ml_model.pkl"):
    print(f"\n[*] Loading training data from {report_path}...")
    
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    file_reports = report.get('file_reports', [])
    
    if not file_reports:
        print("[ERROR] No file reports found in the JSON")
        return False
    
    print(f"[+] Loaded {len(file_reports)} file records")
    
    ml_model = RansomwareMLModel(model_path=model_path)
    
    if ml_model.load_model():
        print("[*] Existing model found, will retrain with new data")
    
    success = ml_model.train(file_reports)
    
    if success:
        ml_model.save_model()
        print(f"\n[+] Training complete!")
        print(f"[+] Model saved to {model_path}")
        return True
    else:
        print("[ERROR] Training failed")
        return False

def main():
    parser = argparse.ArgumentParser(description="Train ML model from scan reports")
    parser.add_argument("report", help="Path to ransomware_risk_report.json")
    parser.add_argument("--model", "-m", default="ransomware_ml_model.pkl", 
                       help="Output model path (default: ransomware_ml_model.pkl)")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("RANSOMWARE ML MODEL TRAINER")
    print("="*70)
    
    train_from_report(args.report, args.model)

if __name__ == "__main__":
    main()
