import argparse
import json
from RansomwareAudit.ml.model import RansomwareMLModel

def predict_from_report(report_path, model_path="ransomware_ml_model.pkl"):
    print(f"\n[*] Loading scan data from {report_path}...")
    
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    file_reports = report.get('file_reports', [])
    
    if not file_reports:
        print("[ERROR] No file reports found")
        return
    
    print(f"[+] Loaded {len(file_reports)} files for prediction")
    
    ml_model = RansomwareMLModel(model_path=model_path)
    
    if not ml_model.load_model():
        print("[ERROR] No trained model found. Train first with: python3 -m RansomwareAudit.ml.trainer")
        return
    
    print("[*] Running ML predictions...")
    predictions = ml_model.predict_batch(file_reports)
    
    anomalies = [p for p in predictions if p['is_anomaly'] == 1]
    
    print("\n" + "="*70)
    print("ML PREDICTION RESULTS")
    print("="*70)
    print(f"Total Files Analyzed: {len(predictions)}")
    print(f"Anomalies Detected: {len(anomalies)}")
    print(f"Normal Files: {len(predictions) - len(anomalies)}")
    
    if anomalies:
        print(f"\n[!] HIGH RISK ANOMALIES DETECTED:\n")
        anomalies_sorted = sorted(anomalies, key=lambda x: x['anomaly_score'], reverse=True)
        for i, anomaly in enumerate(anomalies_sorted[:20], 1):
            print(f"{i}. {anomaly['file']}")
            print(f"   Anomaly Score: {anomaly['anomaly_score']:.3f}\n")
    else:
        print("\n[+] No anomalies detected - all files appear normal")
    
    output_path = "ml_predictions.json"
    with open(output_path, 'w') as f:
        json.dump({
            'total_files': len(predictions),
            'anomalies_detected': len(anomalies),
            'predictions': predictions
        }, f, indent=2)
    
    print(f"\n[+] Detailed predictions saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Predict ransomware risk using ML")
    parser.add_argument("report", help="Path to ransomware_risk_report.json")
    parser.add_argument("--model", "-m", default="ransomware_ml_model.pkl",
                       help="Model path (default: ransomware_ml_model.pkl)")
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("RANSOMWARE ML PREDICTION SYSTEM")
    print("="*70)
    
    predict_from_report(args.report, args.model)

if __name__ == "__main__":
    main()
