"""Measure detection quality against the simulator's ground truth.

The simulator (ransomware_simulator.py) builds a clean folder, then overwrites
a known subset of files and renames them .encrypted, recording exactly which
files it hit. That list is the answer key. This harness runs the scanner on
the result and reports precision, recall and F1 at the file level, plus
detection latency against the real-time monitor.

It also runs a few benign high-churn workloads (zipping a backup, rotating gzip
logs) to measure false positives, since a detector that flags every archive is
useless in practice.

Usage:
    python3 evaluate.py                 # detection accuracy sweep over speeds
    python3 evaluate.py --latency       # also measure monitor detection latency
    python3 evaluate.py --json out.json # write full results
"""
import argparse
import gzip
import json
import os
import shutil
import tempfile
import time
import zipfile

from RansomwareAudit.config.manager import get_config
from RansomwareAudit.engine.risk_engine import calculate_total_risk, score_file
from RansomwareAudit.monitor.watcher import FileSystemMonitor, SlidingWindowDetector
from RansomwareAudit.scanner.directory_scanner import scan_directory
from ransomware_simulator import RansomwareSimulator

QUARANTINE_THRESHOLD = 8  # a file at or above this score is treated as "detected"


def prf(true_pos, false_pos, false_neg):
    precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) else 1.0
    recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return round(precision, 3), round(recall, 3), round(f1, 3)


def ground_truth(test_dir):
    """Return (malicious_paths, benign_paths) from the final folder state."""
    malicious, benign = set(), set()
    for root, _, files in os.walk(test_dir):
        for name in files:
            path = os.path.join(root, name)
            if name == "README_DECRYPT.txt":
                continue
            (malicious if name.endswith(".encrypted") else benign).add(path)
    return malicious, benign


def evaluate_scan(test_dir, cfg, threshold=QUARANTINE_THRESHOLD):
    malicious, benign = ground_truth(test_dir)
    reports = scan_directory(test_dir, cfg, quiet=True)
    flagged = {r["file"] for r in reports
               if (r.get("risk_score") or score_file(r, cfg)[0]) >= threshold}

    tp = len(flagged & malicious)
    fp = len(flagged & benign)
    fn = len(malicious - flagged)
    precision, recall, f1 = prf(tp, fp, fn)
    return {"malicious": len(malicious), "benign": len(benign), "flagged": len(flagged),
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": precision, "recall": recall, "f1": f1}


def accuracy_sweep(speeds=("instant", "fast", "slow"), num_files=80, infection_rate=0.8, seed=1):
    cfg = get_config()
    results = {}
    for speed in speeds:
        test_dir = tempfile.mkdtemp(prefix=f"ra_eval_{speed}_")
        try:
            sim = RansomwareSimulator(test_dir=test_dir)
            sim.create_test_environment(num_files=num_files)
            # overwrite+rename directly (no 3s countdown / prompts) for a batch run
            _attack(sim, infection_rate=infection_rate, speed=speed)
            results[speed] = evaluate_scan(test_dir, cfg)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)
    return results


def _attack(sim, infection_rate, speed):
    import random
    all_files = []
    for root, _, files in os.walk(sim.test_dir):
        for name in files:
            all_files.append(os.path.join(root, name))
    targets = random.sample(all_files, int(len(all_files) * infection_rate))
    delay = {"instant": 0.0, "fast": 0.01, "medium": 0.1, "slow": 0.25}.get(speed, 0.01)
    for path in targets:
        with open(path, "wb") as f:
            f.write(os.urandom(random.randint(1000, 5000)))
        os.rename(path, path + ".encrypted")
        sim.infected_files.append(path + ".encrypted")
        time.sleep(delay)


def benign_false_positives(num_files=120, seed=2):
    """Run benign high-churn workloads and count how many files get flagged."""
    cfg = get_config()
    results = {}
    for workload in ("zip_backup", "gzip_logs", "bulk_edit"):
        test_dir = tempfile.mkdtemp(prefix=f"ra_benign_{workload}_")
        try:
            sim = RansomwareSimulator(test_dir=test_dir)
            sim.create_test_environment(num_files=num_files)
            _benign(workload, test_dir)
            reports = scan_directory(test_dir, cfg, quiet=True)
            flagged = [r["file"] for r in reports
                       if (r.get("risk_score") or score_file(r, cfg)[0]) >= QUARANTINE_THRESHOLD]
            summary = calculate_total_risk(reports, {}, cfg)
            results[workload] = {"files": len(reports), "false_positives": len(flagged),
                                 "risk_level": summary["risk_level"]}
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)
    return results


def _benign(workload, test_dir):
    if workload == "zip_backup":
        with zipfile.ZipFile(os.path.join(test_dir, "backup.zip"), "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(test_dir):
                for name in files:
                    if not name.endswith(".zip"):
                        z.write(os.path.join(root, name))
    elif workload == "gzip_logs":
        for root, _, files in os.walk(test_dir):
            for name in files:
                p = os.path.join(root, name)
                with open(p, "rb") as src, gzip.open(p + ".gz", "wb") as dst:
                    shutil.copyfileobj(src, dst)
    elif workload == "bulk_edit":
        for root, _, files in os.walk(test_dir):
            for name in files:
                with open(os.path.join(root, name), "a") as f:
                    f.write("\nedited line appended by a normal workflow\n")


def latency_test(num_files=120, infection_rate=0.8, interval=1.0, speed="fast"):
    """Prime the polling monitor, run an attack, report how fast it alerts."""
    cfg = get_config()
    test_dir = tempfile.mkdtemp(prefix="ra_latency_")
    try:
        sim = RansomwareSimulator(test_dir=test_dir)
        sim.create_test_environment(num_files=num_files)
        monitor = FileSystemMonitor(test_dir, cfg=cfg,
                                    detector=SlidingWindowDetector.from_config(cfg))
        monitor.prime()

        import random
        all_files = [os.path.join(r, n) for r, _, fs in os.walk(test_dir) for n in fs]
        targets = random.sample(all_files, int(len(all_files) * infection_rate))
        delay = {"instant": 0.0, "fast": 0.01, "medium": 0.1, "slow": 0.25}.get(speed, 0.01)

        start = time.time()
        first_alert = None
        files_lost_at_alert = None

        def do_attack():
            for path in targets:
                with open(path, "wb") as f:
                    f.write(os.urandom(2000))
                os.rename(path, path + ".encrypted")
                time.sleep(delay)

        import threading
        t = threading.Thread(target=do_attack)
        t.start()
        while t.is_alive() or True:
            time.sleep(interval)
            alert = monitor.poll_once()
            if alert and first_alert is None:
                first_alert = round(time.time() - start, 2)
                files_lost_at_alert = sum(1 for p in targets if os.path.exists(p + ".encrypted"))
                break
            if not t.is_alive():
                monitor.poll_once()
                break
        t.join()
        return {"speed": speed, "interval": interval, "targets": len(targets),
                "detection_latency_s": first_alert,
                "files_encrypted_before_alert": files_lost_at_alert}
    finally:
        shutil.rmtree(test_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Detection evaluation harness")
    parser.add_argument("--latency", action="store_true", help="Also run the latency test")
    parser.add_argument("--json", help="Write full results to this JSON file")
    args = parser.parse_args()

    print("=" * 64)
    print("  DETECTION ACCURACY  (static scan vs ground truth)")
    print("=" * 64)
    accuracy = accuracy_sweep()
    print(f"{'speed':<10}{'malicious':>10}{'recall':>9}{'precision':>11}{'F1':>7}{'FP':>5}")
    for speed, r in accuracy.items():
        print(f"{speed:<10}{r['malicious']:>10}{r['recall']:>9}{r['precision']:>11}"
              f"{r['f1']:>7}{r['false_positives']:>5}")

    print("\n" + "=" * 64)
    print("  FALSE POSITIVES  (benign high-churn workloads)")
    print("=" * 64)
    benign = benign_false_positives()
    for workload, r in benign.items():
        print(f"{workload:<14} files={r['files']:>4}  false_positives={r['false_positives']:>3}  "
              f"level={r['risk_level']}")

    results = {"accuracy": accuracy, "benign": benign}
    if args.latency:
        print("\n" + "=" * 64)
        print("  DETECTION LATENCY  (real-time monitor)")
        print("=" * 64)
        results["latency"] = {}
        for speed in ("fast", "slow"):
            lat = latency_test(speed=speed)
            results["latency"][speed] = lat
            print(f"{speed:<6} latency={lat['detection_latency_s']}s  "
                  f"encrypted_before_alert={lat['files_encrypted_before_alert']}/{lat['targets']}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results written to {args.json}")


if __name__ == "__main__":
    main()
