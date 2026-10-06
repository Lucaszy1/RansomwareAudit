import os
from RansomwareAudit.config.manager import get_config
from RansomwareAudit.scanner.entropy import calculate_entropy
from RansomwareAudit.scanner.permissions import get_permissions
from RansomwareAudit.scanner.metadata import get_metadata
from RansomwareAudit.engine.risk_engine import score_file


def iter_files(path, exclude_dirs):
    """Walk `path`, skipping excluded directory names and symlinks."""
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for filename in files:
            file_path = os.path.join(root, filename)
            if not os.path.islink(file_path):
                yield file_path


def scan_directory(path, config=None, quiet=False):
    cfg = config or get_config()
    exclude = set(cfg.get("scanner.exclude_directories", []))
    sample = cfg.get("scanner.entropy_sample_bytes", 1_048_576)

    results = []
    skipped = 0
    for file_path in iter_files(path, exclude):
        try:
            metadata = get_metadata(file_path)
            report = {
                "file": file_path,
                "entropy": round(calculate_entropy(file_path, max_bytes=sample), 2),
                "permissions": get_permissions(file_path),
                **metadata,
            }
            score, reasons = score_file(report, cfg)
            report["risk_score"] = score
            report["reasons"] = reasons
            results.append(report)
        except Exception:
            skipped += 1

    if not quiet:
        print(f"[+] Scanned {len(results)} files successfully")
        if skipped:
            print(f"[WARNING] Skipped {skipped} files due to access errors")
    return results
