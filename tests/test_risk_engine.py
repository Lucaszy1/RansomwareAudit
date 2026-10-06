import io
import os
import zipfile

from conftest import write_text_files
from RansomwareAudit.behavior.file_activity import analyze_file_behavior
from RansomwareAudit.engine.risk_engine import calculate_total_risk, score_file
from RansomwareAudit.scanner.directory_scanner import scan_directory


def report(name, entropy, perms="644"):
    return {"file": f"/d/{name}", "entropy": entropy, "permissions": perms,
            "size_bytes": 1000, "extension": os.path.splitext(name)[1]}


def test_random_bytes_in_text_file_scores_high(cfg):
    score, _ = score_file(report("notes.txt", 7.99), cfg)
    assert score >= 6


def test_high_entropy_zip_is_mostly_ignored(cfg):
    score, _ = score_file(report("backup.zip", 7.99), cfg)
    assert score <= 1


def test_encrypted_extension_uses_inner_type(cfg):
    score, reasons = score_file(report("essay.txt.encrypted", 7.99), cfg)
    assert score >= 12 and any("should be text" in r for r in reasons)


def test_one_bad_file_is_not_averaged_away(cfg):
    """Regression: averaging hid a single encrypted file among many clean ones."""
    clean = [report(f"f{i}.txt", 4.5) for i in range(1000)]
    bad = report("x.txt.encrypted", 7.99)
    summary = calculate_total_risk(clean + [bad], {}, cfg)
    assert summary["risk_level"] in ("HIGH", "CRITICAL")
    assert summary["flagged_files"][0]["file"] == bad["file"]


def test_clean_text_folder_is_low(cfg, tmp_path):
    write_text_files(tmp_path / "docs", 30)
    files = scan_directory(str(tmp_path), cfg, quiet=True)
    summary = calculate_total_risk(files, {}, cfg)
    assert summary["risk_level"] == "LOW"


def test_metamorphic_zipping_benign_folder_stays_below_high(cfg, tmp_path):
    """Property: compressing benign files is benign, so it must not look like an attack."""
    docs = tmp_path / "docs"
    write_text_files(docs, 30)
    before = calculate_total_risk(scan_directory(str(tmp_path), cfg, quiet=True), {}, cfg)

    with zipfile.ZipFile(tmp_path / "docs_backup.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for name in os.listdir(docs):
            z.write(docs / name, name)
    behavior = analyze_file_behavior(str(tmp_path), cfg)
    after = calculate_total_risk(scan_directory(str(tmp_path), cfg, quiet=True), behavior, cfg)

    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert order.index(after["risk_level"]) < order.index("HIGH")
    assert before["risk_level"] == "LOW"
