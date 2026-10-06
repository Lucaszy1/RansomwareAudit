import time

from RansomwareAudit.monitor.watcher import SlidingWindowDetector, diff_snapshots


def test_sliding_window_catches_throttled_attack():
    """Regression: per-poll counting missed slow attacks; the window should not."""
    det = SlidingWindowDetector(window_seconds=30, mass_delete=20)
    now = time.time()
    for i in range(25):                         # 25 deletes over 25s, ~1/s
        det.record("deleted", f"/d/f{i}.txt", ts=now + i)
    score, alerts = det.evaluate(now=now + 25)
    assert score >= 8 and any("deletion" in a.lower() for a in alerts)


def test_window_expires_old_events():
    det = SlidingWindowDetector(window_seconds=10, mass_delete=20)
    base = time.time()
    for i in range(25):
        det.record("deleted", f"/d/f{i}.txt", ts=base + i)   # spread over 25s > window
    score, _ = det.evaluate(now=base + 24)
    assert score == 0


def test_ransom_extension_flagged():
    det = SlidingWindowDetector(window_seconds=30)
    now = time.time()
    for i in range(3):
        det.record("renamed", f"/d/f{i}.docx.encrypted", ts=now + i)
    score, alerts = det.evaluate(now=now + 3)
    assert score > 0 and any("extension" in a.lower() for a in alerts)


def test_diff_detects_rename_by_inode():
    old = {"/d/a.docx": {"dev": 1, "ino": 10, "size": 100, "mtime": 1, "mode": 0o644}}
    new = {"/d/a.docx.encrypted": {"dev": 1, "ino": 10, "size": 100, "mtime": 1, "mode": 0o644}}
    changes = diff_snapshots(old, new)
    assert changes["renamed"] == [("/d/a.docx", "/d/a.docx.encrypted")]
    assert not changes["deleted"] and not changes["created"]


def test_diff_detects_chmod():
    old = {"/d/a": {"dev": 1, "ino": 5, "size": 10, "mtime": 1, "mode": 0o644}}
    new = {"/d/a": {"dev": 1, "ino": 5, "size": 10, "mtime": 1, "mode": 0o777}}
    assert diff_snapshots(old, new)["chmod"] == ["/d/a"]
