"""Real-time monitoring.

Two front ends feed the same SlidingWindowDetector:
- FileSystemMonitor: polls and diffs snapshots (works everywhere).
- EventMonitor: event-driven via watchdog (FSEvents on macOS, inotify on
  Linux, ReadDirectoryChangesW on Windows), so short-lived changes between
  polls aren't missed.

Why a sliding window: earlier versions counted changes per poll, so an attack
throttled to 1 file per second never crossed "20 deletes in one poll". The
detector now counts events over the last N seconds no matter how they're
spread across polls.

Why inode pairing: ransomware usually writes then renames (report.docx ->
report.docx.encrypted). Comparing by path alone sees that as one delete plus
one create. Matching (device, inode) between snapshots recovers it as a
rename, which is one of the strongest ransomware signals.
"""
import os
import queue
import threading
import time
from collections import Counter, deque
from datetime import datetime

from RansomwareAudit.config.manager import get_config
from RansomwareAudit.engine.risk_engine import RANSOM_EXTENSIONS
from RansomwareAudit.scanner.directory_scanner import iter_files
from RansomwareAudit.scanner.entropy import calculate_entropy

ENTROPY_SAMPLE = 65_536
MAX_ENTROPY_CHECKS_PER_BATCH = 50


def threat_level(score):
    if score >= 15:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    return "MEDIUM"


class SlidingWindowDetector:
    """Keeps recent file events and scores them over a time window."""

    def __init__(self, window_seconds=30, mass_modify=50, mass_delete=20, mass_rename=10,
                 entropy_threshold=7.5):
        self.window = window_seconds
        self.mass_modify = mass_modify
        self.mass_delete = mass_delete
        self.mass_rename = mass_rename
        self.entropy_threshold = entropy_threshold
        self.events = deque()  # (timestamp, kind, path, flags)

    @classmethod
    def from_config(cls, cfg=None):
        cfg = cfg or get_config()
        return cls(window_seconds=cfg.get("monitoring.sliding_window_seconds", 30),
                   mass_modify=cfg.get("monitoring.mass_modify_count", 50),
                   mass_delete=cfg.get("monitoring.mass_delete_count", 20),
                   mass_rename=cfg.get("monitoring.mass_rename_count", 10),
                   entropy_threshold=cfg.get("scanner.entropy_threshold", 7.5))

    def record(self, kind, path, ts=None, entropy=None):
        """kind is one of created, modified, deleted, renamed, chmod."""
        flags = set()
        if os.path.splitext(path)[1].lower() in RANSOM_EXTENSIONS and kind in ("created", "renamed"):
            flags.add("ransom_ext")
        if entropy is not None and entropy >= self.entropy_threshold:
            flags.add("high_entropy")
        self.events.append((ts or time.time(), kind, path, frozenset(flags)))

    def _expire(self, now):
        while self.events and now - self.events[0][0] > self.window:
            self.events.popleft()  # O(1), this is why it's a deque and not a list

    def evaluate(self, now=None):
        now = now or time.time()
        self._expire(now)
        kinds = Counter(e[1] for e in self.events)
        score = 0
        alerts = []

        if kinds["modified"] >= self.mass_modify:
            score += 10
            alerts.append(f"Mass modification: {kinds['modified']} files in {self.window}s")
        if kinds["deleted"] >= self.mass_delete:
            score += 8
            alerts.append(f"Mass deletion: {kinds['deleted']} files in {self.window}s")
        if kinds["renamed"] >= self.mass_rename:
            score += 8
            alerts.append(f"Mass rename: {kinds['renamed']} files in {self.window}s")

        ransom = sum(1 for e in self.events if "ransom_ext" in e[3])
        if ransom:
            score += min(15, 3 * ransom)
            alerts.append(f"Ransomware-style extensions appeared on {ransom} files")

        high_entropy = sum(1 for e in self.events if "high_entropy" in e[3])
        if high_entropy:
            score += min(10, 2 * high_entropy)
            alerts.append(f"High-entropy writes: {high_entropy} files")

        repeats = Counter(e[2] for e in self.events if e[1] == "modified")
        hot = [p for p, c in repeats.items() if c > 3]
        if hot:
            score += 5
            alerts.append(f"Rapid repeated modifications: {len(hot)} files")

        return score, alerts


def _signature(st):
    return {"dev": st.st_dev, "ino": st.st_ino, "size": st.st_size,
            "mtime": st.st_mtime, "mode": st.st_mode}


def diff_snapshots(old, new):
    """Compare two {path: signature} snapshots. Renames are matched by inode."""
    changes = {"created": [], "modified": [], "deleted": [], "renamed": [], "chmod": []}
    created = [p for p in new if p not in old]
    deleted = [p for p in old if p not in new]

    deleted_by_inode = {(old[p]["dev"], old[p]["ino"]): p for p in deleted}
    renamed_from = set()
    for path in created:
        key = (new[path]["dev"], new[path]["ino"])
        src = deleted_by_inode.get(key)
        if src is not None and src not in renamed_from:
            renamed_from.add(src)
            changes["renamed"].append((src, path))
            if new[path]["size"] != old[src]["size"] or new[path]["mtime"] != old[src]["mtime"]:
                changes["modified"].append(path)
        else:
            changes["created"].append(path)
    changes["deleted"] = [p for p in deleted if p not in renamed_from]

    for path in new:
        if path in old:
            a, b = old[path], new[path]
            if a["size"] != b["size"] or a["mtime"] != b["mtime"] or a["ino"] != b["ino"]:
                changes["modified"].append(path)
            elif a["mode"] != b["mode"]:
                changes["chmod"].append(path)
    return changes


class FileSystemMonitor:
    """Polling monitor. Call poll_once() yourself, or start_monitoring() to loop."""

    def __init__(self, watch_paths, callback=None, cfg=None, detector=None):
        self.cfg = cfg or get_config()
        self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
        self.callback = callback
        self.exclude = set(self.cfg.get("scanner.exclude_directories", []))
        self.detector = detector or SlidingWindowDetector.from_config(self.cfg)
        self.file_states = {}
        self.alert_history = []
        self.running = False

    def scan_directory(self, path):
        snapshot = {}
        for filepath in iter_files(path, self.exclude):
            try:
                snapshot[filepath] = _signature(os.stat(filepath))
            except OSError:
                continue
        return snapshot

    def prime(self):
        for path in self.watch_paths:
            self.file_states[path] = self.scan_directory(path)

    def poll_once(self, now=None):
        """Diff every watched path once, feed the detector, return an alert dict or None."""
        now = now or time.time()
        new_events = 0
        last_changes = None
        for path in self.watch_paths:
            new_state = self.scan_directory(path)
            changes = diff_snapshots(self.file_states.get(path, {}), new_state)
            self.file_states[path] = new_state
            last_changes = changes

            checks = 0
            for kind in ("created", "modified", "deleted", "chmod"):
                for p in changes[kind]:
                    entropy = None
                    if kind in ("created", "modified") and checks < MAX_ENTROPY_CHECKS_PER_BATCH:
                        entropy = calculate_entropy(p, max_bytes=ENTROPY_SAMPLE)
                        checks += 1
                    self.detector.record(kind, p, now, entropy)
                    new_events += 1
            for src, dst in changes["renamed"]:
                self.detector.record("renamed", dst, now)
                new_events += 1

        if not new_events:
            return None
        score, alerts = self.detector.evaluate(now)
        if score <= 0:
            return None
        alert = {"timestamp": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
                 "epoch": now, "threat_level": threat_level(score),
                 "threat_score": score, "alerts": alerts}
        self.alert_history.append(alert)
        if self.callback:
            self.callback(alert["threat_level"], score, alerts, last_changes)
        return alert

    def start_monitoring(self, interval=None):
        interval = interval or self.cfg.get("monitoring.interval_seconds", 5)
        self.running = True
        print(f"[*] Polling {', '.join(self.watch_paths)} every {interval}s "
              f"(window {self.detector.window}s). Ctrl+C to stop.")
        self.prime()
        try:
            while self.running:
                time.sleep(interval)
                alert = self.poll_once()
                if alert:
                    _print_alert(alert)
        except KeyboardInterrupt:
            pass
        self.stop_monitoring()

    def stop_monitoring(self):
        self.running = False
        print(f"\n[+] Total alerts: {len(self.alert_history)}")

    def get_alert_history(self):
        return self.alert_history


class EventMonitor:
    """Event-driven monitor using watchdog.

    The watchdog callback only pushes onto a queue (fast, so bursts don't drop
    events). A worker thread drains the queue, checks entropy, and scores.
    """

    def __init__(self, watch_paths, callback=None, cfg=None, detector=None):
        from watchdog.observers import Observer  # optional dependency

        self.cfg = cfg or get_config()
        self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
        self.callback = callback
        self.exclude = set(self.cfg.get("scanner.exclude_directories", []))
        self.detector = detector or SlidingWindowDetector.from_config(self.cfg)
        self.events = queue.Queue()
        self.alert_history = []
        self._stop = threading.Event()
        self._observer = Observer()

    def _excluded(self, path):
        parts = set(path.split(os.sep))
        return bool(parts & self.exclude)

    def _make_handler(self):
        from watchdog.events import FileSystemEventHandler
        q = self.events
        excluded = self._excluded

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.is_directory:
                    return
                kind = {"created": "created", "modified": "modified", "deleted": "deleted",
                        "moved": "renamed", "closed": None, "opened": None}.get(event.event_type)
                if kind is None:
                    return
                path = getattr(event, "dest_path", None) if kind == "renamed" else event.src_path
                if path and not excluded(path):
                    q.put((time.time(), kind, path))

        return Handler()

    def _worker(self):
        while not self._stop.is_set():
            batch = []
            try:
                batch.append(self.events.get(timeout=1))
                while len(batch) < 1000:
                    batch.append(self.events.get_nowait())
            except queue.Empty:
                pass
            if not batch:
                continue
            checks = 0
            for ts, kind, path in batch:
                entropy = None
                if kind in ("created", "modified") and checks < MAX_ENTROPY_CHECKS_PER_BATCH and os.path.isfile(path):
                    entropy = calculate_entropy(path, max_bytes=ENTROPY_SAMPLE)
                    checks += 1
                self.detector.record(kind, path, ts, entropy)
            score, alerts = self.detector.evaluate()
            if score > 0:
                alert = {"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "epoch": time.time(),
                         "threat_level": threat_level(score), "threat_score": score, "alerts": alerts}
                self.alert_history.append(alert)
                _print_alert(alert)
                if self.callback:
                    self.callback(alert["threat_level"], score, alerts, None)

    def start(self):
        handler = self._make_handler()
        for path in self.watch_paths:
            self._observer.schedule(handler, path, recursive=True)
        self._observer.start()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._observer.stop()
        self._observer.join()

    def run_forever(self):
        print(f"[*] Watching {', '.join(self.watch_paths)} for file events "
              f"(window {self.detector.window}s). Ctrl+C to stop.")
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        self.stop()
        print(f"\n[+] Total alerts: {len(self.alert_history)}")


def _print_alert(alert):
    print(f"\n[{alert['timestamp']}] *** {alert['threat_level']} (score {alert['threat_score']}) ***")
    for a in alert["alerts"]:
        print(f"  ! {a}")
