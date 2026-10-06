# Changelog

## Hardening & correctness pass

Detection
- **ML features fixed.** Executable/world-writable/size/recent-modified features
  were silently always-zero (string permission mismatch, wrong size key, ISO
  timestamp parsed as float). All six features now read the real report fields.
- **Entropy is chunked and sampled**, so large files no longer load entirely
  into memory.
- **Type-aware entropy scoring.** High entropy in a `.zip`/`.jpg` is expected
  and nearly ignored; near-random bytes in a file that should be text score
  high. Handles `name.docx.encrypted` by looking at the inner type.
- **Overall risk uses worst-file + spread instead of an average**, so a single
  encrypted file among many clean ones is no longer averaged away.

Real-time monitoring
- **Sliding-window detector**: events are scored over a trailing time window,
  so a throttled (slow) attack is no longer missed by per-poll thresholds.
- **Rename detection by inode**, so write-then-rename isn't misread as an
  unrelated delete + create.
- **Event-based monitor** (watchdog/FSEvents/inotify) added alongside polling,
  with a queue + worker so bursts don't drop events.

Quarantine
- Files are **encrypted at rest**, stored under their **SHA-256** with a
  `.qbin` name, and made **owner-read-only** (POSIX) / ACL-restricted (Windows).
- **Restore verifies the hash** and refuses to overwrite an existing file.

Security
- Dashboard no longer runs with `debug=True`, binds to `127.0.0.1`, and
  **requires a per-session token** on every API call. Scans are limited to
  configured roots. Output is HTML-escaped (XSS) and the entropy chart data is
  JSON-escaped.
- Network server/client now require a shared token; list limits are capped.
- Backup extraction is protected against **path traversal** and symlink escape.

Plumbing
- **`config.yaml` is actually read** now (deep-merged over defaults); thresholds
  are no longer hardcoded. `--threshold` and `--dry-run` added to the scanner.
- Removed the fake hardcoded compliance report; the summary is derived from the
  scan.
- Removed unused/placeholder remediation scripts and dead code paths.

Testing
- Added `evaluate.py`, a detection harness that scores the scanner against the
  simulator's ground truth (precision/recall/F1), runs benign workloads to
  measure false positives, and measures monitor latency.
- Added a `pytest` suite (28 tests) covering scanner, ML features, risk scoring,
  quarantine containment/restore, the sliding-window monitor, config merging,
  and a metamorphic test (compressing benign files must not look like an attack).

Repo
- Honest README with an explicit Limitations section.
- Accurate `.gitignore`; removed generated reports and personal scan data.
