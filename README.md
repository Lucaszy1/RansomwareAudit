# RansomwareAudit

A Python tool that looks for ransomware activity using several independent
signals instead of a single one: file entropy, file metadata and permissions,
real-time behavior (rate of changes, mass renames/deletions), and an
unsupervised machine-learning anomaly model. It ships with a local web
dashboard, an encrypted quarantine vault, optional VirusTotal cross-checks,
and a test/evaluation harness that scores detection against ground truth.

This started as an independent STEM research project. It's a learning and
research tool, not a production antivirus — see **Limitations** before relying
on it for anything real.

## How detection works

No single signal is trustworthy on its own, so the scanner combines a few:

- **Entropy** — Shannon entropy (0–8 bits/byte) over a sampled chunk of each
  file. Encrypted or packed data sits near 8.0. The catch is that legitimately
  compressed files (`.zip`, `.jpg`, `.docx`) look identical, so high entropy is
  weighted by file type: near-random bytes in something that should be text
  (`.txt`, `.csv`, source code) score high, while the same entropy in a `.zip`
  barely counts.
- **Extension & rename heuristics** — ransomware-style extensions
  (`.encrypted`, `.locked`, …) and the original type hidden underneath
  (`report.docx.encrypted` → treated as an encrypted `.docx`).
- **Behavior** — for a one-shot scan, how many files changed recently; for
  real-time monitoring, the *rate* of modifications, renames and deletions over
  a sliding time window.
- **Permissions** — world-writable files and executable types.
- **Machine learning** — an Isolation Forest (unsupervised) trained on six
  per-file features (entropy, log size, executable flag, hidden flag,
  world-writable flag, recently-modified flag) that flags statistical outliers.

Per-file scores roll up into an overall risk level using the **worst** file
plus how widespread high-risk files are, rather than an average — so one
encrypted file among thousands of clean ones still surfaces.

## Install

```bash
pip install -r requirements.txt
```

Python 3.8+. The core scanner needs only `numpy`/`scikit-learn`; `reportlab`
(PDF), `watchdog` (event monitoring) and `psutil` (process blocker) are
optional.

## Usage

```bash
# Scan a folder, write JSON + HTML + CSV reports
python3 -m RansomwareAudit.run ~/Documents --html --csv flagged.csv

# Add the ML signal (needs a trained model, see below)
python3 -m RansomwareAudit.run ~/Documents --ml

# See what would be quarantined without touching anything
python3 -m RansomwareAudit.run ~/Documents --quarantine --dry-run

# Quarantine files scoring >= 8, then list / restore them
python3 -m RansomwareAudit.run ~/Documents --quarantine --threshold 8
python3 -m RansomwareAudit.quarantine_cli list
python3 -m RansomwareAudit.quarantine_cli restore <id-prefix>

# Real-time monitoring (polling, or --events for OS file events)
python3 -m RansomwareAudit.monitor_run ~/Documents
python3 -m RansomwareAudit.monitor_run ~/Documents --events

# Train the ML model from a scan report, then reuse it
python3 -m RansomwareAudit.ml.trainer ransomware_risk_report.json
```

Exit code is `2` when `--fail-on HIGH` (or another level) is set and the scan
meets it, which is handy in CI.

### Web dashboard

```bash
python3 -m RansomwareAudit.web.app
```

It binds to `127.0.0.1` only and prints a URL containing a one-time access
token (`http://localhost:5001/#token=…`). Every API call requires that token,
so other sites and other machines can't drive it. Dashboard scans are
restricted to folders under `web_dashboard.allowed_scan_roots` in
`config.yaml`.

## Quarantine design

Quarantine is containment, not just relocation:

1. File **contents are encrypted** (Fernet / AES-128-CBC + HMAC) on the way in,
   so the stored bytes aren't a runnable executable or openable document on any
   OS.
2. Stored under its **SHA-256 with a `.qbin` name**, which removes any
   file-type association. The real name lives only in the manifest.
3. **Permissions** are tightened to owner-read-only on POSIX; on Windows,
   inheritance is stripped with `icacls`.
4. **Restore verifies** the SHA-256 before writing, and refuses to overwrite an
   existing file unless forced.

The encryption key lives in the vault (`0600`), so this protects against
accidental execution and tampering, not against an attacker who already has the
user's account. Full isolation would run the vault under a separate service
account — noted as future work.

## Testing & evaluation

```bash
pytest                 # 28 unit + metamorphic tests
python3 evaluate.py    # detection accuracy vs the simulator's ground truth
python3 evaluate.py --latency
```

`ransomware_simulator.py` builds a clean folder, then overwrites a known subset
of files and renames them `.encrypted`, recording exactly which files it hit.
That list is the answer key. `evaluate.py` runs the scanner against it and
reports precision/recall/F1, runs benign high-churn workloads (zip backup, gzip
log rotation, bulk edits) to measure false positives, and measures real-time
detection latency.

On the bundled simulator, static detection catches the attack cleanly
(the `.encrypted` rename plus random bytes in text files is an easy case) with
no false positives on the benign workloads. The more interesting result is
latency: a fast attack finishes inside one polling interval, so most files are
already encrypted before the first alert, while a throttled attack is caught
after only a handful of files — which is exactly why the monitor scores a
sliding window rather than per-poll counts.

## Limitations

These are real and worth stating plainly:

- **The simulator is easier to detect than real ransomware.** Random bytes have
  maximal entropy and the `.encrypted` extension is a giveaway. Real variants
  use real encryption, keep original extensions, or partially encrypt files.
  Validation here is against the simulator, not a corpus of real samples.
- **Entropy vs. legitimate encryption** is only partly solved by the file-type
  weighting; a genuinely encrypted backup tool could still trip it.
- **No process attribution.** Polling and file-event monitoring can't say
  *which* process made a change. That needs OS-level facilities (Endpoint
  Security on macOS, ETW/minifilters on Windows, fanotify on Linux). The
  `monitor.blocker` module is an experimental prototype and reports only unless
  run with `--kill`.
- **The ML model is unsupervised** — it flags statistical outliers, it is not
  trained on labeled malware, and quality depends entirely on the baseline it's
  trained on.

## Project layout

~4,200 lines of Python across 16 packages (plus the dashboard's HTML/CSS/JS).

```
RansomwareAudit/
  scanner/       entropy, permissions, metadata, directory walk
  engine/        risk scoring
  behavior/      one-shot behavior snapshot
  monitor/       real-time monitoring (polling + event-based) and blocker
  ml/            Isolation Forest model, trainer, features
  quarantine/    encrypted quarantine vault
  backup/        tar.gz backups with path-traversal protection
  reporting/     JSON/HTML/compliance reports
  reports/       PDF report
  integrations/, virustotal/   VirusTotal hash lookups
  notifications/ email/Slack alerts
  network/       central server + client
  web/           Flask dashboard
  config/        config.yaml loader
evaluate.py            detection evaluation harness
ransomware_simulator.py  labeled test-data generator
tests/                 pytest suite
```

## License

MIT — see `LICENSE`.
