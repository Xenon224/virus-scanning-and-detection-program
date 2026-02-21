# 🛡️ Lightweight virus detection Tool

A lightweight, modular antivirus tool built in Python for understanding how real AV software works under the hood. Covers the three core detection layers used by commercial antivirus engines — signature-based detection, heuristic analysis, and real-time monitoring.

> Built for learning. Every part is documented, explained, and designed to be readable.

---

## How It Works

It runs three detection layers simultaneously:

**Signature Detection** — Computes SHA256 hashes of files and checks them against a local database of known malicious hashes. Fast and accurate for known threats.

**Heuristic Analysis** — Scans file contents for suspicious patterns, strings, and API calls commonly found in malware (encoded PowerShell, process injection calls, persistence mechanisms, etc.). Also computes Shannon entropy to catch packed or encrypted malware that hides its content.

**Real-Time Monitoring** — Watches directories for new or modified files and automatically scans them the moment they appear. Mirrors how on-access scanning works in commercial AV tools.

---

## Project Structure

```
antivirus/
├── main.py                  # CLI entry point — run everything from here
├── process_monitor.py       # Scans running processes for suspicious behavior
├── hash_scanner.py          # SHA256 signature-based file detection
├── heuristic_scanner.py     # Pattern + entropy based file analysis
├── directory_watcher.py     # Real-time directory monitoring
├── data/
│   └── signatures.db        # Known bad hash database (one SHA256 per line)
└── logs/
    └── alerts.log           # All alerts logged here automatically
```

---

## Installation

**Requirements:** Python 3.8+

```bash
git clone https://github.com/yourusername/pyav.git
cd pyav
pip install psutil watchdog
```

---

## Usage

Everything runs through `main.py`.

```bash
# Scan a single file
python main.py --scan-file suspicious.exe

# Scan an entire directory (runs in parallel)
python main.py --scan-dir ./Downloads

# Scan all currently running processes
python main.py --processes

# Watch a directory in real-time (Ctrl+C to stop)
python main.py --monitor ./Downloads

# Watch current directory
python main.py --monitor

# Run everything — process scan + directory scan + real-time monitor
python main.py --full ./Downloads

# Help
python main.py --help
```

---

## Detection Capabilities

### Signature Detection
Matches files by SHA256 hash against `data/signatures.db`. To add your own signatures:

```
# data/signatures.db
# One SHA256 hash per line, lines starting with # are comments
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
<add more hashes here>
```

Get a file's hash:
```bash
# Linux / Mac
sha256sum suspicious_file.exe

# Windows (PowerShell)
Get-FileHash suspicious_file.exe -Algorithm SHA256
```

### Heuristic Detection
Scans for suspicious patterns grouped by category:

| Category | Examples |
|---|---|
| Execution / Shell | `cmd /c`, `powershell -enc`, `WinExec` |
| Process Injection | `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory` |
| Persistence | `reg add`, `schtasks /create`, `net user /add` |
| Credential Access | `mimikatz`, `lsass`, `sekurlsa` |
| Network / C2 | Hardcoded URLs, `DownloadFile`, `bitsadmin` |
| Obfuscation | `base64`, `FromBase64String`, XOR patterns |
| AV Evasion | `taskkill`, `vssadmin delete`, `bcdedit` |

Each match contributes to a suspicion score. Files are rated:

```
Score 0–2  →  CLEAN
Score 3–5  →  SUSPICIOUS
Score 6+   →  LIKELY MALICIOUS
```

### Entropy Analysis
Files with Shannon entropy above 7.2 are flagged as potentially packed or encrypted — a common technique malware uses to hide its content from string-based scanners.

### Process Monitoring
Checks all running processes against:
- Known malicious process names
- Suspicious execution paths (`Temp`, `AppData\Roaming`, `Downloads`)
- Abnormal CPU or memory usage

---

## Logging

All alerts are written to `logs/alerts.log` with timestamps and severity levels. The log persists across runs so you have a full audit trail.

```
2026-02-21 14:30:22 [WARNING] [LIKELY MALICIOUS] ./test_folder/bad.bat | Score: 8 | Hits: ['Encoded PowerShell', 'Backdoor account creation', 'Deleting shadow copies']
2026-02-21 14:30:23 [INFO]    [CLEAN] ./test_folder/readme.txt
```

---

## Limitations

This is an educational project. It operates at user level, not kernel level, which means:

- **No kernel hooks** — processes are scanned after they start, not intercepted before execution
- **Local signatures only** — no cloud lookup, database is as current as you keep it
- **No PE analysis** — does not parse executable headers or import tables
- **No sandboxing** — files are scanned statically, not executed in isolation

These are the exact problems that separate tools like CrowdStrike or Windows Defender from a user-space scanner. Understanding why these limitations exist is half the point of building this.

---

## Concepts Covered

By building and reading this project you'll understand:

- How signature-based detection works and why hash matching is both powerful and limited
- What heuristic detection is and how scoring reduces false positives
- What Shannon entropy is and why high entropy indicates packed/encrypted malware
- How real-time on-access scanning works at the OS filesystem event level
- Why commercial AVs use kernel drivers instead of user-space tools
- How multithreading improves scan performance for I/O-bound workloads
- How the three detection layers (signature, heuristic, behavioral) complement each other

---

## Dependencies

| Package | Purpose |
|---|---|
| `psutil` | Reading live process data |
| `watchdog` | Filesystem event monitoring |
| `hashlib` | SHA256 hashing (built-in) |
| `concurrent.futures` | Parallel file scanning (built-in) |
| `logging` | Unified alert logging (built-in) |
| `argparse` | CLI interface (built-in) |

---

## License

MIT License — use it, break it, learn from it.
