import argparse
import logging
import os
import sys
import concurrent.futures

from process_monitor import scan_processes
from hash_scanner import scan_file as hash_scan, scan_directory as hash_scan_dir, load_signatures
from heuristic_scanner import scan_file as heuristic_scan, scan_directory as heuristic_scan_dir, print_result
from directory_watcher import start_watcher

# ── LOGGING SETUP ──────────────────


LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "alerts.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("AV_Main")


# ── SCAN A SINGLE FILE ──────────────────

def cmd_scan_file(file_path):
    """
    runs hash scan + heuristic scan on a single file.
    prints a unified report.
    """
    if not os.path.isfile(file_path):
        logger.error(f"File not found: {file_path}")
        return

    logger.info(f"Scanning file: {file_path}")
    print(f"\n{'='*30}")
    print(f"  FILE SCAN: {file_path}")
    print(f"{'='*30}")

    # ── Hash Scan ──
    signatures = load_signatures()
    hash_alert = hash_scan(file_path, signatures)

    if hash_alert:
        logger.warning(hash_alert)
        print(f"\n  {hash_alert}")
    else:
        print(f"\n  [HASH SCAN]      No signature match found.")

    # ── Heuristic Scan ──
    heuristic_result = heuristic_scan(file_path)

    if heuristic_result is None:
        print(f"  [HEURISTIC SCAN] File type not in scan list — skipped.")
    elif heuristic_result["verdict"] == "CLEAN":
        print(f"  [HEURISTIC SCAN] Clean. Score: {heuristic_result['score']}")
    else:
        logger.warning(
            f"[{heuristic_result['verdict']}] {file_path} | "
            f"Score: {heuristic_result['score']} | "
            f"Hits: {[d for d, s in heuristic_result['hits']]}"
        )
        print_result(heuristic_result)

    print(f"\n  Log saved to: {LOG_PATH}")
    print(f"{'='*60}\n")


# ── SCAN A DIRECTORY ──────────────────

def cmd_scan_dir(directory):
    """
    scans every file in a directory with both scanners
    uses ThreadPoolExecutor to scan files in parallel
    """
    if not os.path.isdir(directory):
        logger.error(f"Directory not found: {directory}")
        return

    logger.info(f"Starting directory scan: {directory}")

    # Collect all files first
    all_files = []
    for root, dirs, files in os.walk(directory):
        for filename in files:
            all_files.append(os.path.join(root, filename))

    print(f"\n{'='*30}")
    print(f"  DIRECTORY SCAN: {directory}")
    print(f"  Found {len(all_files)} files to scan.")
    print(f"{'='*30}\n")

    signatures = load_signatures()
    alerts = []
    scanned = 0

    # ── Parallel scanning with ThreadPoolExecutor ──
    # max_workers=8 means 8 files scanned simultaneously
    # You can tune this number — more workers = faster on multi-core systems
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:

        # Submit all hash scans at once
        hash_futures = {
            executor.submit(hash_scan, f, signatures): f for f in all_files
        }

        # Submit all heuristic scans at once
        heuristic_futures = {
            executor.submit(heuristic_scan, f): f for f in all_files
        }

        # Collect hash results as they complete
        for future in concurrent.futures.as_completed(hash_futures):
            result = future.result()
            scanned += 1
            if result:
                logger.warning(result)
                alerts.append(result)
                print(result)

        # Collect heuristic results as they complete
        for future in concurrent.futures.as_completed(heuristic_futures):
            result = future.result()
            if result and result["verdict"] != "CLEAN":
                logger.warning(
                    f"[{result['verdict']}] {result['file']} | "
                    f"Score: {result['score']} | "
                    f"Hits: {[d for d, s in result['hits']]}"
                )
                print_result(result)
                alerts.append(result)

    print(f"\n{'='*30}")
    print(f"  Scanned : {len(all_files)} files")
    print(f"  Threats : {len(alerts)} found")
    print(f"  Log     : {LOG_PATH}")
    print(f"{'='*30}\n")


# ── SCAN PROCESSES ──────────────────

def cmd_scan_processes():
    """
    Scans all running processes and logs any alerts.
    """
    print(f"\n{'='*30}")
    print(f"  PROCESS SCAN")
    print(f"{'='*30}\n")

    alerts = scan_processes()

    for alert in alerts:
        logger.warning(alert)

    print(f"\n{'='*30}")
    print(f"  Threats : {len(alerts)} found")
    print(f"  Log     : {LOG_PATH}")
    print(f"{'='*30}\n")


# ── WATCH A DIRECTORY ──────────────────

def cmd_watch(directory):
    """
    Starts real-time directory monitoring.
    Runs until Ctrl+C.
    """
    print(f"\n{'='*30}")
    print(f"  REAL-TIME MONITOR: {directory}")
    print(f"  Press Ctrl+C to stop.")
    print(f"{'='*30}\n")

    start_watcher(directory)


# ── FULL SCAN ──────────────────

def cmd_full(directory):
    """
    Runs everything:
    1. Process scan
    2. Full directory scan (hash + heuristic, parallel)
    3. Starts real-time watcher on the directory

    Process scan and directory scan run first, then watcher takes over.
    """
    print(f"\n{'='*30}")
    print(f"  FULL SCAN MODE")
    print(f"  Target: {directory}")
    print(f"{'='*30}\n")

    # Step 1 — processes
    logger.info("Step 1/3 — Scanning running processes...")
    cmd_scan_processes()

    # Step 2 — directory
    logger.info("Step 2/3 — Scanning directory...")
    cmd_scan_dir(directory)

    # Step 3 — watcher
    logger.info("Step 3/3 — Starting real-time monitor...")
    cmd_watch(directory)


# ── CLI SETUP ──────────────────

def build_parser():
    """
    Builds the argparse CLI.
    """
    parser = argparse.ArgumentParser(
        prog="antivirus",
        description="A lightweight antivirus tool — process monitor, file scanner, real-time watcher.",
        formatter_class=argparse.RawTextHelpFormatter   # preserves newlines in help text
    )

    # Mutually exclusive group — only one mode can run at a time
    # This prevents nonsensical combos like --scan-file AND --monitor together
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--scan-file",
        metavar="FILE",
        help="Scan a single file with hash + heuristic scanner.\nExample: python main.py --scan-file suspicious.exe"
    )

    group.add_argument(
        "--scan-dir",
        metavar="DIRECTORY",
        help="Scan all files in a directory (parallel).\nExample: python main.py --scan-dir ./Downloads"
    )

    group.add_argument(
        "--processes",
        action="store_true",
        help="Scan all currently running processes.\nExample: python main.py --processes"
    )

    group.add_argument(
        "--monitor",
        metavar="DIRECTORY",
        nargs="?",              # makes the directory optional
        const=".",              # default to current directory if no path given
        help="Watch a directory in real-time. Defaults to current directory.\nExample: python main.py --monitor ./Downloads"
    )

    group.add_argument(
        "--full",
        metavar="DIRECTORY",
        nargs="?",
        const=".",
        help="Run everything: process scan + directory scan + real-time monitor.\nExample: python main.py --full ./Downloads"
    )

    return parser


# ── ENTRY POINT ──────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    logger.info("Antivirus started.")

    if args.scan_file:
        cmd_scan_file(args.scan_file)

    elif args.scan_dir:
        cmd_scan_dir(args.scan_dir)

    elif args.processes:
        cmd_scan_processes()

    elif args.monitor is not None:
        cmd_watch(args.monitor)

    elif args.full is not None:
        cmd_full(args.full)

    logger.info("Antivirus finished.")


if __name__ == "__main__":
    main()