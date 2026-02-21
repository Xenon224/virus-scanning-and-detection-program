import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hash_scanner import scan_file as hash_scan, load_signatures
from heuristic_scanner import scan_file as heuristic_scan, print_result

# ── LOGGING SETUP ──────────────────

LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "alerts.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH),      # writes to logs/alerts.log
        logging.StreamHandler()             # also prints to console
    ]
)

logger = logging.getLogger("AV_Watcher")

# ── EVENT HANDLER ──────────────────

class MalwareEventHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()

        self.signatures = load_signatures()
        logger.info(f"Watcher initialized. Loaded {len(self.signatures)} signatures.")

    def _scan_file(self, file_path):
            """
            runs both scanners on a file and logs results
            """
            # Small delay 
            time.sleep(0.5)

            if not os.path.isfile(file_path):
                return  # file might have been deleted in that 0.5s, skip

            logger.info(f"Scanning new/modified file: {file_path}")

            # ── Hash Scan ──
            hash_alert = hash_scan(file_path, self.signatures)
            if hash_alert:
                logger.warning(hash_alert)

            # ── Heuristic Scan ──
            heuristic_result = heuristic_scan(file_path)
            if heuristic_result and heuristic_result["verdict"] != "CLEAN":
                logger.warning(
                    f"[{heuristic_result['verdict']}] {file_path} | "
                    f"Score: {heuristic_result['score']} | "
                    f"Entropy: {heuristic_result['entropy']} | "
                    f"Hits: {[d for d, s in heuristic_result['hits']]}"
                )
                print_result(heuristic_result)

            # If both came back clean
            if not hash_alert and (
                heuristic_result is None or heuristic_result["verdict"] == "CLEAN"
            ):
                logger.info(f"[CLEAN] {file_path}")

    def on_created(self, event):
            """starts when a new file is created in the watched directory"""
            if event.is_directory:
                return  # we don't care about folder creation, only files
            self._scan_file(event.src_path)

    def on_modified(self, event):
        """starts when an existing file is modified"""
        if event.is_directory:
            return
        self._scan_file(event.src_path)

# ── WATCHER CONTROL ──────────────────

def start_watcher(watch_path):
    """
    Starts watching a directory. Runs indefinitely unitl interrupted
    """
    if not os.path.isdir(watch_path):
        logger.error(f"Watch path does not exist: {watch_path}")
        return

    event_handler = MalwareEventHandler()
    observer = Observer()

    observer.schedule(
        event_handler,
        path=watch_path,
        recursive=True      # watch all subdirectories too
    )

    observer.start()
    logger.info(f"Watching directory: {watch_path}")
    logger.info("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)   # keep main thread alive while observer runs in background

    except KeyboardInterrupt:
        logger.info("Watcher stopped by user.")
        observer.stop()

    observer.join()         # wait for observer thread to fully finish

    return False    # timed out
# ── RUN IT ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python directory_watcher.py <directory_to_watch>")
        print("Example: python directory_watcher.py ./test_folder")
    else:
        start_watcher(sys.argv[1])