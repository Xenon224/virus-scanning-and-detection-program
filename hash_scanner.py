import hashlib
import os

# ── CONFIG ──────────────────
# Path to our signature database
SIGNATURES_DB = os.path.join(os.path.dirname(__file__), "data", "signatures.db")

def load_signatures():
    """
    reads signatures.db and loads all hashes into a set
    """

    signatures = set()

    try:
        with open(SIGNATURES_DB,"r") as f:
            for line in f:
                line = line.strip()
                #skip empty lines and comments
                if line and not line.startswith("#"):
                    signatures.add(line.lower())
    except FileNotFoundError:
        print(f"[WARNING] Signature database not found at {SIGNATURES_DB}")

    return signatures

def compute_hash(file_path):
    """
    reads a file in chunks and computes its SHA256 hash
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path,"rb") as f: # rb = read binary
            while chunck := f.read(65536): # 65536 bytes = 64KB per chunk
                sha256.update(chunck) # feed each chunk into the hasher

        return sha256.hexdigest()
    
    except (PermissionError,FileNotFoundError,OSError):
        # can't read the file, skip it
        return None
    
def scan_file(file_path , signatures = None):
    """
    Main function. Takes a file path, hashes it, checks against signatures
    """
    if signatures is None:
        signatures = load_signatures()

    file_hash = compute_hash(file_path)

    if file_hash == None:
        ## couldn't read the file
        return None
    
    if file_hash in signatures:
        alert = (
            f"[HASH MATCH] Malicious file detected!\n"
            f"  File : {file_path}\n"
            f"  Hash : {file_hash}"
        )
        return alert
    
    return None #clean file , no match

def scan_directory(directory):
    """
    walks through every file in a directory (and subdirectories),
    runs each one through scan_file().
    """
    print(f"\n[HASH SCANNER] Scanning directory: {directory}\n")

    signatures = load_signatures()
    print(f"[HASH SCANNER] Loaded {len(signatures)} signatures from database.\n")

    alerts = []
    scanned = 0

    for root , dir , files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root,filename)
            result = scan_file(file_path,signatures)
            scanned += 1

            if result:
                print(result)
                alerts.append(result)

    print(f"\n[HASH SCANNER] Scanned {scanned} files. Found {len(alerts)} threat(s).")
    return alerts

# ── RUN IT ──────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Scan a file      : python hash_scanner.py <file_path>")
        print("  Scan a directory : python hash_scanner.py <directory_path>")
    else:
        target = sys.argv[1]

        if os.path.isfile(target):
            sigs = load_signatures()
            result = scan_file(target, sigs)
            if result:
                print(result)
            else:
                print(f"[CLEAN] No threats found in: {target}")

        elif os.path.isdir(target):
            scan_directory(target)

        else:
            print(f"[ERROR] Path not found: {target}")