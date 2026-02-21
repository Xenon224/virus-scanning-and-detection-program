import os
import math

# ── PATTERN DEFINITIONS ──────────────────
# Each pattern is a tuple: (pattern_string, score, description)
# Score represents how suspicious this pattern is on its own

TEXT_PATTERNS = [
    # (pattern,                   score, description)

    # -- Execution / Shell
    ("cmd /c",                      2, "Silent command execution"),
    ("powershell -enc",             3, "Encoded PowerShell — common obfuscation"),
    ("powershell -w hidden",        3, "Hidden PowerShell window"),
    ("wscript.shell",               2, "Windows Script Host shell execution"),
    ("winexec",                     2, "Legacy execution API, rarely used legitimately"),
    ("shellexecute",                1, "Program launch API"),

    # -- Process Injection
    ("createremotethread",          3, "Code injection into another process"),
    ("virtualallocex",              3, "Memory allocation in remote process"),
    ("writeprocessmemory",          3, "Writing into another process — injection"),
    ("ntunmapviewofsection",        3, "Process hollowing technique"),

    # -- Persistence
    ("reg add",                     2, "Registry modification — persistence"),
    ("schtasks /create",            2, "Scheduled task creation — persistence"),
    ("net user /add",               3, "Backdoor account creation"),
    ("startup",                     1, "Reference to startup folder"),

    # -- Credential Access
    ("mimikatz",                    3, "Known credential dumping tool"),
    ("lsass",                       2, "Accessing LSASS — credential theft target"),
    ("sekurlsa",                    3, "Mimikatz module for credential extraction"),

    # -- Network / C2
    ("http://",                     1, "Hardcoded HTTP URL"),
    ("https://",                    1, "Hardcoded HTTPS URL"),
    ("socket.connect",              1, "Network connection"),
    ("wget ",                       1, "File download utility"),
    ("curl ",                       1, "File download utility"),
    ("downloadfile",                2, "Downloading files — dropper behavior"),
    ("bitsadmin",                   2, "BITS abuse for downloading malware"),

    # -- Obfuscation
    ("base64",                      1, "Base64 encoding — payload obfuscation"),
    ("frombase64string",            2, "Decoding base64 — unpacking payload"),
    ("char(",                       1, "Character encoding — obfuscation"),
    ("xor",                         1, "XOR encryption — common in shellcode"),

    # -- AV Evasion
    ("taskkill",                    2, "Killing processes — possible AV termination"),
    ("netsh firewall",              2, "Firewall rule modification"),
    ("bcdedit",                     2, "Boot config edit — disabling recovery"),
    ("vssadmin delete",             3, "Deleting shadow copies — ransomware behavior"),

    # -- Test Signature
    ("eicar-standard-antivirus-test-file", 10, "EICAR AV test string detected"),
]

# Raw byte patterns (hex sequences known to appear in malware)
# Format: (hex_string, score, description)
BYTE_PATTERNS = [
    # EICAR test file starts with these bytes
    ("584234215024404021", 10, "EICAR test file byte signature"),

    # Common shellcode prologue (push ebp / mov ebp esp)
    ("5589e5",              2, "x86 function prologue — possible shellcode"),

    # XOR loop pattern common in shellcode decoders
    ("eb0c",               1, "Short jump — possible obfuscation loop"),
]

# ── SCORING THRESHOLDS ──────────────────
THRESHOLD_SUSPICIOUS    = 3
THRESHOLD_MALICIOUS     = 6

# ── FILE TYPES TO SCAN ──────────────────
# We focus on executable and script types
# Scanning every .jpg and .mp3 is wasteful
SCANNABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".py", ".sh", ".php", ".asp",
    ".aspx", ".rb", ".pl", ".com", ".scr", ".hta"
}

def compute_entropy(data):
    """
    computes Shannon entropy of a byte string.
    Entropy measures randomness — 0 is completely uniform, 8 is completely random

    normal executables have entropy around 4-6.
    encrypted or packed malware (UPX, custom packers) has entropy close to 8

    catches packed malware that hides its actual code until runtime
    """

    if not data:
        return 0
    
    # Count frequency of each byte value (0-255)
    freq = [0]*256
    for byte in data:
        freq[byte] += 1

    # Shannon entropy formula
    """
    Simplified intuition:
    for each byte_value in 0..255:
    probability = how_often_it_appears / total_bytes
    entropy -= probability * log2(probability)
                                       ↑
                    this is the "surprise" of seeing this byte
    """
    
    entropy = 0
    length = len(data)
    for count in freq:
        if count == 0 :
            continue
        
        probablity = count/length
        entropy -= probablity * math.log2(probablity)
    
    return entropy

def scan_text_patterns(content):
    """
    scans file content (as lowercase string) against TEXT_PATTERNS
    returns list of (description, score) tuples for every match found
    """
    hits = []
    for pattern , score , description in TEXT_PATTERNS:
        if pattern.lower() in content:
            hits.append((description,score))
    
    return hits

def scan_byte_patterns(raw_bytes):
    """
    scans raw file bytes against BYTE_PATTERNS.
    converts file to hex string once, then searches for hex sequences.
    """
    hits = []
    hex_content = raw_bytes.hex()
    for hex_pattern, score, description in BYTE_PATTERNS:
        if hex_pattern.lower() in hex_content:
            hits.append((description, score))
    return hits

def scan_file(file_path):
    """
    Main heuristic scan function for a single file.
    Returns a dict with full results, or None if file can't be read.

    Dict structure:
    {
        "file"      : path,
        "score"     : total suspicion score,
        "verdict"   : CLEAN / SUSPICIOUS / LIKELY MALICIOUS,
        "hits"      : list of matched patterns with scores,
        "entropy"   : file entropy value
    }
    """
    # Skip files with extensions we don't care about
    ext = os.path.splitext(file_path)[1].lower()

    if ext not in SCANNABLE_EXTENSIONS:
        return None

    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except (PermissionError, FileNotFoundError, OSError):
        return None

    # Decode to text for string scanning — errors='ignore' skips unreadable bytes
    content_lower = raw_bytes.decode("utf-8", errors="ignore").lower()

    # Run all scans
    text_hits  = scan_text_patterns(content_lower)
    byte_hits  = scan_byte_patterns(raw_bytes)
    entropy    = compute_entropy(raw_bytes)

    all_hits = text_hits + byte_hits

    # Entropy bonus — high entropy suggests packing/encryption
    entropy_score = 0
    if entropy > 7.2:
        all_hits.append(("High entropy — file may be packed or encrypted", 2))
        entropy_score = 2

    total_score = sum(score for _, score in all_hits)

    # Determine verdict
    if total_score >= THRESHOLD_MALICIOUS:
        verdict = "LIKELY MALICIOUS"
    elif total_score >= THRESHOLD_SUSPICIOUS:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "file"    : file_path,
        "score"   : total_score,
        "verdict" : verdict,
        "hits"    : all_hits,
        "entropy" : round(entropy, 3),
    }

def print_result(result):
    """
    Pretty prints the result dict from scan_file().
    """
    if result is None:
        return

    verdict = result["verdict"]

    # Only print if something was found
    if verdict == "CLEAN":
        return

    print(f"\n{'='*55}")
    print(f"  [{verdict}] {result['file']}")
    print(f"{'='*55}")
    print(f"  Score   : {result['score']}")
    print(f"  Entropy : {result['entropy']}")
    print(f"  Hits    :")
    for description, score in result["hits"]:
        print(f"    [+{score}] {description}")
    print(f"{'='*55}")


def scan_directory(directory):
    """
    Walks a directory and heuristically scans all scannable files.
    Returns list of non-clean results.
    """
    print(f"\n[HEURISTIC SCANNER] Scanning: {directory}\n")

    results  = []
    scanned  = 0
    flagged  = 0

    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            result = scan_file(file_path)

            if result is None:
                continue    # skipped (wrong extension or unreadable)

            scanned += 1

            if result["verdict"] != "CLEAN":
                print_result(result)
                results.append(result)
                flagged += 1

    print(f"\n[HEURISTIC SCANNER] Scanned {scanned} files. Flagged {flagged}.")
    return results


# ── RUN IT ──────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Scan a file      : python heuristic_scanner.py <file_path>")
        print("  Scan a directory : python heuristic_scanner.py <directory_path>")
    else:
        target = sys.argv[1]

        if os.path.isfile(target):
            result = scan_file(target)
            if result:
                print_result(result)
                if result["verdict"] == "CLEAN":
                    print(f"[CLEAN] {target}")
            else:
                print(f"[SKIPPED] File type not in scan list: {target}")

        elif os.path.isdir(target):
            scan_directory(target)

        else:
            print(f"[ERROR] Path not found: {target}")
