import psutil
import datetime

# ── SIGNATURE LIST ──────────────────
KNOWN_BAD_PROCESSES = [
    "mimikatz.exe",       # credential dumper
    "netcat.exe",         # reverse shell tool
    "nc.exe",             # netcat alias
    "meterpreter.exe",    # metasploit payload
    "rats.exe",
    "keylogger.exe",
    "nmap.exe",           # port scanner (flagged in many corporate AVs)
]

# ── SUSPICIOUS PATHS ──────────────────
SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\appdata\\roaming\\",
]

# ── THRESHOLDS ──────────────────
CPU_THRESHOLD = 80      
MEMORY_THRESHOLD = 50


def check_process(proc):
    """
    takes a single process and runs it through check systems and return list of alerts
    """
    alerts = []

    try:
        name = proc.name().lower()
        pid = proc.pid
        exe = proc.exe().lower()
        cpu = proc.cpu_percent(interval=0.1)
        mem = proc.memory_percent()
    
        #check name
        if name in KNOWN_BAD_PROCESSES:
            alerts.append(
                f"[Signature Match] Process '{name}' (PID {pid}) using {cpu:.1f}% CPU"
            )
        
        # check path
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in exe:
                alerts.append(
                    f"[Signature Match] Process '{name}' (PID {pid}) running from: {exe}"
                )
        
        #check cpu usage
        if cpu > CPU_THRESHOLD:
            alerts.append(
                f"[HIGH CPU] Process '{name}' (PID {pid}) using {cpu:.1f}% CPU"
            )
        
        #check memory usage
        if mem > MEMORY_THRESHOLD:
            alerts.append(
                f"[HIGH MEM] Process '{name}' (PID {pid}) using {mem:.1f}% memory"
            )
    
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        #ignore if process died or no permission
        pass

    return alerts

def scan_processes():
    """
    loops through every running process in the system
    """
    print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Scanning running processes...\n")

    all_alerts =[]

    for proc in psutil.process_iter():
        alerts = check_process(proc)
        for alert in alerts:
            print(alert)
            all_alerts.append(alert)

    if not all_alerts:
        print("No suspicious processes found.")

    return all_alerts

# ── RUN IT ──────────────────
if __name__ == "__main__":
    scan_processes()