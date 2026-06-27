#!/usr/bin/env python3
# MalScan v1.0 - Enterprise Malware Scanner
# Powered by HackerAI
# For authorized penetration testing and organizational security assessments
# Tested on: Kali Linux / Ubuntu / Parrot OS

import os
import sys
import signal
import time
import subprocess
from datetime import datetime

# Ensure running as root
if os.geteuid() != 0:
    print("\033[1;91m[!] This tool must be run as root for full system access.\033[0m")
    print("\033[1;93m[*] Re-run with: sudo python3 malscan.py\033[0m")
    sys.exit(1)

VERSION = "1.0"
AUTHOR = "HackerAI"

def signal_handler(sig, frame):
    print("\n\033[1;93m[!] Cleaning up...\033[0m")
    cleanup_temp_files()
    print("\033[1;92m[+] MalScan terminated\033[0m")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

PROC_TEMP = "/tmp/malscan_proc.txt"
FILE_TEMP = "/tmp/malscan_file.txt"
REPORT_TEMP = "/tmp/malscan_report.txt"

def cleanup_temp_files():
    for f in [PROC_TEMP, FILE_TEMP, REPORT_TEMP]:
        if os.path.exists(f):
            os.remove(f)

# ============================================================
# BANNER
# ============================================================
def banner():
    os.system("clear")
    colors = [
        "\033[1;91m",  # Red
        "\033[1;92m",  # Green
        "\033[1;93m",  # Yellow
        "\033[1;94m",  # Blue
        "\033[1;95m",  # Magenta
        "\033[1;96m",  # Cyan
    ]
    art = f"""
{colors[0]}  __  __       _ ____                       {colors[2]}Version {VERSION}
{colors[0]} |  \\/  | __ _| / ___|  __ _ ___  ___ __ _  {colors[4]}Enterprise Malware Scanner
{colors[1]} | |\\/| |/ _` | \\___ \\ / _` / __|/ __/ _` | {colors[5]}Kali Linux Edition
{colors[2]} | |  | | (_| | |___) | (_| \\__ \\ (_| (_| |
{colors[3]} |_|  |_|\\__,_|_|____/ \\__,_|___/\\___\\__,_|
{colors[4]}    Authorized Security Testing Only
\033[0m"""
    print(art)

# ============================================================
# DEPENDENCY CHECK
# ============================================================
def dependencies():
    print("\n\033[1;92m[*] Checking dependencies...\033[0m")
    required = {
        "php": "apt-get install php",
        "lsof": "apt-get install lsof",
        "ss": "apt-get install iproute2",
    }
    for cmd, install in required.items():
        if not shutil_which(cmd):
            print(f"\033[1;91m[!] {cmd} not found. Install: {install}\033[0m")
            sys.exit(1)
        else:
            print(f"\033[1;92m[+] {cmd} found\033[0m")

def shutil_which(cmd):
    return subprocess.run(f"which {cmd}", shell=True, capture_output=True, text=True).returncode == 0

# ============================================================
# MODULE 1: Process Anomaly Detection
# ============================================================
def scan_processes():
    print("\n\033[1;94m" + "━"*50)
    print("\033[1;93m [PROCESS SCAN] Checking for malicious processes\033[0m")
    print("\033[1;94m" + "━"*50 + "\033[0m")

    malicious_found = 0
    proc_results = []
    proc_data = []

    # 1. Check suspicious process names
    suspicious_names = [
        "keylog", "xspy", "rootkit", "backdoor", "shell", "reverse",
        "meterp", "beacon", "c2_", "bot_", "miner", "dns2tcp",
        "icmpsh", "pwn", "exploit", "dnscat", "xmrig", "kdevtmpfsi"
    ]
    
    try:
        ps_output = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10).stdout
        for line in ps_output.split("\n"):
            for name in suspicious_names:
                if name.lower() in line.lower():
                    print(f"\033[1;91m[!] Suspicious process: {line.strip()[:100]}\033[0m")
                    proc_results.append(f"[SUSPICIOUS NAME] {line.strip()}")
                    proc_data.append(line.strip())
                    malicious_found += 1
                    break
    except Exception as e:
        print(f"\033[1;91m[!] Error scanning processes: {e}\033[0m")

    # 2. Check processes running from writable directories
    print("\n\033[1;93m[*] Checking processes in writable directories...\033[0m")
    writable_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run"]
    for line in ps_output.split("\n"):
        for wd in writable_dirs:
            if wd in line and len(line.strip()) > 0:
                print(f"\033[1;91m[!] Process in {wd}: {line.strip()[:100]}\033[0m")
                proc_results.append(f"[WRITABLE DIR] {line.strip()}")
                proc_data.append(line.strip())
                malicious_found += 1
                break

    # 3. Check for reverse shell indicators
    print("\n\033[1;93m[*] Checking for reverse shell indicators...\033[0m")
    rs_indicators = ["/dev/tcp/", "/dev/udp/", "ncat", "nc -e", "bash -i", "sh -i", "python -c", "perl -e", "mkfifo"]
    for line in ps_output.split("\n"):
        for indicator in rs_indicators:
            if indicator.lower() in line.lower():
                print(f"\033[1;91m[!] Reverse shell indicator '{indicator}': {line.strip()[:100]}\033[0m")
                proc_results.append(f"[REVERSE SHELL] {line.strip()}")
                proc_data.append(line.strip())
                malicious_found += 1
                break

    # 4. Check for cryptominers by CPU usage
    print("\n\033[1;93m[*] Checking for high CPU usage (potential miners)...\033[0m")
    try:
        ps_cpu = subprocess.run(["ps", "-eo", "pid,pcpu,comm", "--sort=-pcpu"], capture_output=True, text=True, timeout=10).stdout
        for line in ps_cpu.split("\n")[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 3:
                try:
                    cpu = float(parts[1])
                    if cpu > 50:
                        print(f"\033[1;91m[!] High CPU ({cpu}%): {line.strip()}\033[0m")
                        proc_results.append(f"[HIGH CPU] {line.strip()}")
                        proc_data.append(line.strip())
                        malicious_found += 1
                except ValueError:
                    pass
    except Exception as e:
        print(f"\033[1;91m[!] Error checking CPU: {e}\033[0m")

    # Save results
    if proc_data:
        with open(PROC_TEMP, "w") as f:
            f.write("\n".join(proc_data))
    
    if malicious_found == 0:
        print(f"\n\033[1;92m[+] No suspicious processes detected\033[0m")
    else:
        print(f"\n\033[1;91m[!] Total suspicious items: {malicious_found}\033[0m")

    input("\n\033[1;92m[+] Press Enter to continue...\033[0m")

# ============================================================
# MODULE 2: File System Malware Scan
# ============================================================
def scan_filesystem():
    print("\n\033[1;94m" + "━"*50)
    print("\033[1;93m [FILE SCAN] Scanning filesystem for malware\033[0m")
    print("\033[1;94m" + "━"*50 + "\033[0m")

    file_results = []

    # 1. ClamAV scan if available
    if shutil_which("clamscan"):
        print("\033[1;92m[*] ClamAV detected - performing signature scan\033[0m")
        print("\033[1;93m[*] Scanning /tmp, /dev/shm, /var/tmp, $HOME/.ssh...\033[0m")
        try:
            result = subprocess.run(
                ["clamscan", "-r", "--quiet", "--max-files=1000", "--max-scansize=50M",
                 "/tmp", "/dev/shm", "/var/tmp", os.path.expanduser("~/.ssh")],
                capture_output=True, text=True, timeout=120
            )
            if result.stdout:
                print(f"\033[1;91m{result.stdout}\033[0m")
                file_results.append(result.stdout)
            if result.stderr:
                print(f"\033[1;93m{result.stderr}\033[0m")
        except subprocess.TimeoutExpired:
            print("\033[1;93m[!] ClamAV scan timed out (skipping)\033[0m")
    else:
        print("\033[1;93m[!] ClamAV not installed. Install: apt-get install clamav\033[0m")

    # 2. Check for unauthorized SUID binaries
    print("\n\033[1;93m[*] Checking for unauthorized SUID binaries...\033[0m")
    trusted_suid_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    try:
        suid_find = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True, timeout=30
        )
        for binary in suid_find.stdout.split("\n"):
            if binary.strip():
                trusted = any(binary.startswith(d) for d in trusted_suid_dirs)
                if not trusted:
                    print(f"\033[1;91m[!] Unauthorized SUID binary: {binary}\033[0m")
                    file_results.append(f"[SUID] {binary}")
    except subprocess.TimeoutExpired:
        print("\033[1;93m[!] SUID search timed out\033[0m")

    # 3. Check for hidden executables in home directories
    print("\n\033[1;93m[*] Checking for hidden executables in /home...\033[0m")
    try:
        hidden = subprocess.run(
            ["find", "/home", "-name", ".*", "-type", "f", "-executable"],
            capture_output=True, text=True, timeout=30
        )
        for h in hidden.stdout.split("\n"):
            if h.strip():
                print(f"\033[1;91m[!] Hidden executable: {h}\033[0m")
                file_results.append(f"[HIDDEN EXE] {h}")
    except subprocess.TimeoutExpired:
        pass

    # 4. Check recently modified binaries
    print("\n\033[1;93m[*] Checking recently modified binaries...\033[0m")
    try:
        recent = subprocess.run(
            ["find", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "-mtime", "-7", "-type", "f", "-executable"],
            capture_output=True, text=True, timeout=30
        )
        for r in recent.stdout.split("\n"):
            if r.strip():
                print(f"\033[1;93m[?] Recently modified binary: {r}\033[0m")
                file_results.append(f"[RECENT BIN] {r}")
    except subprocess.TimeoutExpired:
        pass

    # 5. Check for world-writable files in system directories
    print("\n\033[1;93m[*] Checking for world-writable system files...\033[0m")
    try:
        www = subprocess.run(
            ["find", "/etc", "/bin", "/sbin", "/usr", "-perm", "-2", "-type", "f"],
            capture_output=True, text=True, timeout=30
        )
        for w in www.stdout.split("\n"):
            if w.strip():
                print(f"\033[1;91m[!] World-writable system file: {w}\033[0m")
                file_results.append(f"[WORLD-WRITABLE] {w}")
    except subprocess.TimeoutExpired:
        pass

    if file_results:
        with open(FILE_TEMP, "w") as f:
            f.write("\n".join(file_results))

    print(f"\n\033[1;92m[+] Filesystem scan complete - {len(file_results)} findings\033[0m")
    input("\033[1;92m[+] Press Enter to continue...\033[0m")

# ============================================================
# MODULE 3: Persistence & Cron Analysis
# ============================================================
def scan_persistence():
    print("\n\033[1;94m" + "━"*50)
    print("\033[1;93m [PERSISTENCE SCAN] Checking persistence mechanisms\033[0m")
    print("\033[1;94m" + "━"*50 + "\033[0m")

    persist_results = []

    # 1. Check system cron directories
    print("\n\033[1;93m[*] Checking system cron directories...\033[0m")
    cron_dirs = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d"]
    for cd in cron_dirs:
        if os.path.isdir(cd):
            items = os.listdir(cd)
            for item in items:
                if item not in [".", "..", ".placeholder"]:
                    full_path = os.path.join(cd, item)
                    print(f"\033[1;93m[?] Cron entry: {full_path}\033[0m")
                    persist_results.append(f"[CRON] {full_path}")

    # 2. Check user crontabs for suspicious entries
    print("\n\033[1;93m[*] Checking user crontabs for suspicious entries...\033[0m")
    suspicious_cron_keywords = ["wget", "curl", "bash", "ncat", "nc ", "python", "perl", "/tmp", "/dev/shm"]
    try:
        with open("/etc/passwd") as f:
            for line in f:
                username = line.split(":")[0]
                try:
                    cron_out = subprocess.run(
                        ["crontab", "-u", username, "-l"],
                        capture_output=True, text=True, timeout=5
                    )
                    if cron_out.stdout:
                        for cronline in cron_out.stdout.split("\n"):
                            for kw in suspicious_cron_keywords:
                                if kw in cronline.lower():
                                    print(f"\033[1;91m[!] Suspicious cron ({username}): {cronline.strip()}\033[0m")
                                    persist_results.append(f"[SUSPICIOUS CRON] {username}: {cronline.strip()}")
                                    break
                except Exception:
                    pass
    except FileNotFoundError:
        pass

    # 3. Check systemd services
    print("\n\033[1;93m[*] Checking systemd services...\033[0m")
    try:
        svc_out = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running"],
            capture_output=True, text=True, timeout=10
        )
        for line in svc_out.stdout.split("\n"):
            suspicious_svc = ["update", "download", "backup", "sync", "monitor", "agent"]
            for kw in suspicious_svc:
                if kw in line.lower():
                    print(f"\033[1;93m[?] Review service: {line.strip()[:80]}\033[0m")
                    persist_results.append(f"[SERVICE] {line.strip()}")
                    break
    except Exception as e:
        pass

    # 4. Check SSH authorized_keys
    print("\n\033[1;93m[*] Checking SSH authorized_keys...\033[0m")
    home_dirs = ["/root"] + [f"/home/{d}" for d in os.listdir("/home") if os.path.isdir(f"/home/{d}")]
    for hd in home_dirs:
        ak = os.path.join(hd, ".ssh", "authorized_keys")
        if os.path.isfile(ak):
            try:
                with open(ak) as f:
                    keys = f.read().strip()
                    key_count = len(keys.split("\n")) if keys else 0
                    print(f"\033[1;93m[?] {hd} has {key_count} authorized_keys\033[0m")
                    if key_count > 3:
                        print(f"\033[1;91m[!] {hd} has unusually many authorized keys ({key_count})\033[0m")
                        persist_results.append(f"[MANY SSH KEYS] {hd}: {key_count}")
            except Exception:
                pass

    # 5. Check .bashrc / .profile for persistence
    print("\n\033[1;93m[*] Checking shell startup files for persistence...\033[0m")
    startup_files = [".bashrc", ".profile", ".bash_profile", ".zshrc"]
    for hd in home_dirs:
        for sf in startup_files:
            sp = os.path.join(hd, sf)
            if os.path.isfile(sp):
                try:
                    with open(sp) as f:
                        content = f.read()
                        suspicious_starts = ["wget", "curl", "nohup", "ncat", "nc -e", "bash -i", "python -c"]
                        for kw in suspicious_starts:
                            if kw in content.lower():
                                print(f"\033[1;91m[!] Suspicious entry in {sp}: contains '{kw}'\033[0m")
                                persist_results.append(f"[STARTUP PERSISTENCE] {sp}")
                                break
                except Exception:
                    pass

    print(f"\n\033[1;92m[+] Persistence scan complete - {len(persist_results)} findings\033[0m")
    input("\033[1;92m[+] Press Enter to continue...\033[0m")

# ============================================================
# MODULE 4: Network Connection Analysis
# ============================================================
def scan_network():
    print("\n\033[1;94m" + "━"*50)
    print("\033[1;93m [NETWORK SCAN] Analyzing network connections\033[0m")
    print("\033[1;94m" + "━"*50 + "\033[0m")

    net_results = []

    # 1. Check connections to known C2 ports
    print("\n\033[1;93m[*] Checking for connections to known C2/backdoor ports...\033[0m")
    c2_ports = [4444, 4443, 1337, 31337, 8080, 9999, 9001, 11000, 4433, 8443, 5555, 6666, 7777, 8888]
    try:
        ss_out = subprocess.run(["ss", "-tunp"], capture_output=True, text=True, timeout=10).stdout
        for port in c2_ports:
            for line in ss_out.split("\n"):
                if f":{port}" in line:
                    print(f"\033[1;91m[!] Connection to suspicious port {port}: {line.strip()}\033[0m")
                    net_results.append(f"[C2 PORT {port}] {line.strip()}")
    except Exception as e:
        print(f"\033[1;91m[!] Error: {e}\033[0m")

    # 2. Check listening services on all interfaces
    print("\n\033[1;93m[*] Checking listening services on all interfaces (0.0.0.0)...\033[0m")
    try:
        listening = subprocess.run(["ss", "-tlpn"], capture_output=True, text=True, timeout=10).stdout
        for line in listening.split("\n"):
            if "0.0.0.0:" in line or ":::" in line:
                port_match = line.split(":")[-1].split()[0] if ":" in line else ""
                sensitive_ports = ["22", "3306", "5432", "6379", "27017", "9200", "8080"]
                if port_match not in sensitive_ports:
                    print(f"\033[1;93m[?] Listening publicly: {line.strip()}\033[0m")
                    net_results.append(f"[PUBLIC LISTENER] {line.strip()}")
                else:
                    print(f"\033[1;92m[+] Expected service listening: {line.strip()}\033[0m")
    except Exception as e:
        pass

    # 3. Check established external connections
    print("\n\033[1;93m[*] Checking established external connections...\033[0m")
    try:
        established = subprocess.run(["ss", "-tup", "state", "established"], capture_output=True, text=True, timeout=10).stdout
        for line in established.split("\n"):
            if "127.0.0.1" not in line and "::1" not in line and len(line.strip()) > 10:
                # Extract process name
                if "users:" in line:
                    proc = line.split("users:")[1].strip().split('"')[1] if '"' in line else "unknown"
                    trusted = ["firefox", "chrome", "chromium", "brave", "thunderbird", "apt", "dpkg", 
                              "systemd", "NetworkManager", "dhclient", "ntpd", "sshd", "snapd", "discord", "slack"]
                    if not any(t in proc.lower() for t in trusted):
                        print(f"\033[1;91m[!] Untracked process with external connection: {proc}\033[0m")
                        print(f"\033[1;91m    {line.strip()}\033[0m")
                        net_results.append(f"[UNTRACKED OUTBOUND] {proc}: {line.strip()}")
    except Exception as e:
        pass

    # 4. DNS analysis - check for suspicious domains in /etc/hosts
    print("\n\033[1;93m[*] Checking /etc/hosts for suspicious entries...\033[0m")
    try:
        with open("/etc/hosts") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "127.0.0.1" not in line and "::1" not in line:
                    print(f"\033[1;93m[?] Non-loopback hosts entry: {line}\033[0m")
                    net_results.append(f"[HOSTS ENTRY] {line}")
    except FileNotFoundError:
        pass

    print(f"\n\033[1;92m[+] Network scan complete - {len(net_results)} findings\033[0m")
    input("\033[1;92m[+] Press Enter to continue...\033[0m")

# ============================================================
# MODULE 5: Rootkit Detection
# ============================================================
def scan_rootkits():
    print("\n\033[1;94m" + "━"*50)
    print("\033[1;93m [ROOTKIT SCAN] Checking for rootkit indicators\033[0m")
    print("\033[1;94m" + "━"*50 + "\033[0m")

    rootkit_results = []

    # 1. Check /proc vs ps discrepancy (hidden processes)
    print("\n\033[1;93m[*] Checking for hidden processes...\033[0m")
    try:
        proc_count = len([d for d in os.listdir("/proc") if d.isdigit()])
        ps_count = len(subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10).stdout.split("\n"))
        diff = proc_count - ps_count
        print(f"\033[1;93m[?] /proc entries: {proc_count} | ps entries: {ps_count} | diff: {diff}\033[0m")
        if diff > 20:
            print(f"\033[1;91m[!] Possible hidden process discrepancy detected (diff={diff})\033[0m")
            rootkit_results.append(f"[HIDDEN PROCESS] proc={proc_count} ps={ps_count} diff={diff}")
    except Exception as e:
        print(f"\033[1;91m[!] Error: {e}\033[0m")

    # 2. Check loaded kernel modules
    print("\n\033[1;93m[*] Checking loaded kernel modules...\033[0m")
    suspicious_mods = ["hide", "rootkit", "hook", "keylog", "adore", "suterusu", "diamorphine", "kmod"]
    try:
        lsmod = subprocess.run(["lsmod"], capture_output=True, text=True, timeout=10).stdout
        for line in lsmod.split("\n"):
            mod_name = line.split()[0] if line.split() else ""
            for sm in suspicious_mods:
                if sm in mod_name.lower():
                    print(f"\033[1;91m[!] Suspicious kernel module: {mod_name}\033[0m")
                    rootkit_results.append(f"[SUSPICIOUS MODULE] {mod_name}")
    except Exception as e:
        pass

    # 3. Check LD_PRELOAD
    print("\n\033[1;93m[*] Checking LD_PRELOAD...\033[0m")
    ld_preload = os.environ.get("LD_PRELOAD", "")
    if ld_preload:
        print(f"\033[1;91m[!] LD_PRELOAD is set: {ld_preload}\033[0m")
        rootkit_results.append(f"[LD_PRELOAD] {ld_preload}")

    # 4. Check for known rootkit files
    print("\n\033[1;93m[*] Checking for known rootkit artifact files...\033[0m")
    rootkit_files = [
        "/dev/.md", "/dev/.kgate", "/dev/.hidedir",
        "/proc/knl", "/proc/.proc",
        "/usr/share/.bash", "/etc/rc.d/rc.local",
    ]
    for rf in rootkit_files:
        if os.path.exists(rf):
            print(f"\033[1;91m[!] Known rootkit artifact: {rf}\033[0m")
            rootkit_results.append(f"[ROOTKIT FILE] {rf}")

    # 5. Check for unhideable processes using /proc/[pid]/fd
    print("\n\033[1;93m[*] Checking for processes hidden from /proc listing...\033[0m")
    for pid_dir in os.listdir("/proc"):
        if pid_dir.isdigit():
            try:
                cmdline_path = f"/proc/{pid_dir}/cmdline"
                if os.path.exists(cmdline_path):
                    with open(cmdline_path, "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                        if cmdline and len(cmdline) > 3:
                            # Check if this PID appears in ps output
                            ps_check = subprocess.run(
                                ["ps", "-p", pid_dir, "--no-headers"],
                                capture_output=True, text=True, timeout=5
                            )
                            if not ps_check.stdout.strip():
                                print(f"\033[1;91m[!] Process hidden from ps: PID={pid_dir} cmd={cmdline[:80]}\033[0m")
                                rootkit_results.append(f"[HIDDEN PID] {pid_dir}: {cmdline[:80]}")
            except Exception:
                pass

    # 6. Check for kernel module hiding
    print("\n\033[1;93m[*] Checking /proc/modules vs lsmod discrepancy...\033[0m")
    try:
        proc_mods = set()
        with open("/proc/modules") as f:
            for line in f:
                proc_mods.add(line.split()[0])
        lsmod_mods = set()
        for line in lsmod.split("\n")[1:]:
            if line.strip():
                lsmod_mods.add(line.split()[0])
        
        hidden_in_proc = lsmod_mods - proc_mods
        if hidden_in_proc:
            for mod in hidden_in_proc:
                print(f"\033[1;91m[!] Module hidden from /proc/modules: {mod}\033[0m")
                rootkit_results.append(f"[HIDDEN MODULE] {mod}")
    except Exception as e:
        pass

    print(f"\n\033[1;92m[+] Rootkit scan complete - {len(rootkit_results)} findings\033[0m")
    input("\033[1;92m[+] Press Enter to continue...\033[0m")

# ============================================================
# REPORT GENERATION
# ============================================================
def generate_report():
    print("\n\033[1;94m" + "━"*50)
    print("\033[1;93m [REPORT] Generating scan report...\033[0m")
    print("\033[1;94m" + "━"*50 + "\033[0m")

    hostname = os.uname().nodename
    datetime_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    kernel = os.uname().release

    # Get OS info
    os_info = "Unknown"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_info = line.split("=")[1].strip().strip('"')
                    break
    except FileNotFoundError:
        pass

    # Collect data from temp files
    proc_data = ""
    if os.path.exists(PROC_TEMP):
        with open(PROC_TEMP) as f:
            proc_data = f.read()
    
    file_data = ""
    if os.path.exists(FILE_TEMP):
        with open(FILE_TEMP) as f:
            file_data = f.read()

    # Build report
    separator = "=" * 60
    report_lines = [
        separator,
        "               MalScan - Enterprise Scan Report",
        separator,
        f"Hostname      : {hostname}",
        f"Scan Date     : {datetime_str}",
        f"Kernel        : {kernel}",
        f"Distribution  : {os_info}",
        "",
        "   PROCESS ANALYSIS",
        separator,
        proc_data if proc_data else "No suspicious processes detected.",
        "",
        "   FILESYSTEM ANALYSIS",
        separator,
        file_data if file_data else "No filesystem issues detected.",
        "",
        "   NETWORK ANALYSIS",
        separator,
        "Listening services:",
    ]

    try:
        netstat = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=10).stdout
        report_lines.append(netstat)
    except Exception:
        report_lines.append("(could not retrieve)")

    report_lines += [
        "",
        "Active connections (top 30):",
    ]
    try:
        active = subprocess.run(["ss", "-tunp"], capture_output=True, text=True, timeout=10).stdout
        for line in active.split("\n")[:30]:
            report_lines.append(line)
    except Exception:
        report_lines.append("(could not retrieve)")

    report_lines += [
        "",
        "   PERSISTENCE ANALYSIS",
        separator,
    ]
    try:
        with open("/etc/crontab") as f:
            cron_count = sum(1 for l in f if not l.startswith("#") and l.strip())
        report_lines.append(f"System crontab entries: {cron_count}")
    except FileNotFoundError:
        report_lines.append("System crontab: not found")

    report_lines += [
        "",
        "   RECOMMENDATIONS",
        separator,
        "1. Review all suspicious processes listed above",
        "2. Remove unauthorized cron jobs and startup items",
        "3. Run full ClamAV scan: sudo clamscan -r /",
        "4. Check for unauthorized SSH keys in ~/.ssh/authorized_keys",
        "5. Audit SUID binaries and remove unnecessary ones",
        "6. Review open ports and kill unauthorized reverse shells",
        "7. Investigate any kernel module anomalies",
        "8. Run rkhunter/chkrootkit for additional rootkit detection",
        "",
        separator,
    ]

    report = "\n".join(report_lines)

    # Save report
    report_path = f"/tmp/malscan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, "w") as f:
        f.write(report)
    with open(REPORT_TEMP, "w") as f:
        f.write(report)

    print(f"\n\033[1;92m[+] Report saved to: {report_path}\033[0m")
    print(f"\033[1;92m[+] Displaying report:\033[0m\n")
    print(report)

    cleanup_temp_files()
    input("\n\033[1;92m[+] Press Enter to continue...\033[0m")

# ============================================================
# FULL SCAN
# ============================================================
def full_scan():
    print("\n\033[1;95m[!] Starting FULL malware scan...\033[0m")
    scan_processes()
    scan_filesystem()
    scan_persistence()
    scan_network()
    scan_rootkits()
    generate_report()

# ============================================================
# INTERACTIVE MENU
# ============================================================
def menu():
    while True:
        os.system("clear")
        banner()
        print("\n\033[1;94m" + "━"*50)
        print("\033[1;97m   Select Scan Module:\033[0m")
        print("\033[1;94m" + "━"*50 + "\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m01\033[0m\033[1;92m]\033[0m \033[1;97mFull Scan (All Modules)\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m02\033[0m\033[1;92m]\033[0m \033[1;97mProcess Anomaly Scan\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m03\033[0m\033[1;92m]\033[0m \033[1;97mFile System Malware Scan\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m04\033[0m\033[1;92m]\033[0m \033[1;97mPersistence & Cron Audit\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m05\033[0m\033[1;92m]\033[0m \033[1;97mNetwork Connection Analysis\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m06\033[0m\033[1;92m]\033[0m \033[1;97mRootkit Detection\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m07\033[0m\033[1;92m]\033[0m \033[1;97mGenerate Report\033[0m")
        print("  \033[1;92m[\033[0m\033[1;77m00\033[0m\033[1;92m]\033[0m \033[1;97mExit\033[0m")
        print("\033[1;94m" + "━"*50 + "\033[0m")

        choice = input("\n\033[1;92m[\033[0m\033[1;77m+\033[0m\033[1;92m] Choose option [Default: 01]: \033[0m").strip() or "01"

        if choice in ["01", "1"]:
            full_scan()
        elif choice in ["02", "2"]:
            scan_processes()
        elif choice in ["03", "3"]:
            scan_filesystem()
        elif choice in ["04", "4"]:
            scan_persistence()
        elif choice in ["05", "5"]:
            scan_network()
        elif choice in ["06", "6"]:
            scan_rootkits()
        elif choice in ["07", "7"]:
            generate_report()
        elif choice in ["00", "0"]:
            print("\n\033[1;92m[+] Exiting MalScan\033[0m")
            cleanup_temp_files()
            sys.exit(0)
        else:
            print("\n\033[1;91m[!] Invalid option\033[0m")
            time.sleep(1)

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    banner()
    dependencies()
    menu()