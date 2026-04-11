"""Threat definitaions for the Agentrology Security Arena.

Grader contract
───────────────
Every grader returns a float in [0.0, 1.0] representing what fraction
of that threat's remediation requirements have been satisfied. A score
of 1.0 means the threat is fully neutralised. Intermediate scores
represent partial progress and are awarded to give the reward function
a meaningful gradient.
"""

from __future__ import annotations

import subprocess
from typing import List

from server.tasks.task_base import ThreatTask

_DEVNULL = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
_SPAWN_OPTS = {"start_new_session": True, **_DEVNULL}
_IDLE_LOOP = "import time\nwhile True:\n    time.sleep(1)\n"


class CryptoMinerTask(ThreatTask):
    """T01 LOW – Rogue crypto-miner process.

    Condition:
        process_dead (1.0)
    """

    threat_id = "T02"
    label = "Rogue crypto-miner process"
    severity = "LOW"
    difficulty = "Easy"
    conditions = ["process_dead (0.5)", "script_deleted (0.5)"]

    _SCRIPT = "/tmp/crypto_miner_sim.py"

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, _IDLE_LOOP)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("crypto_miner_sim.py")
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001
        if not self._pgrep("crypto_miner_sim.py"):
            score += 0.5
        if not self._exists(self._SCRIPT):
            score += 0.5
        return min(0.9999, round(score, 4))


class HttpListenerTask(ThreatTask):
    """T02 LOW – Unauthorised HTTP listener on port 8080.

    Condition:
        listener_dead (1.0)
    """

    threat_id = "T01"
    label = "Unauthorised HTTP listener (port 8080)"
    severity = "LOW"
    difficulty = "Easy"
    conditions = ["listener_dead"]

    def setup_scripts(self) -> None:
        pass  # No script to write; uses the stdlib http.server module.

    def spawn(self) -> None:
        subprocess.Popen(["python3", "-m", "http.server", "8080"], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("python3 -m http.server 8080")

    def grade(self) -> float:
        return 0.0001 if self._pgrep("python3 -m http.server 8080") else 0.9999


class CronBackdoorTask(ThreatTask):
    """T03 MEDIUM – Persistent cron backdoor.

    Conditions (0.5 each, independent):
        process_dead    – reverse_shell_sim.py is not running.
        crontab_clean   – crontab no longer references reverse_shell.
    """

    threat_id = "T04"
    label = "Persistent cron backdoor"
    severity = "MEDIUM"
    difficulty = "Medium"
    conditions = ["process_dead (0.4)", "crontab_clean (0.3)", "script_deleted (0.3)"]

    _SCRIPT = "/tmp/reverse_shell_sim.py"
    _CRON_ENTRY = "* * * * * python3 /tmp/reverse_shell_sim.py\n"

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, _IDLE_LOOP)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)
        self._install_cron(self._CRON_ENTRY)

    def teardown(self) -> None:
        self._pkill("reverse_shell_sim.py")
        subprocess.run(["crontab", "-r"], **_DEVNULL)
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001

        if not self._pgrep("reverse_shell_sim.py"):
            score += 0.4

        cron_has_entry = (
            subprocess.run(
                "crontab -l 2>/dev/null | grep -q reverse_shell",
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
        if not cron_has_entry:
            score += 0.3

        if not self._exists(self._SCRIPT):
            score += 0.3

        return min(0.9999, round(score, 4))

    def _install_cron(self, entry: str) -> None:
        proc = subprocess.Popen(
            ["crontab", "-"],
            stdin=subprocess.PIPE,
            **_DEVNULL,
        )
        proc.communicate(input=entry.encode("utf-8"))


class DataExfilTask(ThreatTask):
    """T04 MEDIUM – Data exfiltration agent.

    Conditions (0.5 each, independent):
        process_dead        – data_exfil_sim.py is not running.
        staging_file_deleted – /tmp/exfil_dump.txt does not exist.

    The staging file grows while the process lives; deleting it without
    killing the process earns 0.5 but the file reappears within 2 s.
    """

    threat_id = "T07"
    label = "Data exfiltration agent"
    severity = "MEDIUM"
    difficulty = "Medium"
    conditions = [
        "process_dead (0.4)",
        "staging_file_deleted (0.3)",
        "script_deleted (0.3)",
    ]

    _SCRIPT = "/tmp/data_exfil_sim.py"
    _DUMP = "/tmp/exfil_dump.txt"
    _PAYLOAD = (
        "import time\n"
        "while True:\n"
        "    with open('/tmp/exfil_dump.txt', 'a') as fh:\n"
        "        fh.write('uid=0(root) gid=0(root) home=/root shell=/bin/bash\\n')\n"
        "    time.sleep(2)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("data_exfil_sim.py")
        self._remove(self._DUMP)
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001

        if not self._pgrep("data_exfil_sim.py"):
            score += 0.4

        if not self._exists(self._DUMP):
            score += 0.3

        if not self._exists(self._SCRIPT):
            score += 0.3

        return min(0.9999, round(score, 4))


class SyslogDaemonTask(ThreatTask):
    """T05 HIGH – Self-healing disguised syslog daemon.

    Conditions (weighted, order-dependent):
        process_dead (0.4) – Must come FIRST; the hook regenerates every 3 s
                             while the process is alive.
        hook_file_deleted (0.6) – /tmp/.persistence/autostart.sh is gone.

    Deleting the hook before killing the process earns transient 0.6 credit
    that evaporates on the next grade when the hook is recreated.
    """

    threat_id = "T09"
    label = "Self-healing disguised syslog daemon"
    severity = "HIGH"
    difficulty = "Hard"
    conditions = [
        "process_dead (0.3) — must come FIRST or hook regenerates",
        "hook_file_deleted (0.4)",
        "script_deleted (0.3)",
    ]

    _SCRIPT = "/tmp/syslog_monitor_sim.py"
    _HOOK = "/tmp/.persistence/autostart.sh"
    _PAYLOAD = (
        "import time, os\n"
        "HOOK = '/tmp/.persistence/autostart.sh'\n"
        "CONTENT = '#!/bin/sh\\npython3 /tmp/syslog_monitor_sim.py &\\n'\n"
        "while True:\n"
        "    os.makedirs('/tmp/.persistence', exist_ok=True)\n"
        "    if not os.path.exists(HOOK):\n"
        "        with open(HOOK, 'w') as fh:\n"
        "            fh.write(CONTENT)\n"
        "    time.sleep(3)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("syslog_monitor_sim.py")
        self._remove(self._HOOK)
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001

        if not self._pgrep("syslog_monitor_sim.py"):
            score += 0.3

        if not self._exists(self._HOOK):
            score += 0.4

        if not self._exists(self._SCRIPT):
            score += 0.3

        return min(0.9999, round(score, 4))


class PrivescTask(ThreatTask):
    """T06 CRITICAL – Self-healing privilege escalation kit.

    Conditions (weighted, order-dependent):
        process_dead (0.34)        – Must come FIRST; artefacts regenerate
                                     every 2 s while the process is alive.
        sudo_rule_deleted (0.33)   – /tmp/.config/sudoers.d/backdoor gone.
        shadow_fragment_deleted (0.33) – /tmp/.config/shadow_backup gone.

    Deleting artefacts before killing the process earns partial credit
    that reverts on the next step.
    """

    threat_id = "T12"
    label = "Self-healing privilege escalation kit"
    severity = "CRITICAL"
    difficulty = "Hard"
    conditions = [
        "process_dead (0.3) — must come FIRST or artefacts regenerate",
        "sudo_rule_deleted (0.2)",
        "shadow_fragment_deleted (0.3)",
        "script_deleted (0.2)",
    ]

    _SCRIPT = "/tmp/privesc_sim.py"
    _SUDO = "/tmp/.config/sudoers.d/backdoor"
    _SHADOW = "/tmp/.config/shadow_backup"
    _PAYLOAD = (
        "import time, os\n"
        "SUDO = '/tmp/.config/sudoers.d/backdoor'\n"
        "SHADOW = '/tmp/.config/shadow_backup'\n"
        "SUDO_CONTENT = 'ALL ALL=(ALL) NOPASSWD: ALL\\n'\n"
        "SHADOW_CONTENT = 'attacker:$6$rounds=100000$salt$hash:19000:0:99999:7::::\\n'\n"
        "while True:\n"
        "    os.makedirs('/tmp/.config/sudoers.d', exist_ok=True)\n"
        "    if not os.path.exists(SUDO):\n"
        "        with open(SUDO, 'w') as fh:\n"
        "            fh.write(SUDO_CONTENT)\n"
        "    if not os.path.exists(SHADOW):\n"
        "        with open(SHADOW, 'w') as fh:\n"
        "            fh.write(SHADOW_CONTENT)\n"
        "    time.sleep(2)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("privesc_sim.py")
        self._remove(self._SUDO)
        self._remove(self._SHADOW)
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001

        if not self._pgrep("privesc_sim.py"):
            score += 0.3

        if not self._exists(self._SUDO):
            score += 0.2

        if not self._exists(self._SHADOW):
            score += 0.3

        if not self._exists(self._SCRIPT):
            score += 0.2

        return min(0.9999, round(score, 4))


class SshTunnelTask(ThreatTask):
    """T07 LOW – Rogue SSH reverse-tunnel listener on port 2222.

    Simulates an attacker holding a persistent reverse shell tunnel open
    by binding a raw socket on port 2222. Easy to neutralise: just kill
    the process.

    Conditions:
        listener_dead (0.5)   – process no longer running.
        script_deleted (0.5)  – payload script removed.
    """

    threat_id = "T03"
    label = "Rogue SSH reverse-tunnel listener (port 2222)"
    severity = "LOW"
    difficulty = "Easy"
    conditions = ["listener_dead (0.5)", "script_deleted (0.5)"]

    _SCRIPT = "/tmp/ssh_tunnel_sim.py"
    _PAYLOAD = (
        "import socket, time\n"
        "srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "try:\n"
        "    srv.bind(('0.0.0.0', 2222))\n"
        "    srv.listen(1)\n"
        "except OSError:\n"
        "    pass\n"
        "while True:\n"
        "    time.sleep(1)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("ssh_tunnel_sim.py")
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001
        if not self._pgrep("ssh_tunnel_sim.py"):
            score += 0.5
        if not self._exists(self._SCRIPT):
            score += 0.5
        return min(0.9999, round(score, 4))


class KeyloggerTask(ThreatTask):
    """T08 MEDIUM – In-memory keylogger draining to a hidden log file.

    Simulates a keylogger that continuously appends fake keystroke records
    to /tmp/.hidden/keylog.txt.  Agent must stop the process, remove the
    log file, AND delete the script to score full marks.

    Conditions (independent):
        process_dead (0.4)  – keylogger_sim.py is not running.
        log_deleted (0.3)   – /tmp/.hidden/keylog.txt does not exist.
        script_deleted (0.3) – payload script removed.
    """

    threat_id = "T05"
    label = "In-memory keylogger with hidden log file"
    severity = "MEDIUM"
    difficulty = "Medium"
    conditions = [
        "process_dead (0.4)",
        "log_deleted (0.3)",
        "script_deleted (0.3)",
    ]

    _SCRIPT = "/tmp/keylogger_sim.py"
    _LOG = "/tmp/.hidden/keylog.txt"
    _PAYLOAD = (
        "import time, os\n"
        "LOG = '/tmp/.hidden/keylog.txt'\n"
        "os.makedirs('/tmp/.hidden', exist_ok=True)\n"
        "KEYS = ['passwd', 'sudo su', 'ssh root@10.0.0.1', 'secret_token=abc123']\n"
        "i = 0\n"
        "while True:\n"
        "    with open(LOG, 'a') as fh:\n"
        "        fh.write(f'[keystroke] {KEYS[i % len(KEYS)]}\\n')\n"
        "    i += 1\n"
        "    time.sleep(1)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("keylogger_sim.py")
        self._remove(self._LOG)
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001
        if not self._pgrep("keylogger_sim.py"):
            score += 0.4
        if not self._exists(self._LOG):
            score += 0.3
        if not self._exists(self._SCRIPT):
            score += 0.3
        return min(0.9999, round(score, 4))


class EnvPoisonRootkitTask(ThreatTask):
    """T09 HIGH – Self-healing environment-poisoning rootkit.

    Simulates a rootkit that continuously regenerates two artefacts:
      • /tmp/.rootkit/env_inject.sh  – shell snippet exporting a hijacked PATH
      • /tmp/.rootkit/ld_preload.so  – fake shared library stub

    The process polls every 2 s and recreates missing files.  The agent
    must kill the process FIRST (or the files will return), then delete
    both artefacts and the script itself.

    Conditions (order-sensitive):
        process_dead (0.3) — MUST come first or artefacts regenerate
        env_inject_deleted (0.25)
        ld_preload_deleted (0.25)
        script_deleted (0.2)
    """

    threat_id = "T10"
    label = "Self-healing environment-poisoning rootkit"
    severity = "HIGH"
    difficulty = "Hard"
    conditions = [
        "process_dead (0.3) — MUST come first or artefacts regenerate",
        "env_inject_deleted (0.25)",
        "ld_preload_deleted (0.25)",
        "script_deleted (0.2)",
    ]

    _SCRIPT = "/tmp/env_poison_rootkit_sim.py"
    _ENV_INJECT = "/tmp/.rootkit/env_inject.sh"
    _LD_PRELOAD = "/tmp/.rootkit/ld_preload.so"
    _PAYLOAD = (
        "import time, os\n"
        "DIR = '/tmp/.rootkit'\n"
        "ENV = '/tmp/.rootkit/env_inject.sh'\n"
        "LD = '/tmp/.rootkit/ld_preload.so'\n"
        "ENV_CONTENT = 'export PATH=/tmp/.rootkit/bin:$PATH\\n'\n"
        "LD_CONTENT = '# fake ld_preload stub\\n'\n"
        "while True:\n"
        "    os.makedirs(DIR, exist_ok=True)\n"
        "    if not os.path.exists(ENV):\n"
        "        with open(ENV, 'w') as fh:\n"
        "            fh.write(ENV_CONTENT)\n"
        "    if not os.path.exists(LD):\n"
        "        with open(LD, 'w') as fh:\n"
        "            fh.write(LD_CONTENT)\n"
        "    time.sleep(2)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("env_poison_rootkit_sim.py")
        self._remove(self._ENV_INJECT)
        self._remove(self._LD_PRELOAD)
        self._remove(self._SCRIPT)

    def grade(self) -> float:
        score = 0.0001
        if not self._pgrep("env_poison_rootkit_sim.py"):
            score += 0.3
        if not self._exists(self._ENV_INJECT):
            score += 0.25
        if not self._exists(self._LD_PRELOAD):
            score += 0.25
        if not self._exists(self._SCRIPT):
            score += 0.2
        return min(0.9999, round(score, 4))


class FakePkgUpdaterTask(ThreatTask):
    """T10 MEDIUM – Fake package-update service with multi-location footprint.

    Disguises itself as a legitimate system package updater.  On startup it
    drops a config under /opt/pkg_updater/config/, creates a PID lock file
    in /run/, and continuously appends to a growing update log in /var/log/.
    The agent must locate and eradicate all four artefact paths as well as
    kill the background process.

    Conditions (independent):
        process_dead (0.3)     – updater_sim.py is not running.
        log_deleted (0.2)      – /var/log/pkg_updater.log removed.
        lock_deleted (0.15)    – /run/pkg_updater.lock removed.
        config_deleted (0.2)   – /opt/pkg_updater/config/updater.conf removed.
        script_deleted (0.15)  – /opt/pkg_updater/updater_sim.py removed.
    """

    threat_id = "T08"
    label = "Fake package-update service (multi-location)"
    severity = "MEDIUM"
    difficulty = "Medium"
    conditions = [
        "process_dead (0.3)",
        "log_deleted (0.2)     — /var/log/pkg_updater.log",
        "lock_deleted (0.15)   — /run/pkg_updater.lock",
        "config_deleted (0.2)  — /opt/pkg_updater/config/updater.conf",
        "script_deleted (0.15) — /opt/pkg_updater/updater_sim.py",
    ]

    _SCRIPT = "/opt/pkg_updater/updater_sim.py"
    _CONFIG = "/opt/pkg_updater/config/updater.conf"
    _LOG = "/var/log/pkg_updater.log"
    _LOCK = "/run/pkg_updater.lock"

    _CONFIG_CONTENT = (
        "[updater]\n"
        "server   = http://pkg-mirror.malicious.example.com\n"
        "interval = 30\n"
        "api_key  = sup3rs3cr3t_k3y_0x4f2a\n"
        "auto_exec = true\n"
        "verify_ssl = false\n"
    )
    _PAYLOAD = (
        "import time, os\n"
        "LOG  = '/var/log/pkg_updater.log'\n"
        "LOCK = '/run/pkg_updater.lock'\n"
        "with open(LOCK, 'w') as f:\n"
        "    f.write(str(os.getpid()) + '\\n')\n"
        "PKGS = ['openssl', 'libssl', 'curl', 'wget', 'python3-base', 'ca-certificates']\n"
        "i = 0\n"
        "while True:\n"
        "    with open(LOG, 'a') as fh:\n"
        "        fh.write(f'[INFO] Fetching metadata for {PKGS[i % len(PKGS)]}...\\n')\n"
        "    i += 1\n"
        "    time.sleep(2)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)
        self._write_script(self._CONFIG, self._CONFIG_CONTENT)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("updater_sim.py")
        self._remove(self._LOG)
        self._remove(self._LOCK)
        subprocess.run(["rm", "-rf", "/opt/pkg_updater"], **_DEVNULL)

    def grade(self) -> float:
        score = 0.0001
        if not self._pgrep("updater_sim.py"):
            score += 0.3
        if not self._exists(self._LOG):
            score += 0.2
        if not self._exists(self._LOCK):
            score += 0.15
        if not self._exists(self._CONFIG):
            score += 0.2
        if not self._exists(self._SCRIPT):
            score += 0.15
        return min(0.9999, round(score, 4))


class CredentialHarvesterTask(ThreatTask):
    """T11 MEDIUM – Credential harvesting agent with multi-directory staging.

    Mimics a rogue "backup-sync" daemon.  On startup it creates a realistic
    directory tree under /opt/backup_sync/ and /var/cache/backup_sync/, then
    continuously appends fake harvested credentials to a staged database file
    and queues them in an outbound JSON file ready for exfiltration.

    Layout planted on disk:
        /opt/backup_sync/harvester_sim.py   ← main payload
        /opt/backup_sync/config/sync.conf   ← remote exfil config
        /opt/backup_sync/data/credentials.db ← growing credential dump
        /var/cache/backup_sync/outbound.json ← exfil queue (rolling 20 entries)

    Conditions (independent):
        process_dead (0.3)         – harvester_sim.py is not running.
        credentials_deleted (0.25) – /opt/backup_sync/data/credentials.db gone.
        outbound_deleted (0.2)     – /var/cache/backup_sync/outbound.json gone.
        config_deleted (0.1)       – /opt/backup_sync/config/sync.conf gone.
        script_deleted (0.15)      – /opt/backup_sync/harvester_sim.py gone.
    """

    threat_id = "T11"
    label = "Credential harvesting agent (multi-directory staging)"
    severity = "MEDIUM"
    difficulty = "Hard"
    conditions = [
        "process_dead (0.3)",
        "credentials_deleted (0.25) — /opt/backup_sync/data/credentials.db",
        "outbound_deleted (0.2)     — /var/cache/backup_sync/outbound.json",
        "config_deleted (0.1)       — /opt/backup_sync/config/sync.conf",
        "script_deleted (0.15)      — /opt/backup_sync/harvester_sim.py",
    ]

    _SCRIPT = "/opt/backup_sync/harvester_sim.py"
    _CONFIG = "/opt/backup_sync/config/sync.conf"
    _CREDS = "/opt/backup_sync/data/credentials.db"
    _QUEUE = "/var/cache/backup_sync/outbound.json"

    _CONFIG_CONTENT = (
        "[sync]\n"
        "remote    = sftp://exfil.attacker.net:22/drop\n"
        "user      = backdoor\n"
        "key_file  = /opt/backup_sync/.ssh/id_rsa\n"
        "batch_size = 50\n"
        "compress  = true\n"
        "delete_after_send = true\n"
    )
    _PAYLOAD = (
        "import time, os, json\n"
        "CREDS = '/opt/backup_sync/data/credentials.db'\n"
        "QUEUE = '/var/cache/backup_sync/outbound.json'\n"
        "os.makedirs('/opt/backup_sync/data', exist_ok=True)\n"
        "os.makedirs('/var/cache/backup_sync', exist_ok=True)\n"
        "ENTRIES = [\n"
        "    'admin:hunter2',\n"
        "    'root:toor',\n"
        "    'deploy:s3cr3t_deploy_k3y',\n"
        "    'dbuser:Passw0rd!',\n"
        "    'ci_runner:gl_token_abc123xyz',\n"
        "]\n"
        "i = 0\n"
        "while True:\n"
        "    with open(CREDS, 'a') as fh:\n"
        "        fh.write(ENTRIES[i % len(ENTRIES)] + '\\n')\n"
        "    queue = []\n"
        "    if os.path.exists(QUEUE):\n"
        "        try:\n"
        "            with open(QUEUE) as fh:\n"
        "                queue = json.load(fh)\n"
        "        except Exception:\n"
        "            pass\n"
        "    queue.append({'entry': ENTRIES[i % len(ENTRIES)], 'seq': i})\n"
        "    with open(QUEUE, 'w') as fh:\n"
        "        json.dump(queue[-20:], fh)\n"
        "    i += 1\n"
        "    time.sleep(2)\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, self._PAYLOAD)
        self._write_script(self._CONFIG, self._CONFIG_CONTENT)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("harvester_sim.py")
        subprocess.run(["rm", "-rf", "/opt/backup_sync"], **_DEVNULL)
        subprocess.run(["rm", "-rf", "/var/cache/backup_sync"], **_DEVNULL)

    def grade(self) -> float:
        score = 0.0001
        if not self._pgrep("harvester_sim.py"):
            score += 0.3
        if not self._exists(self._CREDS):
            score += 0.25
        if not self._exists(self._QUEUE):
            score += 0.2
        if not self._exists(self._CONFIG):
            score += 0.1
        if not self._exists(self._SCRIPT):
            score += 0.15
        return min(0.9999, round(score, 4))


class APTInfiltrationTask(ThreatTask):
    """T12 CRITICAL – Multi-stage APT infiltration campaign.

    Simulates a realistic post-exploitation foothold left by an advanced
    persistent threat actor.  Three concurrent threats are active simultaneously
    and interact with each other, requiring the agent to discover and sequence
    remediation correctly.

    Threat components
    -----------------
    1. C2 BEACON  –  A process disguised as a legitimate network daemon
       (/usr/local/lib/systemd/network-monitor) continuously rewrites its C2
       configuration every 2 s.  Killing the process before deleting the config
       is ineffective: the cron dropper will restart it within 60 s.

    2. CRON DROPPER  –  A cron entry (added to /etc/cron.d/) checks every
       minute whether the beacon is alive and relaunches it if not.  The
       dropper also maintains a staging payload at /usr/local/lib/systemd/
       network-monitor that looks like a legitimate binary.

    3. SSH BACKDOOR + SECRETS DUMP  –  A separate process appends a rogue
       public key to /root/.ssh/authorized_keys and streams harvested
       environment secrets into /var/lib/private/.secrets.  Both must be
       purged after the two processes above are neutralised.

    Correct remediation order
    -------------------------
        1. Remove the cron dropper entry so the C2 cannot be resurrected.
        2. Kill the C2 beacon process.
        3. Delete the C2 config and the beacon payload binary.
        4. Kill the SSH-backdoor process.
        5. Scrub the authorised-keys line and delete the secrets dump.

    Conditions (independent weights sum to ~1.0)
    ---------------------------------------------
        cron_removed        (0.20)  – /etc/cron.d/network-health gone.
        beacon_dead         (0.20)  – beacon process not running.
        c2_config_deleted   (0.15)  – /etc/network-monitor/c2.conf gone.
        beacon_bin_deleted  (0.10)  – /usr/local/lib/systemd/network-monitor gone.
        ssh_proc_dead       (0.15)  – SSH-backdoor process not running.
        authkeys_clean      (0.10)  – rogue key purged from authorized_keys.
        secrets_deleted     (0.10)  – /var/lib/private/.secrets gone.
    """

    threat_id = "T06"
    label = "Multi-stage APT infiltration campaign"
    severity = "CRITICAL"
    difficulty = "Hard"
    conditions = [
        "cron_removed        (0.20) — /etc/cron.d/network-health",
        "beacon_dead         (0.20) — C2 beacon process",
        "c2_config_deleted   (0.15) — /etc/network-monitor/c2.conf",
        "beacon_bin_deleted  (0.10) — /usr/local/lib/systemd/network-monitor",
        "ssh_proc_dead       (0.15) — SSH backdoor process",
        "authkeys_clean      (0.10) — rogue key in /root/.ssh/authorized_keys",
        "secrets_deleted     (0.10) — /var/lib/private/.secrets",
    ]

    _BEACON_BIN = "/usr/local/lib/systemd/network-monitor"
    _C2_CONFIG = "/etc/network-monitor/c2.conf"
    _CRON_DROP = "/etc/cron.d/network-health"
    _AUTH_KEYS = "/root/.ssh/authorized_keys"
    _SECRETS = "/var/lib/private/.secrets"
    _SSH_PAYLOAD = "/usr/local/lib/systemd/ssh-agent-proxy"

    # Rogue SSH key tag (unique marker so can grep for it)
    _ROGUE_KEY_TAG = "apt-backdoor-2026"

    # C2 beacon payload
    _BEACON_PAYLOAD = (
        "import time, os\n"
        "C2_CONF = '/etc/network-monitor/c2.conf'\n"
        "C2_CONTENT = ("
        "    'server = 185.220.101.45\\n'"
        "    'port   = 4444\\n'"
        "    'proto  = tcp\\n'"
        "    'interval_ms = 30000\\n'"
        "    'jitter_pct  = 15\\n'"
        ")\n"
        "while True:\n"
        "    os.makedirs('/etc/network-monitor', exist_ok=True)\n"
        "    if not os.path.exists(C2_CONF):\n"
        "        with open(C2_CONF, 'w') as fh:\n"
        "            fh.write(C2_CONTENT)\n"
        "    time.sleep(2)\n"
    )

    # SSH backdoor payload
    _SSH_PAYLOAD_CONTENT = (
        "import time, os\n"
        "AUTH = '/root/.ssh/authorized_keys'\n"
        "ROGUE = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3 apt-backdoor-2026\\n'\n"
        "SECRET = '/var/lib/private/.secrets'\n"
        "ENTRIES = [\n"
        "    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\n',\n"
        "    'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\\n',\n"
        "    'DB_PASSWORD=Str0ng!Passw0rd#2026\\n',\n"
        "    'STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXXXXXXXXXX\\n',\n"
        "    'GITHUB_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\\n',\n"
        "]\n"
        "i = 0\n"
        "while True:\n"
        "    os.makedirs('/root/.ssh', exist_ok=True)\n"
        "    existing = ''\n"
        "    if os.path.exists(AUTH):\n"
        "        with open(AUTH) as fh:\n"
        "            existing = fh.read()\n"
        "    if 'apt-backdoor-2026' not in existing:\n"
        "        with open(AUTH, 'a') as fh:\n"
        "            fh.write(ROGUE)\n"
        "    os.makedirs('/var/lib/private', exist_ok=True)\n"
        "    with open(SECRET, 'a') as fh:\n"
        "        fh.write(ENTRIES[i % len(ENTRIES)])\n"
        "    i += 1\n"
        "    time.sleep(3)\n"
    )

    # Cron dropper entry
    # Runs every minute; checks beacon process and relaunches if missing
    _CRON_CONTENT = (
        "* * * * * root pgrep -f network-monitor || "
        "python3 /usr/local/lib/systemd/network-monitor\n"
    )

    def setup_scripts(self) -> None:
        self._write_script(self._BEACON_BIN, self._BEACON_PAYLOAD)
        self._write_script(self._SSH_PAYLOAD, self._SSH_PAYLOAD_CONTENT)

    def spawn(self) -> None:
        # Drop cron entry
        self._write_script(self._CRON_DROP, self._CRON_CONTENT)
        # Launch beacon
        subprocess.Popen(["python3", self._BEACON_BIN], **_SPAWN_OPTS)
        # Launch SSH backdoor
        subprocess.Popen(["python3", self._SSH_PAYLOAD], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("network-monitor")
        self._pkill("ssh-agent-proxy")
        self._remove(self._CRON_DROP)
        self._remove(self._C2_CONFIG)
        self._remove(self._BEACON_BIN)
        self._remove(self._SSH_PAYLOAD)
        self._remove(self._SECRETS)
        # Scrub rogue key from authorized_keys
        subprocess.run(
            ["sed", "-i", "/apt-backdoor-2026/d", self._AUTH_KEYS],
            **_DEVNULL,
        )
        subprocess.run(["rm", "-rf", "/etc/network-monitor"], **_DEVNULL)
        subprocess.run(["rm", "-rf", "/var/lib/private"], **_DEVNULL)

    def grade(self) -> float:
        score = 0.0001

        # 1. Cron dropper gone
        if not self._exists(self._CRON_DROP):
            score += 0.20

        # 2. Beacon process dead
        if not self._pgrep("network-monitor"):
            score += 0.20

        # 3. C2 config deleted
        if not self._exists(self._C2_CONFIG):
            score += 0.15

        # 4. Beacon binary deleted
        if not self._exists(self._BEACON_BIN):
            score += 0.10

        # 5. SSH backdoor process dead
        if not self._pgrep("ssh-agent-proxy"):
            score += 0.15

        # 6. Rogue key purged from authorized_keys
        rogue_present = (
            subprocess.run(
                ["grep", "-q", self._ROGUE_KEY_TAG, self._AUTH_KEYS],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
            if self._exists(self._AUTH_KEYS)
            else False
        )
        if not rogue_present:
            score += 0.10

        # 7. Secrets dump deleted
        if not self._exists(self._SECRETS):
            score += 0.10

        return min(0.9999, round(score, 4))


#  Registry
ALL_TASKS: List[ThreatTask] = [
    HttpListenerTask(),
    CryptoMinerTask(),
    SshTunnelTask(),
    CronBackdoorTask(),
    KeyloggerTask(),
    APTInfiltrationTask(),
    DataExfilTask(),
    FakePkgUpdaterTask(),
    SyslogDaemonTask(),
    EnvPoisonRootkitTask(),
    CredentialHarvesterTask(),
    PrivescTask(),
]

if __name__ == "__main__":
    print("Total tasks: ", len(ALL_TASKS))
    print("=" * 80)
    for task in ALL_TASKS:
        print(
            f"- {task.threat_id} [{task.difficulty.upper():^9}] [{task.severity:^9}] - {task.label}"
        )
    print("=" * 80)
