"""Threat definitaions for the Agentrology Security Arena.

Grader contract
───────────────
Every grader returns a float in [0.0, 1.0] representing what fraction
of that threat's remediation requirements have been satisfied. A score
of 1.0 means the threat is fully neutralised. Intermediate scores
represent partial progress and are awarded to give the reward function
a meaningful gradient.

Difficulty design
─────────────────
T01  LOW      Single condition  → binary  0.0 / 1.0
T02  LOW      Single condition  → binary  0.0 / 1.0
T03  MEDIUM   Two conditions, equal weight → 0.0 / 0.5 / 1.0
T04  MEDIUM   Two conditions, equal weight → 0.0 / 0.5 / 1.0
T05  HIGH     Self-healing artefact + ordering constraint.
              The syslog payload re-creates its persistence hook every
              3 seconds while alive. The agent must kill the process
              FIRST, then delete the hook. Deleting the hook while the
              process still runs earns 0.3 (shows awareness) but the
              file will be recreated before the next grade.
              Score: process_dead × 0.4  +  hook_gone × 0.6
T06  CRITICAL Three conditions + self-healing. The privesc payload
              continuously overwrites both artefact files every 2 s.
              Deleting files while the process is alive earns partial
              credit but they will reappear. Agent must kill the process
              then clean up in subsequent steps.
              Score: process_dead × 0.34  +  sudo_gone × 0.33  +
                     shadow_gone × 0.33
"""

from __future__ import annotations

import subprocess

from server.tasks.task_base import ThreatTask

_DEVNULL = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
_SPAWN_OPTS = {"start_new_session": True, **_DEVNULL}
_IDLE_LOOP = "import time\nwhile True:\n    time.sleep(1)\n"


class CryptoMinerTask(ThreatTask):
    """T01 LOW – Rogue crypto-miner process.

    Condition:
        process_dead (1.0)
    """

    threat_id = "T01"
    label = "Rogue crypto-miner process"
    severity = "LOW"
    conditions = ["process_dead"]

    _SCRIPT = "/tmp/crypto_miner_sim.py"

    def setup_scripts(self) -> None:
        self._write_script(self._SCRIPT, _IDLE_LOOP)

    def spawn(self) -> None:
        subprocess.Popen(["python3", self._SCRIPT], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("crypto_miner_sim.py")

    def grade(self) -> float:
        return 0.0 if self._pgrep("crypto_miner_sim.py") else 1.0


class HttpListenerTask(ThreatTask):
    """T02 LOW – Unauthorised HTTP listener on port 8080.

    Condition:
        listener_dead (1.0)
    """

    threat_id = "T02"
    label = "Unauthorised HTTP listener (port 8080)"
    severity = "LOW"
    conditions = ["listener_dead"]

    def setup_scripts(self) -> None:
        pass  # No script to write; uses the stdlib http.server module.

    def spawn(self) -> None:
        subprocess.Popen(["python3", "-m", "http.server", "8080"], **_SPAWN_OPTS)

    def teardown(self) -> None:
        self._pkill("python3 -m http.server 8080")

    def grade(self) -> float:
        return 0.0 if self._pgrep("python3 -m http.server 8080") else 1.0


class CronBackdoorTask(ThreatTask):
    """T03 MEDIUM – Persistent cron backdoor.

    Conditions (0.5 each, independent):
        process_dead    – reverse_shell_sim.py is not running.
        crontab_clean   – crontab no longer references reverse_shell.
    """

    threat_id = "T03"
    label = "Persistent cron backdoor"
    severity = "MEDIUM"
    conditions = ["process_dead (0.5)", "crontab_clean (0.5)"]

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

    def grade(self) -> float:
        score = 0.0

        if not self._pgrep("reverse_shell_sim.py"):
            score += 0.5

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
            score += 0.5

        return round(score, 2)

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

    threat_id = "T04"
    label = "Data exfiltration agent"
    severity = "MEDIUM"
    conditions = ["process_dead (0.5)", "staging_file_deleted (0.5)"]

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

    def grade(self) -> float:
        score = 0.0

        if not self._pgrep("data_exfil_sim.py"):
            score += 0.5

        if not self._exists(self._DUMP):
            score += 0.5

        return round(score, 2)


class SyslogDaemonTask(ThreatTask):
    """T05 HIGH – Self-healing disguised syslog daemon.

    Conditions (weighted, order-dependent):
        process_dead (0.4) – Must come FIRST; the hook regenerates every 3 s
                             while the process is alive.
        hook_file_deleted (0.6) – /tmp/.persistence/autostart.sh is gone.

    Deleting the hook before killing the process earns transient 0.6 credit
    that evaporates on the next grade when the hook is recreated.
    """

    threat_id = "T05"
    label = "Self-healing disguised syslog daemon"
    severity = "HIGH"
    conditions = [
        "process_dead (0.4) — must come FIRST or hook regenerates",
        "hook_file_deleted (0.6)",
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

    def grade(self) -> float:
        score = 0.0

        if not self._pgrep("syslog_monitor_sim.py"):
            score += 0.4

        if not self._exists(self._HOOK):
            score += 0.6

        return round(score, 2)


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

    threat_id = "T06"
    label = "Self-healing privilege escalation kit"
    severity = "CRITICAL"
    conditions = [
        "process_dead (0.34) — must come FIRST or artefacts regenerate",
        "sudo_rule_deleted (0.33)",
        "shadow_fragment_deleted (0.33)",
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

    def grade(self) -> float:
        score = 0.0

        if not self._pgrep("privesc_sim.py"):
            score += 0.34

        if not self._exists(self._SUDO):
            score += 0.33

        if not self._exists(self._SHADOW):
            score += 0.33

        return round(score, 2)


#  Registry

#: Canonical ordered list of all threat tasks (T01 → T06).
ALL_TASKS: list[ThreatTask] = [
    CryptoMinerTask(),
    HttpListenerTask(),
    CronBackdoorTask(),
    DataExfilTask(),
    SyslogDaemonTask(),
    PrivescTask(),
]
