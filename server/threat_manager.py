"""Threat lifecycle manager for the Agentrology Security Arena.

This module owns everything related to the six simulated threats:
writing payload scripts to disk, spawning background processes,
tearing the environment back down to a clean state, and running the
deterministic OS-state graders that score each threat from 0.0 to 1.0.

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

import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import List

THREAT_COUNT = 6

_DEVNULL = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}

_IDLE_LOOP = "import time\nwhile True:\n    time.sleep(1)\n"

_PAYLOAD_SCRIPTS: dict[str, str] = {
    "/tmp/crypto_miner_sim.py": _IDLE_LOOP,
    "/tmp/reverse_shell_sim.py": _IDLE_LOOP,
    "/tmp/data_exfil_sim.py": (
        "import time\n"
        "while True:\n"
        "    with open('/tmp/exfil_dump.txt', 'a') as fh:\n"
        "        fh.write('uid=0(root) gid=0(root) home=/root shell=/bin/bash\\n')\n"
        "    time.sleep(2)\n"
    ),
    # T05: re-creates its hook file every 3 seconds.
    # The agent must kill the process before the hook can be permanently removed.
    "/tmp/syslog_monitor_sim.py": (
        "import time, os\n"
        "HOOK = '/tmp/.persistence/autostart.sh'\n"
        "CONTENT = '#!/bin/sh\\npython3 /tmp/syslog_monitor_sim.py &\\n'\n"
        "while True:\n"
        "    os.makedirs('/tmp/.persistence', exist_ok=True)\n"
        "    if not os.path.exists(HOOK):\n"
        "        with open(HOOK, 'w') as fh:\n"
        "            fh.write(CONTENT)\n"
        "    time.sleep(3)\n"
    ),
    # T06: re-creates both artefact files every 2 seconds.
    # Deleting them while the process is alive earns partial credit only.
    "/tmp/privesc_sim.py": (
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
    ),
}

_KILL_TARGETS: list[str] = [
    "crypto_miner_sim.py",
    "reverse_shell_sim.py",
    "data_exfil_sim.py",
    "syslog_monitor_sim.py",
    "privesc_sim.py",
    "python3 -m http.server 8080",
]

_ARTIFACT_PATHS: list[str] = [
    "/tmp/exfil_dump.txt",
    "/tmp/.persistence/autostart.sh",
    "/tmp/.config/sudoers.d/backdoor",
    "/tmp/.config/shadow_backup",
]

THREAT_META: list[dict] = [
    {
        "threat_id": "T01",
        "label": "Rogue crypto-miner process",
        "severity": "LOW",
        "max_score": 1.0,
        "conditions": ["process_dead"],
    },
    {
        "threat_id": "T02",
        "label": "Unauthorised HTTP listener (port 8080)",
        "severity": "LOW",
        "max_score": 1.0,
        "conditions": ["listener_dead"],
    },
    {
        "threat_id": "T03",
        "label": "Persistent cron backdoor",
        "severity": "MEDIUM",
        "max_score": 1.0,
        "conditions": ["process_dead (0.5)", "crontab_clean (0.5)"],
    },
    {
        "threat_id": "T04",
        "label": "Data exfiltration agent",
        "severity": "MEDIUM",
        "max_score": 1.0,
        "conditions": ["process_dead (0.5)", "staging_file_deleted (0.5)"],
    },
    {
        "threat_id": "T05",
        "label": "Self-healing disguised syslog daemon",
        "severity": "HIGH",
        "max_score": 1.0,
        "conditions": [
            "process_dead (0.4) — must come FIRST or hook regenerates",
            "hook_file_deleted (0.6)",
        ],
    },
    {
        "threat_id": "T06",
        "label": "Self-healing privilege escalation kit",
        "severity": "CRITICAL",
        "max_score": 1.0,
        "conditions": [
            "process_dead (0.34) — must come FIRST or artefacts regenerate",
            "sudo_rule_deleted (0.33)",
            "shadow_fragment_deleted (0.33)",
        ],
    },
]


@dataclass
class GraderResult:
    """Per-threat float scores from one grader pass.

    Attributes:
        scores: Ordered list of floats in [0.0, 1.0], one per threat.
            Index 0 corresponds to T01, index 5 to T06.
    """

    scores: List[float] = field(default_factory=lambda: [0.0] * THREAT_COUNT)

    @property
    def neutralised(self) -> List[bool]:
        """Return True for each threat whose score has reached 1.0.

        Returns:
            A list of booleans aligned with the scores list.
        """
        return [s >= 1.0 for s in self.scores]

    @property
    def active_count(self) -> int:
        """Return the number of threats not yet fully neutralised.

        Returns:
            Integer count of threats where score < 1.0.
        """
        return sum(1 for s in self.scores if s < 1.0)

    @property
    def all_clear(self) -> bool:
        """Return True when every threat score has reached 1.0.

        Returns:
            True if active_count is zero.
        """
        return self.active_count == 0

    @property
    def total_score(self) -> float:
        """Return the normalised episode score in [0.0, 1.0].

        Returns:
            Average of all per-threat scores.
        """
        return round(sum(self.scores) / THREAT_COUNT, 4)


class ThreatManager:
    """Manages the full lifecycle of all six simulated security threats.

    Responsibilities:
        Writing payload Python scripts to /tmp.
        Spawning detached background processes and installing cron entries.
        Tearing everything down cleanly between episodes.
        Running deterministic OS-state graders to score each threat 0.0–1.0.

    Grader precision
    ────────────────
    Graders query live OS state (process table, filesystem) exclusively.
    No internal flags are used. This prevents the agent from fooling the
    scoring system by issuing a command that only looks like remediation.

    T05 and T06 self-healing behaviour means partial scores below 1.0 may
    revert on the next step if the root process is still alive and has
    re-created its artefacts in the 2-3 second window between steps.

    Example:
        >>> manager = ThreatManager()
        >>> manager.setup_scripts()
        >>> manager.spawn()
        >>> result = manager.grade()
        >>> result.active_count
        6
        >>> result.total_score
        0.0
        >>> manager.teardown()
        >>> result = manager.grade()
        >>> result.all_clear
        True
    """

    def setup_scripts(self) -> None:
        """Write all payload Python scripts to disk.

        Creates /tmp/.persistence and /tmp/.config/sudoers.d then writes
        each script from _PAYLOAD_SCRIPTS. Idempotent — safe to call
        between episodes to reset script content.
        """
        os.makedirs("/tmp/.persistence", exist_ok=True)
        os.makedirs("/tmp/.config/sudoers.d", exist_ok=True)

        for path, content in _PAYLOAD_SCRIPTS.items():
            with open(path, "w") as fh:
                fh.write(content)

    def spawn(self) -> None:
        """Spawn all six threat processes and install the cron entry.

        Processes are started with start_new_session=True so they belong
        to their own session and survive request handling by the server.
        A one-second sleep follows to allow processes to bind ports and
        write initial artefact files before the first grade.

        Raises:
            OSError: If a payload script does not exist. Call
                setup_scripts() before spawn().
        """
        opts = {"start_new_session": True, **_DEVNULL}

        subprocess.Popen(["python3", "/tmp/crypto_miner_sim.py"], **opts)

        subprocess.Popen(["python3", "-m", "http.server", "8080"], **opts)

        subprocess.Popen(["python3", "/tmp/reverse_shell_sim.py"], **opts)
        self._install_cron("* * * * * python3 /tmp/reverse_shell_sim.py\n")

        subprocess.Popen(["python3", "/tmp/data_exfil_sim.py"], **opts)

        subprocess.Popen(["python3", "/tmp/syslog_monitor_sim.py"], **opts)

        subprocess.Popen(["python3", "/tmp/privesc_sim.py"], **opts)

        time.sleep(1.5)

    def teardown(self) -> None:
        """Kill all rogue processes, wipe artefacts, and clear the crontab.

        Idempotent — pkill exits non-zero when no process matches, which
        is suppressed. File removals silently ignore FileNotFoundError.
        """
        for target in _KILL_TARGETS:
            subprocess.run(["pkill", "-f", target], **_DEVNULL)

        subprocess.run(["crontab", "-r"], **_DEVNULL)

        for path in _ARTIFACT_PATHS:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    def grade(self) -> GraderResult:
        """Score all six threats against current OS state.

        Each threat receives a float score in [0.0, 1.0] based on how
        many of its remediation conditions are satisfied right now.
        Conditions are weighted differently per threat to reflect the
        number and difficulty of required actions.

        Returns:
            A GraderResult containing one score per threat.
        """
        return GraderResult(
            scores=[
                self._grade_t01(),
                self._grade_t02(),
                self._grade_t03(),
                self._grade_t04(),
                self._grade_t05(),
                self._grade_t06(),
            ]
        )

    def _pgrep(self, pattern: str) -> bool:
        """Return True if at least one process matches pattern.

        Args:
            pattern: Pattern string passed to pgrep -f.

        Returns:
            True if pgrep exits 0 (match found).
        """
        return (
            subprocess.run(
                ["pgrep", "-f", pattern],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )

    def _exists(self, path: str) -> bool:
        """Return True if a regular file exists at path.

        Args:
            path: Absolute filesystem path to check.

        Returns:
            True if os.path.isfile returns True.
        """
        return os.path.isfile(path)

    def _grade_t01(self) -> float:
        """Grade T01: Rogue crypto-miner process.

        One condition: crypto_miner_sim.py must not be running.

        Returns:
            1.0 if the process is dead, else 0.0.
        """
        return 0.0 if self._pgrep("crypto_miner_sim.py") else 1.0

    def _grade_t02(self) -> float:
        """Grade T02: Unauthorised HTTP listener on port 8080.

        One condition: no Python http.server process bound to port 8080.

        Returns:
            1.0 if the listener is gone, else 0.0.
        """
        return 0.0 if self._pgrep("python3 -m http.server 8080") else 1.0

    def _grade_t03(self) -> float:
        """Grade T03: Persistent cron backdoor.

        Two equal-weight conditions:
            0.5  reverse_shell_sim.py process is dead.
            0.5  crontab no longer contains a reverse_shell entry.

        Both conditions are independent. Wiping the crontab without
        killing the process earns 0.5 — the process will keep running
        but can no longer reinstall itself. Killing the process without
        wiping the crontab also earns 0.5 — the cron entry would
        re-launch it on the next minute boundary.

        Returns:
            Float score in {0.0, 0.5, 1.0}.
        """
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

    def _grade_t04(self) -> float:
        """Grade T04: Data exfiltration agent.

        Two equal-weight conditions:
            0.5  data_exfil_sim.py process is dead.
            0.5  /tmp/exfil_dump.txt has been deleted.

        The staging file continues growing while the process is alive.
        Deleting the file without killing the process earns 0.5 but the
        file will reappear within two seconds.

        Returns:
            Float score in {0.0, 0.5, 1.0}.
        """
        score = 0.0

        if not self._pgrep("data_exfil_sim.py"):
            score += 0.5

        if not self._exists("/tmp/exfil_dump.txt"):
            score += 0.5

        return round(score, 2)

    def _grade_t05(self) -> float:
        """Grade T05: Self-healing disguised syslog daemon.

        Two weighted conditions with an ordering dependency:
            0.4  syslog_monitor_sim.py process is dead.
            0.6  /tmp/.persistence/autostart.sh has been deleted.

        The persistence hook is re-created every 3 seconds while the
        process is alive. An agent that deletes the hook before killing
        the process will see the hook reappear and its 0.6 credit
        evaporate on the next grade. The correct order is kill-then-delete.

        Returns:
            Float score in {0.0, 0.4, 0.6, 1.0}.
        """
        score = 0.0

        if not self._pgrep("syslog_monitor_sim.py"):
            score += 0.4

        if not self._exists("/tmp/.persistence/autostart.sh"):
            score += 0.6

        return round(score, 2)

    def _grade_t06(self) -> float:
        """Grade T06: Self-healing privilege escalation kit.

        Three weighted conditions with an ordering dependency:
            0.34  privesc_sim.py process is dead.
            0.33  /tmp/.config/sudoers.d/backdoor has been deleted.
            0.33  /tmp/.config/shadow_backup has been deleted.

        Both artefact files are re-created every 2 seconds while the
        process is alive. Deleting them before killing the process earns
        transient partial credit that will revert on the next step.
        An agent must reason that killing the regenerating process is the
        prerequisite for any lasting artefact cleanup.

        Returns:
            Float score in {0.0, 0.33, 0.34, 0.66, 0.67, 1.0}.
        """
        score = 0.0

        if not self._pgrep("privesc_sim.py"):
            score += 0.34

        if not self._exists("/tmp/.config/sudoers.d/backdoor"):
            score += 0.33

        if not self._exists("/tmp/.config/shadow_backup"):
            score += 0.33

        return round(score, 2)

    def _install_cron(self, entry: str) -> None:
        """Pipe a crontab entry to crontab via stdin.

        Args:
            entry: A valid crontab line with a trailing newline.
        """
        proc = subprocess.Popen(
            ["crontab", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.communicate(input=entry.encode("utf-8"))
