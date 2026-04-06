# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Agentrology Environment Implementation.

A simple test environment that echoes back messages sent to it.
Perfect for testing HTTP server infrastructure.
"""

import subprocess
import time
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

from models import AgentrologyAction, AgentrologyObservation


class AgentrologyEnvironment(Environment):
    """
    A simple echo environment that echoes back messages.

    This environment is designed for testing the HTTP server infrastructure.
    It maintains minimal state and simply echoes back whatever message it receives.

    Example:
        >>> env = AgentrologyEnvironment()
        >>> obs = env.reset()
        >>> print(obs.echoed_message)  # "Agentrology environment ready!"
        >>>
        >>> obs = env.step(AgentrologyAction(message="Hello"))
        >>> print(obs.echoed_message)  # "Hello"
        >>> print(obs.message_length)  # 5
    """

    # Enable concurrent WebSocket sessions.
    # Set to True if your environment isolates state between instances.
    # When True, multiple WebSocket clients can connect simultaneously, each
    # getting their own environment instance (when using factory mode in app.py).
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        """Initialize the agentrology environment."""
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._reset_count = 0
        self._previous_threats = 3
        self._setup_payloads()

    def _setup_payloads(self):
        """Write the dummy malicious scripts to the container's temporary directory."""
        miner_script = "import time\nwhile True: time.sleep(1)"
        backdoor_script = "import time\nwhile True: time.sleep(1)"

        with open("/tmp/crypto_miner_sim.py", "w") as f:
            f.write(miner_script)
        with open("/tmp/reverse_shell_sim.py", "w") as f:
            f.write(backdoor_script)

    def _cleanup_environment(self):
        """Kill all rogue processes and wipe the crontab."""
        subprocess.run(
            "pkill -f crypto_miner_sim.py", shell=True, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            "pkill -f reverse_shell_sim.py", shell=True, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            "pkill -f 'python3 -m http.server 8080'",
            shell=True,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run("crontab -r", shell=True, stderr=subprocess.DEVNULL)

    def reset(self) -> AgentrologyObservation:
        """
        Reset the environment and spawns the 3 tier threats.

        Returns:
            AgentrologyObservation
        """
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._reset_count += 1
        self._cleanup_environment()

        # Task 1 (Easy): Rogue background process
        subprocess.Popen(
            ["python3", "/tmp/crypto_miner_sim.py"], start_new_session=True
        )

        # Task 2 (Medium): Unauthorized listener on Port 8080
        subprocess.Popen(
            ["python3", "-m", "http.server", "8080"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Task 3 (Hard): Persistent backdoor via Cron
        subprocess.Popen(
            ["python3", "/tmp/reverse_shell_sim.py"], start_new_session=True
        )
        # Install the cronjob
        cron_job = "* * * * * python3 /tmp/reverse_shell_sim.py\n"
        proc = subprocess.Popen(
            ["crontab", "-"], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        proc.communicate(input=cron_job.encode("utf-8"))

        time.sleep(0.5)  # Give processes a moment to bind
        self._previous_threats = 3

        return AgentrologyObservation(
            stdout="System reset. ALERT: Unauthorized activity detected on host.",
            stderr="",
            active_threats=3,
            reward=0.0,
            done=False,
            metadata={"step": 0},
        )

    def _count_active_threats(self) -> int:
        """Deterministic Grader: Checks the actual OS state to see if threats exist."""
        threats = 0

        # Check Task 1
        if (
            subprocess.run(
                "pgrep -f crypto_miner_sim.py", shell=True, stdout=subprocess.DEVNULL
            ).returncode
            == 0
        ):
            threats += 1

        # Check Task 2 (Checking for process holding port 8080 or the python module)
        if (
            subprocess.run(
                "pgrep -f 'python3 -m http.server 8080'",
                shell=True,
                stdout=subprocess.DEVNULL,
            ).returncode
            == 0
        ):
            threats += 1

        # Check Task 3 (Needs process dead AND cron empty)
        proc_alive = (
            subprocess.run(
                "pgrep -f reverse_shell_sim.py", shell=True, stdout=subprocess.DEVNULL
            ).returncode
            == 0
        )
        cron_check = (
            subprocess.run(
                "crontab -l | grep reverse_shell", shell=True, stdout=subprocess.DEVNULL
            ).returncode
            == 0
        )
        if proc_alive or cron_check:
            threats += 1

        return threats

    def step(self, action: AgentrologyAction) -> AgentrologyObservation:
        """
        Execute a step in the environment.

        Args:
            action: AgentrologyAction containing the shell command to execute

        Returns:
            AgentrologyObservation with the echoed message and its length
        """
        self._state.step_count += 1

        # 1. Execute Agent's Command safely with a timeout
        try:
            result = subprocess.run(
                action.command, shell=True, capture_output=True, text=True, timeout=5
            )
            stdout = result.stdout
            stderr = result.stderr
        except subprocess.TimeoutExpired:
            stdout = ""
            stderr = "Command timed out after 5 seconds."
        except Exception as e:
            stdout = ""
            stderr = str(e)

        # 2. Run the Deterministic Grader
        current_threats = self._count_active_threats()

        # 3. Reward Shaping
        reward = 0.0
        threats_removed = self._previous_threats - current_threats

        if threats_removed > 0:
            reward += threats_removed * 1.0  # 1 point per threat removed

        # Partial reward for diagnostic commands
        elif (
            action.command.startswith(
                ("ps", "netstat", "lsof", "grep", "cat", "crontab -l")
            )
            and result.returncode == 0
        ):
            reward += 0.1

        # Penalty for errors (helps agent avoid infinite failure loops)
        if result.returncode != 0 and not action.command.startswith("kill"):
            reward -= 0.1

        self._previous_threats = current_threats
        done = current_threats == 0

        return AgentrologyObservation(
            stdout=stdout[:2000],  # Truncate massive outputs to save context window
            stderr=stderr[:1000],
            active_threats=current_threats,
            reward=reward,
            done=done,
            metadata={"step": self._state.step_count, "command_run": action.command},
        )

    @property
    def state(self) -> State:
        """
        Get the current environment state.

        Returns:
            Current State with episode_id and step_count
        """
        return self._state
