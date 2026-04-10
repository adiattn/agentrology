# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Core Agentrology OpenEnv environment: the Linux Security Arena.

Implements the OpenEnv Environment interface. Owns episode state and
delegates threat lifecycle to ThreatManager and command validation to
CommandValidator.

Reward is computed from the delta between consecutive GraderResult
score vectors so that every incremental improvement (e.g. killing a
self-healing process before its artefacts can be cleaned) earns
proportional reward rather than an all-or-nothing +1.0.

Public surface:
    AgentrologyEnvironment.reset()  -> AgentrologyObservation
    AgentrologyEnvironment.step()   -> AgentrologyObservation
    AgentrologyEnvironment.state    -> State
"""

import logging
import re
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

from models import AgentrologyAction, AgentrologyObservation, ThreatStatus
from server.security import CommandValidator
from server.threat_manager import GraderResult, ThreatManager

SEPARATORS_REGEX = r"(?:\s*(?:;|\|\||&&|\|)\s*)+"
DIAGNOSTIC_PREFIXES = (
    "ps",
    "pgrep",
    "pstree",
    "netstat",
    "ss",
    "lsof",
    "ls",
    "find",
    "grep",
    "cat",
    "stat",
    "file",
    "crontab -l",
    "uptime",
    "who",
    "last",
    "id",
    "whoami",
    "hostname",
    "uname",
    "strings",
)


RESET_BANNER = """[[ AGENTROLOGY INCIDENT RESPONSE CONSOLE ]]

STATUS: ACTIVE BREACH!!
ACTIVE_THREATS: 6 Confirmed Indicators of Compromise (IOCs) Detected
ACTION: IMMEDIATE REMEDIATION REQUIRED

Threat intelligence briefing loaded. Begin investigation.
"""

_COMMAND_TIMEOUT_SECONDS = 10
_COMMAND_REPETITION_THRESHOLD = 5  # max these many repetitions allowed
_COMMAND_REPETITION_PENALTY = 0.1  # penalty per repetition beyond threshold
_STDOUT_MAX_CHARS = 2000
_STDERR_MAX_CHARS = 1000

_executor = ThreadPoolExecutor(max_workers=4)


class AgentrologyEnvironment(Environment):
    """OpenEnv environment that simulates a compromised Linux host.

    On reset() it delegates to ThreatManager to spawn six threat
    processes and plant associated filesystem artefacts. On every
    step() it validates the agent's command through CommandValidator,
    executes it in a subprocess, then asks ThreatManager to grade the
    resulting OS state and computes a delta-based shaped reward.

    Reward shaping
    ──────────────
    Each step reward is the sum of per-threat score improvements:
        reward = Σ max(0, current_score[i] - previous_score[i])
    Score improvements from 0.0 → 0.4 (killing a self-healing process)
    and from 0.4 → 1.0 (then cleaning its artefacts) are each rewarded
    separately. Score regressions (artefact reappears) do not incur a
    negative — the reward simply returns to 0.0 for that step.

    Attributes:
        SUPPORTS_CONCURRENT_SESSIONS: OpenEnv flag enabling multiple
            simultaneous sessions against this server.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self) -> None:
        """Initialise the environment with fresh collaborators."""
        super().__init__()
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._validator = CommandValidator()
        self._threat_manager = ThreatManager()
        self._previous_result = GraderResult()
        self._threat_manager.setup_scripts()
        self.command_history: list[str] = []
        self._trace_steps: list[dict[str, Any]] = []
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.setLevel(logging.DEBUG)
        self._logger.info("Environment initialized.")

    def generate_restricted_process_list(self) -> list[str]:
        """Generate a list of processes that should be restricted.

        Returns:
            A list of process names to be restricted.
        """
        return []

    def reset(self) -> AgentrologyObservation:
        """Tear down any active threats and spawn a fresh incident.

        Returns:
            An AgentrologyObservation with active_threats == 6 and the
            incident response banner in stdout.
        """
        self._logger.info("Resetting environment and spawning new incident.")
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._threat_manager.teardown()
        self._threat_manager.setup_scripts()
        self._threat_manager.spawn()
        self._previous_result = GraderResult()
        self.command_history.clear()
        self._trace_steps.clear()

        return AgentrologyObservation(
            stdout=RESET_BANNER,
            stderr="",
            active_threats=6,
            reward=0.0,
            done=False,
            threat_status=self._build_threat_status(self._previous_result),
            metadata={
                "step": 0,
                "episode_id": self._state.episode_id,
                "scores": self._previous_result.scores,
                "total_score": self._previous_result.total_score,
            },
        )

    def step(self, action: AgentrologyAction) -> AgentrologyObservation:
        """Execute one agent action and return the updated observation.

        Flow:
            1. Validate the command through CommandValidator.
            2. If blocked, return a security-violation observation without
               executing or grading (step count still increments).
            3. Execute the command in a sandboxed subprocess with timeout.
            4. Ask ThreatManager to grade current OS state.
            5. Compute delta-based shaped reward and return observation.

        Args:
            action: The AgentrologyAction containing the command to run.

        Returns:
            An AgentrologyObservation with stdout, stderr, per-threat
            float scores, reward, and done signal.
        """
        self._state.step_count += 1
        command = action.command.strip()

        validation = self._validator.validate(command)
        if not validation.is_allowed:
            current = self._threat_manager.grade()
            self._record_trace(command, "", "", current, validation.reason)
            return self._blocked_observation(command, current, validation.reason)

        # repetition count: how many times has this exact command been executed consequently in the past?
        repetition_count = 0
        for i in range(len(self.command_history) - 1, -1, -1):
            if self.command_history[i] == command:
                repetition_count += 1
            else:
                break

        self.command_history.append(command)
        if "ps" not in command and "pgrep" not in command and "pstree" not in command:
            if repetition_count >= _COMMAND_REPETITION_THRESHOLD:
                current = self._threat_manager.grade()
                reason = f"Command has been executed {repetition_count} times. "
                self._record_trace(command, "", "", current, reason)
                return self._blocked_observation(command, current, reason)
            elif repetition_count > 2:
                penalty = repetition_count * _COMMAND_REPETITION_PENALTY
                current = self._threat_manager.grade()
                reward = -penalty
                reason = f"Command has been executed {repetition_count} times."
                self._record_trace(command, "", "", current, reason)

                # Note: Not updating self._previous_result here intentionally for repetition penalties.
                return AgentrologyObservation(
                    stdout="",
                    stderr="",
                    active_threats=current.active_count,
                    reward=reward,
                    done=current.all_clear,
                    threat_status=self._build_threat_status(current),
                    security_violation=reason,
                    metadata={
                        "step": self._state.step_count,
                        "command": command,
                        "repetition_count": repetition_count,
                        "scores": current.scores,
                        "total_score": current.total_score,
                    },
                )

        self._logger.debug(f"Executing command: {command}")
        stdout, stderr, return_code = self._execute(command)
        self._logger.debug(
            f"Command return code: {return_code}, stdout length: {len(stdout)}, stderr: length: {len(stderr)}"
        )
        current = self._threat_manager.grade()
        reward = self._compute_reward(command, return_code, current)

        self._record_trace(command, stdout, stderr, current, "")
        self._previous_result = current

        return AgentrologyObservation(
            stdout=stdout,
            stderr=stderr,
            active_threats=current.active_count,
            reward=reward,
            done=current.all_clear,
            threat_status=self._build_threat_status(current),
            security_violation="",
            metadata={
                "step": self._state.step_count,
                "command_run": command,
                "return_code": return_code,
                "scores": current.scores,
                "total_score": current.total_score,
            },
        )

    def _record_trace(
        self,
        command: str,
        stdout: str,
        stderr: str,
        current: GraderResult,
        blocked_reason: str,
    ):
        neutralised_threats = []
        for i, (old_score, new_score) in enumerate(
            zip(self._previous_result.scores, current.scores, strict=False)
        ):
            if old_score < 1.0 and new_score >= 1.0:
                neutralised_threats.append(
                    self._threat_manager.threat_meta()[i]["threat_id"]
                )

        self._trace_steps.append(
            {
                "step_id": self._state.step_count,
                "command": command,
                "stdout": stdout,
                "stderr": stderr,
                "blocked_reason": blocked_reason,
                "neutralised_threats": neutralised_threats,
            }
        )

    @property
    def state(self) -> State:
        """Return the current OpenEnv State.

        Returns:
            The internal State carrying episode ID and step count.
        """
        return self._state

    def _execute(self, command: str):
        future = _executor.submit(self._execute_command, command)
        return future.result()

    def _execute_command(self, command: str) -> tuple[str, str, int]:
        """Run a validated shell command and capture its output.

        Args:
            command: The validated shell command string.

        Returns:
            A three-tuple of (stdout, stderr, return_code). Strings are
            truncated to their respective character limits.
            return_code is 124 on timeout and 1 on unexpected exception.
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=_COMMAND_TIMEOUT_SECONDS,
            )
            return (
                result.stdout[:_STDOUT_MAX_CHARS],
                result.stderr[:_STDERR_MAX_CHARS],
                result.returncode,
            )
        except subprocess.TimeoutExpired:
            return ("", f"Command timed out after {_COMMAND_TIMEOUT_SECONDS}s.", 124)
        except Exception as exc:
            return ("", str(exc)[:_STDERR_MAX_CHARS], 1)

    def is_repeating_bad_command(self, command: str, threshold: int = 3) -> bool:
        """
        Detect repeated command patterns like:
        - "whoami whoami whoami"
        - "whoami && whoami && whoami"
        - "ls | ls | ls"

        Args:
            command: Input command string
            threshold: Minimum repetition count to flag

        Returns:
            bool
        """
        MIN_REP_CMD_LENGTH = 8
        if len(command) < MIN_REP_CMD_LENGTH:
            return False

        command = command.strip()

        # Case 1: simple repetition via whitespace (no separators)
        tokens = command.split()
        if len(tokens) > 1:
            token_counts = Counter(tokens)
            _, count = token_counts.most_common(1)[0]

            # If one token dominates heavily -> repetition
            if count >= threshold and count / len(tokens) > 0.6:
                return True

        # Case 2: repetition via shell separators
        parts = re.split(SEPARATORS_REGEX, command)
        parts = [re.sub(r"\s+", " ", p.strip().lower()) for p in parts if p.strip()]

        if len(parts) >= threshold:
            counts = Counter(parts)
            _, count = counts.most_common(1)[0]

            if count >= threshold:
                return True

        return False

    def _ensure_safe_reward(self, reward: float) -> float:
        """Clamp reward to a range of [0.0, 1.0] to prevent runaway values from unexpected score deltas.

        Args:
            reward: The raw computed reward for the current step.

        Returns:
            A float reward value clamped between 0.0 and 1.0.
        """
        if reward < 0.0:
            reward = 0.0001
        if reward >= 1.0:
            reward = 0.9999
        return reward

    def _compute_reward(
        self,
        command: str,
        return_code: int,
        current: GraderResult,
    ) -> float:
        """Compute the delta-based shaped reward for this step.

        Reward components:
            Score delta:  Σ (current_score[i] - previous_score[i])
                          True delta, meaning score regressions on self-healing
                          threats will correctly penalise the agent and encourage urgency.
            Diagnostic:   +0.05 for a successful diagnostic command when the
                          score delta is zero (encourages exploration without
                          inflating total episode reward).
            Error:        -0.1 for any failed command (discourages
                          the agent from getting stuck in an error loop).

        Args:
            command: The shell command that was executed.
            return_code: Exit code returned by the subprocess.
            current: GraderResult snapshot taken after the command ran.

        Returns:
            A rounded float reward value.
        """
        score_delta = sum(
            (now - before)
            for now, before in zip(
                current.scores, self._previous_result.scores, strict=False
            )
        )

        reward = score_delta

        if score_delta == 0.0:
            cmd_lower = command.lower()
            is_diagnostic = any(cmd_lower.startswith(p) for p in DIAGNOSTIC_PREFIXES)
            if is_diagnostic and return_code == 0:
                reward += 0.05

        if return_code != 0:
            reward -= 0.08

        if self.is_repeating_bad_command(
            command, threshold=_COMMAND_REPETITION_THRESHOLD
        ):
            reward -= 0.1

        return round(self._ensure_safe_reward(reward), 4)

    def _blocked_observation(
        self,
        command: str,
        current: GraderResult,
        reason: str,
    ) -> AgentrologyObservation:
        """Build an observation for a command blocked by the security policy.

        Args:
            command: The command string that was rejected.
            current: GraderResult from a grader run (no execution happened).
            reason: Human-readable explanation of why the command was blocked.

        Returns:
            An AgentrologyObservation with security_violation populated
            and zero reward.
        """
        return AgentrologyObservation(
            stdout="",
            stderr="",
            active_threats=current.active_count,
            reward=0.0,
            done=current.all_clear,
            threat_status=self._build_threat_status(current),
            security_violation=reason,
            metadata={
                "step": self._state.step_count,
                "command_blocked": command,
                "scores": current.scores,
                "total_score": current.total_score,
            },
        )

    def _build_threat_status(self, result: GraderResult) -> list[ThreatStatus]:
        """Construct ThreatStatus objects from a GraderResult.

        Args:
            result: The GraderResult whose scores list to wrap.

        Returns:
            A list of ThreatStatus instances aligned with THREAT_META order.
        """
        return [
            ThreatStatus(
                threat_id=meta["threat_id"],
                label=meta["label"],
                severity=meta["severity"],
                neutralised=score >= 1.0,
            )
            for meta, score in zip(
                self._threat_manager.threat_meta(), result.scores, strict=False
            )
        ]

    def get_trace(self) -> dict[str, Any]:
        result = self._previous_result
        threats = [
            {
                "threat_id": meta["threat_id"],
                "label": meta["label"],
                "severity": meta["severity"],
                "conditions": meta.get("conditions", []),
                "score": score,
                "neutralised": score >= 1.0,
            }
            for meta, score in zip(
                self._threat_manager.threat_meta(), result.scores, strict=False
            )
        ]
        return {
            "type": "trace",
            "commands": self.command_history,
            "step_count": self._state.step_count,
            "total_score": result.total_score,
            "active_threats": result.active_count,
            "threats": threats,
            "steps": self._trace_steps,
        }
