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

import subprocess
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

from models import AgentrologyAction, AgentrologyObservation, ThreatStatus
from server.security import CommandValidator
from server.threat_manager import THREAT_META, GraderResult, ThreatManager

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

_COMMAND_TIMEOUT_SECONDS = 5
_STDOUT_MAX_CHARS = 2000
_STDERR_MAX_CHARS = 1000


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
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._validator = CommandValidator()
        self._threat_manager = ThreatManager()
        self._previous_result = GraderResult()
        self._threat_manager.setup_scripts()

    def reset(self) -> AgentrologyObservation:
        """Tear down any active threats and spawn a fresh incident.

        Returns:
            An AgentrologyObservation with active_threats == 6 and the
            incident response banner in stdout.
        """
        self._state = State(episode_id=str(uuid4()), step_count=0)
        self._threat_manager.teardown()
        self._threat_manager.setup_scripts()
        self._threat_manager.spawn()
        self._previous_result = GraderResult()

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
            return self._blocked_observation(command, current, validation.reason)

        stdout, stderr, return_code = self._execute(command)
        current = self._threat_manager.grade()
        reward = self._compute_reward(command, return_code, current)
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

    @property
    def state(self) -> State:
        """Return the current OpenEnv State.

        Returns:
            The internal State carrying episode ID and step count.
        """
        return self._state

    def _execute(self, command: str) -> tuple[str, str, int]:
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

    def _compute_reward(
        self,
        command: str,
        return_code: int,
        current: GraderResult,
    ) -> float:
        """Compute the delta-based shaped reward for this step.

        Reward components:
            Score delta:  Σ max(0, current_score[i] - previous_score[i])
                          Positive-only so score regressions on self-healing
                          threats do not penalise the agent twice.
            Diagnostic:   +0.05 for a successful diagnostic command when the
                          score delta is zero (encourages exploration without
                          inflating total episode reward).
            Error:        -0.05 for a failed non-kill command (discourages
                          the agent from getting stuck in an error loop).

        Args:
            command: The shell command that was executed.
            return_code: Exit code returned by the subprocess.
            current: GraderResult snapshot taken after the command ran.

        Returns:
            A rounded float reward value.
        """
        score_delta = sum(
            max(0.0, now - before)
            for now, before in zip(current.scores, self._previous_result.scores)
        )

        reward = score_delta

        if score_delta == 0.0:
            cmd_lower = command.lower()
            is_diagnostic = any(cmd_lower.startswith(p) for p in DIAGNOSTIC_PREFIXES)
            if is_diagnostic and return_code == 0:
                reward += 0.05

        if return_code != 0 and not command.lower().startswith("kill"):
            reward -= 0.05

        return round(reward, 4)

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
            for meta, score in zip(THREAT_META, result.scores)
        ]
