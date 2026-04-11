"""Centralized reward computation for the Agentrology Security Arena.

All reward shaping logic lives here. ``AgentrologyEnvironment`` delegates
every reward decision to ``RewardComputer``, which accepts the full context
for one step and returns a single float reward alongside a structured
breakdown for debugging.

RewardComputer is *stateful* — it tracks how many times each exact command
has been seen this episode so that exploration bonuses decay as the agent
repeats the same commands. Call ``reset()`` at the start of every episode.

Reward components (in priority order)
1. BLOCKED (validation penalty)
   The command was rejected by the security policy. The ``ValidationResult``
   already carries a tiered penalty (set at rule-classification time in
   security.py). No other components apply.

2. SCORE DELTA (neutralization progress)
   Σ (current_score[i] − previous_score[i]) across all threats.
   Positive when threats are neutralised, negative when self-healing threats
   recover ground. This is the primary learning signal.

3. EXPLORATION BONUS (no score change steps only)
   When score_delta == 0 the agent gets small auxiliary rewards so it is not
   completely starved of signal during reconnaissance. Bonuses DECAY the more
   times the same command has already been run this episode:

   times_seen  diagnostic_bonus   non_diagnostic_bonus
       1           +0.05              +0.01
       2           +0.025             +0.005
       3           +0.01              +0.002
      4+            0.0               0.0

   Diagnostics that exit non-zero (grep finds nothing, pgrep no match) are
   NOT penalised — they still receive a small fraction of the diagnostic
   bonus, because an empty result is still informative exploration.

   Non-diagnostic commands with a non-zero exit get no bonus here; the
   execution-error penalty handles them in component 4.

4. EXECUTION ERROR (non-diagnostic commands only)
   −0.04  when a non-diagnostic command exits non-zero.
   Diagnostics are exempt because grep/find/pgrep frequently exit 1 with
   perfectly valid (empty) results.

5. INTRA-COMMAND REPETITION PENALTY
   −0.1  when the command string itself contains repeated sub-commands
   (e.g. ``whoami && whoami && whoami``). Detected by the environment via
   ``is_repeating_bad_command()`` before calling compute_step().

Final reward is clamped to [−1.0, 10.0]:
  - Floor −1.0 prevents a single bad step from dominating the episode.
  - Ceiling 10.0 allows rare multi-threat simultaneous clears.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

from server.security import ValidationResult

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

KILL_PREFIXES = ("pkill", "kill", "killall")

_REWARD_FLOOR = -1.0
_REWARD_CEILING = 10.0

# Exploration bonus decay table keyed by times_seen (1-indexed).
# Index 0 is unused; index 4+ maps to 0.0.
_DIAG_BONUS_BY_SEEN: list[float] = [0.0, 0.05, 0.025, 0.01, 0.0]
_NDIAG_BONUS_BY_SEEN: list[float] = [0.0, 0.01, 0.005, 0.002, 0.0]

# Fractional bonus for a diagnostic that exits non-zero (e.g. grep no-match)
_DIAG_FAIL_FRACTION = 0.4  # 40% of normal diagnostic bonus

# Error penalty – only non-diagnostic commands
_ERROR_PENALTY = -0.04

# Intra-command repetition penalty
_INTRA_REPEAT_PENALTY = -0.1


@dataclass
class RewardBreakdown:
    """Structured breakdown of one step's reward computation.

    Every field represents one additive component of the final reward.
    Useful for logging, debugging, and dashboard display.
    """

    blocked: bool = False
    violation_penalty: float = 0.0
    score_delta: float = 0.0
    exploration_bonus: float = 0.0
    is_diagnostic: bool = False
    times_seen: int = 0
    error_penalty: float = 0.0
    intra_repeat_penalty: float = 0.0
    total: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "blocked": self.blocked,
            "violation_penalty": self.violation_penalty,
            "score_delta": round(self.score_delta, 4),
            "exploration_bonus": round(self.exploration_bonus, 4),
            "is_diagnostic": self.is_diagnostic,
            "times_seen": self.times_seen,
            "error_penalty": self.error_penalty,
            "intra_repeat_penalty": self.intra_repeat_penalty,
            "total": round(self.total, 4),
            "notes": self.notes,
        }


class RewardComputer:
    """Computes the shaped reward for a single environment step.

    Stateful: maintains a per-episode count of how many times each command
    has been executed so exploration bonuses can decay appropriately.
    Call ``reset()`` at the start of every new episode.
    """

    def __init__(self) -> None:
        self._seen: Dict[str, int] = defaultdict(int)

    def reset(self) -> None:
        """Clear all per-episode state.

        Must be called at the start of each new episode (when the
        environment resets) so command-seen counts start fresh.
        """
        self._seen.clear()

    def compute_blocked(
        self,
        validation: ValidationResult,
    ) -> tuple[float, RewardBreakdown]:
        """Reward for a command blocked by the security policy.

        Only the validation penalty applies; no other components run.
        The _seen counter is NOT incremented for blocked commands.

        Args:
            validation: The rejected ValidationResult (carries .penalty).

        Returns:
            (reward, breakdown)
        """
        bd = RewardBreakdown(
            blocked=True,
            violation_penalty=validation.penalty,
            notes=[f"blocked: {validation.reason}"],
        )
        bd.total = self._clamp(validation.penalty)
        return bd.total, bd

    def compute_step(
        self,
        *,
        command: str,
        return_code: int,
        prev_scores: List[float],
        curr_scores: List[float],
        is_repeating_bad: bool,
    ) -> tuple[float, RewardBreakdown]:
        """Reward for a command that was executed (not blocked).

        Increments the internal seen-counter for ``command`` before
        computing the exploration bonus, so bonus decay applies
        starting from the *second* execution.

        Args:
            command: The shell command that ran.
            return_code: Subprocess exit code (0 = success).
            prev_scores: Per-threat scores from the *previous* step.
            curr_scores: Per-threat scores from the *current* step.
            is_repeating_bad: True if the command string itself contains
                a suspicious repeated sub-command pattern (detected by
                the environment before calling this method).

        Returns:
            (reward, breakdown)
        """
        # Track how many times this command has been run this episode
        self._seen[command] += 1
        times_seen = self._seen[command]

        bd = RewardBreakdown(times_seen=times_seen)
        cmd_lower = command.lower()

        bd.score_delta = sum(
            now - before for now, before in zip(curr_scores, prev_scores, strict=False)
        )
        reward = bd.score_delta

        if bd.score_delta == 0.0:
            bd.is_diagnostic = any(cmd_lower.startswith(p) for p in DIAGNOSTIC_PREFIXES)

            idx = min(times_seen, len(_DIAG_BONUS_BY_SEEN) - 1)

            if bd.is_diagnostic:
                base_bonus = _DIAG_BONUS_BY_SEEN[idx]
                if return_code == 0:
                    bd.exploration_bonus = base_bonus
                    bd.notes.append(
                        f"diag (seen={times_seen}, rc=0) bonus={base_bonus:.4f}"
                    )
                else:
                    # Non-zero exit is still valid exploration (grep no-match etc.)
                    # give a fraction of the base bonus, never penalise.
                    bd.exploration_bonus = round(base_bonus * _DIAG_FAIL_FRACTION, 4)
                    bd.notes.append(
                        f"diag (seen={times_seen}, rc={return_code}) partial_bonus={bd.exploration_bonus:.4f}"
                    )
            else:
                base_bonus = _NDIAG_BONUS_BY_SEEN[idx]
                if return_code == 0:
                    bd.exploration_bonus = base_bonus
                    bd.notes.append(
                        f"non-diag (seen={times_seen}, rc=0) bonus={base_bonus:.4f}"
                    )
                # non-zero non-diagnostic: no bonus; error penalty fires below

            reward += bd.exploration_bonus

        # 3. Error penalty (non-diagnostic and non-kill commands only)
        is_kill_cmd = any(cmd_lower.startswith(p) for p in KILL_PREFIXES)
        if return_code != 0 and not bd.is_diagnostic and not is_kill_cmd:
            bd.error_penalty = _ERROR_PENALTY
            reward += bd.error_penalty
            bd.notes.append(f"error penalty (rc={return_code})")

        if is_repeating_bad:
            bd.intra_repeat_penalty = _INTRA_REPEAT_PENALTY
            reward += bd.intra_repeat_penalty
            bd.notes.append("intra-command repetition pattern")

        bd.total = self._clamp(round(reward, 4))
        return bd.total, bd

    @staticmethod
    def _clamp(value: float) -> float:
        return max(_REWARD_FLOOR, min(_REWARD_CEILING, value))
