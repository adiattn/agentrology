"""Threat lifecycle manager for the Agentrology Security Arena.

Orchestrates all six ThreatTask instances. All threat-specific logic
(scripts, spawn, teardown, grading) now lives in tasks.py. This module
owns only the cross-cutting episode lifecycle and the GraderResult type.

Example:
    >>> manager = ThreatManager()
    >>> manager.setup_scripts()
    >>> manager.spawn()
    >>> result = manager.grade()
    >>> result.active_count
    6
    >>> manager.teardown()
    >>> manager.grade().all_clear
    True
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List

from server.tasks import ALL_TASKS, ThreatTask

THREAT_COUNT = len(ALL_TASKS)


@dataclass
class GraderResult:
    """Per-threat float scores from one grader pass.

    Attributes:
        scores: Ordered list of floats in [0.0, 1.0], one per threat.
            Index 0 → T01, index 5 → T06.
    """

    scores: List[float] = field(default_factory=lambda: [0.0] * THREAT_COUNT)

    @property
    def neutralised(self) -> List[bool]:
        """True for each threat whose score has reached 1.0."""
        return [s >= 1.0 for s in self.scores]

    @property
    def active_count(self) -> int:
        """Number of threats not yet fully neutralised."""
        return sum(1 for s in self.scores if s < 1.0)

    @property
    def all_clear(self) -> bool:
        """True when every threat score has reached 1.0."""
        return self.active_count == 0

    @property
    def total_score(self) -> float:
        """Normalised episode score in [0.0, 1.0] (average of all threats)."""
        return round(sum(self.scores) / THREAT_COUNT, 4)

    def summary(self) -> str:
        """Return a human-readable per-threat breakdown."""
        lines = []
        for task, score in zip(ALL_TASKS, self.scores, strict=False):
            status = "✓" if score >= 1.0 else "✗"
            lines.append(
                f"  {status} {task.threat_id} [{task.severity:<8}] {score:.2f}  {task.label}"
            )
        lines.append(
            f"\n  Total: {self.total_score:.4f}  |  Active: {self.active_count}/{THREAT_COUNT}"
        )
        return "\n".join(lines)


class ThreatManager:
    """Orchestrates the full lifecycle of all six simulated security threats.
    All threat-specific behaviour is delegated to the ThreatTask objects

    Args:
        tasks: Override the default ALL_TASKS list (useful for testing
               a subset of threats).
    """

    def __init__(self) -> None:
        self._tasks: list[ThreatTask] = ALL_TASKS.copy()

    def active_count(self) -> int:
        """Return the number of currently active threats."""
        return len(self._tasks)

    def reset_tasks(self, task_ids: list[str], all_if_empty: bool = False) -> None:
        """Reset the active task list (tearing down any existing tasks first)."""
        self.teardown()
        if all_if_empty and not task_ids:
            self._tasks = [task for task in ALL_TASKS]
        else:
            self._tasks = [task for task in ALL_TASKS if task.threat_id in task_ids]
        self.setup_scripts()
        self.spawn()

    def setup_scripts(self) -> None:
        """Write all payload scripts to disk (idempotent)."""
        for task in self._tasks:
            task.setup_scripts()

    def spawn(self, settle_seconds: float = 1.5) -> None:
        """Spawn all threat processes.

        Args:
            settle_seconds: Time to wait after spawning so processes can
                bind ports and write initial artefact files before grading.
        """
        for task in self._tasks:
            task.spawn()
        time.sleep(settle_seconds)

    def teardown(self) -> None:
        """Kill all processes and remove all artefacts (idempotent)."""
        for task in self._tasks:
            task.teardown()

    def grade(self) -> GraderResult:
        """Score all threats against current OS state.

        Returns:
            GraderResult with one float score per threat.
        """
        return GraderResult(scores=[task.grade() for task in self._tasks])

    def threat_meta(self, active_only: bool = False) -> list[dict]:
        """Return display metadata for all managed tasks."""
        return [
            {
                "threat_id": t.threat_id,
                "label": t.label,
                "severity": t.severity,
                "conditions": t.conditions,
            }
            for t in (ALL_TASKS if active_only else self._tasks)
        ]

    def list_all_available_tasks(self) -> list[dict]:
        """Return a list of all available tasks."""
        return self.threat_meta(active_only=False)
