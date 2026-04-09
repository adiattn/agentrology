"""Threat task definitions for the Agentrology Security Arena.

Each threat is represented as a ThreatTask subclass that owns its own:
  - metadata (id, label, severity, conditions)
  - payload script content
  - spawn logic
  - teardown logic
  - grading logic

The ThreatManager in threat_manager.py orchestrates all tasks.
"""

from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

_DEVNULL = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}


@dataclass
class ThreatTask(ABC):
    """Abstract base for a single simulated security threat.

    Subclasses must declare class-level metadata attributes and implement
    setup_scripts(), spawn(), teardown(), and grade().

    Class attributes (must be defined by every subclass):
        threat_id:  Short identifier, e.g. "T01".
        label:      Human-readable threat name.
        severity:   One of LOW / MEDIUM / HIGH / CRITICAL.
        conditions: List of condition descriptions used for display.
    """

    threat_id: ClassVar[str]
    label: ClassVar[str]
    severity: ClassVar[str]
    conditions: ClassVar[list[str]]

    def _pgrep(self, pattern: str) -> bool:
        """Return True if at least one process matches *pattern*.

        Args:
            pattern: Pattern string passed to ``pgrep -f``.
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
        """Return True if a regular file exists at *path*."""
        return os.path.isfile(path)

    def _write_script(self, path: str, content: str) -> None:
        """Write *content* to *path*, creating parent directories as needed."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

    def _pkill(self, pattern: str) -> None:
        """Kill all processes matching *pattern*, ignoring no-match errors."""
        subprocess.run(["pkill", "-f", pattern], **_DEVNULL)

    def _remove(self, path: str) -> None:
        """Delete *path*, silently ignoring FileNotFoundError."""
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    @abstractmethod
    def setup_scripts(self) -> None:
        """Write payload scripts and create required directories."""

    @abstractmethod
    def spawn(self) -> None:
        """Start background processes (and install cron entries if needed)."""

    @abstractmethod
    def teardown(self) -> None:
        """Kill processes, remove artefacts, and undo any system changes."""

    @abstractmethod
    def grade(self) -> float:
        """Score remediation progress.

        Returns:
            Float in [0.0, 1.0]. 1.0 means the threat is fully neutralised.
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.threat_id} [{self.severity}]>"

    def build_metadata(self) -> dict:
        """Return metadata dictionary for this threat, used in server responses."""
        return {
            "threat_id": self.threat_id,
            "label": self.label,
            "severity": self.severity,
            "conditions": self.conditions,
        }
