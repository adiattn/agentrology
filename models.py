# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Pydantic models for the Agentrology OpenEnv environment.

Defines the action and observation contracts that the agent and the
environment server exchange on every step.
"""

from typing import Any, Dict, List

from openenv.core.env_server.types import Action, Observation
from pydantic import BaseModel, Field
from typing_extensions import override


class ThreatStatus(BaseModel):
    """Live status of one tracked threat.

    Attributes:
        threat_id: Short identifier such as 'T01'.
        label: Human-readable threat class name.
        severity: One of LOW, MEDIUM, HIGH, CRITICAL.
        neutralised: True when the threat has been fully remediated.
    """

    threat_id: str
    label: str
    severity: str
    neutralised: bool


class AgentrologyAction(Action):
    """A single shell command submitted by the agent.

    Attributes:
        command: The raw shell command string to execute.
            Must not exceed 512 characters. Dangerous commands
            (SSH, sudo, curl, etc.) are rejected before execution.
    """

    command: str = Field(
        ...,
        description=(
            "Shell command to execute "
            "(e.g. 'ps aux', 'kill -9 <PID>', 'crontab -r', 'rm -f /tmp/file')."
        ),
        max_length=512,
    )


class AgentrologyObservation(Observation):
    """Full environment observation returned after each step or reset.

    Attributes:
        stdout: Standard output captured from the executed command.
            Truncated to 2 000 characters.
        stderr: Standard error output. Truncated to 1 000 characters.
        active_threats: Count of threats that have not yet been neutralised.
            Reaches 0 when the episode is complete.
        reward: Floating-point reward for this step, in the range [-0.5, 6.0].
        done: True when active_threats reaches 0.
        threat_status: Per-threat neutralisation flags ordered T01 through T06.
        security_violation: Non-empty string when the submitted command was
            blocked by the security policy. The command is not executed.
        metadata: Arbitrary key-value diagnostics (step number, command run, etc.).
    """

    stdout: str = Field(..., description="Standard output from the executed command.")
    stderr: str = Field(..., description="Standard error output, if any.")
    active_threats: int = Field(
        ..., description="Number of threats still active on the host."
    )
    threat_status: List[ThreatStatus] = Field(
        default_factory=list,
        description="Per-threat neutralisation flags.",
    )
    security_violation: str = Field(
        default="",
        description="Populated when a command is blocked by the security policy.",
    )
