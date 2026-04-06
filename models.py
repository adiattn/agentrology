# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Data models for the Agentrology Environment.

The agentrology environment is a simple test environment that echoes back messages.
"""

from openenv.core.env_server.types import Action, Observation
from pydantic import Field


class AgentrologyAction(Action):
    """Action for the Agentrology environment - just a message to echo."""

    command: str = Field(
        ...,
        description="The shell command to execute (e.g., 'ps aux', 'kill -9 <PID>', 'crontab -r')",
    )


class AgentrologyObservation(Observation):
    """Observation from the Agentrology environment - the echoed message."""

    stdout: str = Field(..., description="Standard output from the executed command")
    stderr: str = Field(..., description="Error output, if any")
    active_threats: int = Field(
        ..., description="Number of policy-violating threats remaining"
    )
