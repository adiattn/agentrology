# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Agentrology Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from models import AgentrologyAction, AgentrologyObservation


class AgentrologyEnv(
    EnvClient[AgentrologyAction, AgentrologyObservation, State]
):
    """
    Client for the Agentrology Environment.

    This client maintains a persistent WebSocket connection to the environment server,
    enabling efficient multi-step interactions with lower latency.
    Each client instance has its own dedicated environment session on the server.

    Example:
        >>> # Connect to a running server
        >>> with AgentrologyEnv(base_url="http://localhost:8000") as client:
        ...     result = client.reset()
        ...     print(result.observation.echoed_message)
        ...
        ...     result = client.step(AgentrologyAction(message="Hello!"))
        ...     print(result.observation.echoed_message)

    Example with Docker:
        >>> # Automatically start container and connect
        >>> client = AgentrologyEnv.from_docker_image("agentrology-env:latest")
        >>> try:
        ...     result = client.reset()
        ...     result = client.step(AgentrologyAction(message="Test"))
        ... finally:
        ...     client.close()
    """

    def _step_payload(self, action: AgentrologyAction) -> Dict:
        """
        Convert AgentrologyAction to JSON payload for step message.

        Args:
            action: AgentrologyAction instance

        Returns:
            Dictionary representation suitable for JSON encoding
        """
        return {
            "message": action.message,
        }

    def _parse_result(self, payload: Dict) -> StepResult[AgentrologyObservation]:
        """
        Parse server response into StepResult[AgentrologyObservation].

        Args:
            payload: JSON response data from server

        Returns:
            StepResult with AgentrologyObservation
        """
        obs_data = payload.get("observation", {})
        observation = AgentrologyObservation(
            echoed_message=obs_data.get("echoed_message", ""),
            message_length=obs_data.get("message_length", 0),
            done=payload.get("done", False),
            reward=payload.get("reward"),
            metadata=obs_data.get("metadata", {}),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """
        Parse server response into State object.

        Args:
            payload: JSON response from state request

        Returns:
            State object with episode_id and step_count
        """
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
