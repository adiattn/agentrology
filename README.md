---
title: Agentrology Environment Server
emoji: 🛡️
colorFrom: gray
colorTo: red
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
  - security
  - linux
---

# Agentrology Environment: The Linux Security Arena

Agentrology is a container-native OpenEnv testbed that trains AI agents to act as automated Security Operations Center (SOC) analysts. The agent is dropped into a live Linux container with simulated active security threats (e.g., rogue processes, unauthorized listeners, persistent backdoors) and must use standard Linux shell commands to diagnose and neutralize them.

## Quick Start

The simplest way to interact with the Agentrology environment is through the `AgentrologyEnv` class:

```python
from agentrology import AgentrologyAction, AgentrologyEnv

try:
    # Create environment from Docker image
    env = AgentrologyEnv.from_docker_image("agentrology-env:latest")

    # Reset spawns the background threats (e.g., a rogue miner script)
    result = env.reset()
    print(f"Reset: {result.observation.stdout}")

    # Example Agent Trajectory: Diagnose and Remediate
    commands = [
        "ps aux | grep malicious", # Agent looks for the rogue process
        "kill -9 105",             # Agent attempts to kill the discovered PID
    ]

    for cmd in commands:
        result = env.step(AgentrologyAction(command=cmd))
        print(f"Command run: '{cmd}'")
        print(f"  → STDOUT: '{result.observation.stdout}'")
        print(f"  → Active Threats Remaining: {result.observation.active_threats}")
        print(f"  → Reward: {result.reward}")
        
        if result.observation.done:
            print("Threat neutralized. Episode complete.")
            break

finally:
    # Always clean up the container and background processes
    env.close()
```

That's it! The `AgentrologyEnv.from_docker_image()` method handles:
- Starting the Docker container with the required Linux utilities
- Waiting for the server to be ready
- Connecting to the environment
- Container cleanup when you call `close()`

## Building the Docker Image

Before using the environment, you need to build the Docker image (which includes the lightweight Linux utilities required for the simulation):

```bash
# From project root
docker build -t agentrology-env:latest -f server/Dockerfile .
```

## Deploying to Hugging Face Spaces

You can easily deploy your OpenEnv environment to Hugging Face Spaces using the `openenv push` command.

```bash
# From the environment directory (where openenv.yaml is located)
openenv push

# Or specify options
openenv push --namespace my-org --private
```

### Prerequisites
- Authenticate with Hugging Face: The command will prompt for login if not already authenticated

After deployment, your space will be available at:
`https://huggingface.co/spaces/<repo-id>`

The deployed space includes:
- **Web Interface** at `/web` - Interactive UI for exploring the environment manually.
- **API Documentation** at `/docs` - Full OpenAPI/Swagger interface.
- **Health Check** at `/health` - Container health monitoring.
- **WebSocket** at `/ws` - Persistent session endpoint for low-latency terminal interactions.

## Environment Details

### Action
**AgentrologyAction**: Contains the shell command the agent wishes to execute.
- `command` (str) - The shell command to run (e.g., `'netstat -tulpn'`, `'kill -9 402'`, `'crontab -r'`).

### Observation
**AgentrologyObservation**: Contains the terminal output and the deterministic evaluation of the system state.
- `stdout` (str) - Standard output from the command.
- `stderr` (str) - Error output, if any.
- `active_threats` (int) - The number of policy-violating processes still running.
- `reward` (float) - The reward for the current step.
- `done` (bool) - True if all threats are neutralized (`active_threats == 0`).

### Reward Logic
Grading is 100% deterministic, evaluated by checking the Linux process table and system configurations:
- **+1.0**: The specific threat is completely neutralized (e.g., process killed, backdoor removed).
- **+0.1**: Partial progress (e.g., executing a useful diagnostic command like `ps` or `lsof` without crashing the system).
- **-0.5**: Destructive negligence (e.g., attempting to kill system-critical processes or returning an invalid command syntax).
- **0.0**: Ineffective action (the threat persists).


## Development & Testing

### Direct Environment Testing

Test the environment logic directly without starting the HTTP server:

```bash
# From the server directory
python3 server/agentrology_environment.py
```

This verifies that:
- Background processes spawn correctly on reset.
- The `subprocess` engine executes commands safely.
- The deterministic graders correctly identify active vs. dead processes.

### Running Locally

Run the server locally for development:

```bash
uvicorn server.app:app --reload
```
