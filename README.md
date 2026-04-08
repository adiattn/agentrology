-----
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

<div align="center">
  <h1>Agentrology: The Linux Security Arena</h1>
  <p><b>An Autonomous SOC Analyst Training Environment for Frontier Models</b></p>
  <p>Agentrology is a container-native OpenEnv testbed designed to evaluate and train AI agents operating as autonomous Security Operations Center (SOC) analysts.</p>

  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux" />
  <img src="https://img.shields.io/badge/Security-Red_Team-red?style=for-the-badge&logo=tryhackme&logoColor=white" alt="Security" />
  <img src="https://img.shields.io/badge/Docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/OpenEnv-Compatible-success?style=for-the-badge" alt="OpenEnv" />

  <hr>
  <p>The environment drops the agent into a live, headless Linux container populated with active, simulated security threats—ranging from unauthorized listeners to complex privilege escalation kits. Agents must utilize standard Linux sysadmin utilities to perform forensic analysis, diagnose the system state, and neutralize threats sequentially, all while operating under a strict command execution sandbox.</p>

</div>
<hr>


## Architecture & Threat Model

The environment simulates a compromised host containing six deterministic indicators of compromise (IOCs). The episode concludes successfully only when all threats are neutralized.

| ID | Severity | Threat Description | Required Remediation |
| :--- | :--- | :--- | :--- |
| **T01** | LOW | Rogue crypto-miner process | Process termination |
| **T02** | LOW | Unauthorized HTTP listener | Port mapping & termination |
| **T03** | MEDIUM | Persistent cron backdoor | Crontab clearance & termination |
| **T04** | MEDIUM | Data exfiltration agent | Process termination & artifact deletion |
| **T05** | HIGH | Disguised syslog daemon | Boot script deletion & termination |
| **T06** | CRITICAL | Privilege escalation kit | Sudoers/shadow cleanup & termination |

-----

## Quick Start

The repository includes a suite of robust bash scripts located in the `scripts/` directory to handle building, running, and testing the environment.

### 1. Build and Run the Container

Use the provided script to build the Docker image and spin up the containerized environment. It safely checks for existing instances and manages port bindings.

```bash
chmod +x scripts/docker_build_and_run.sh
./scripts/docker_build_and_run.sh --web
```

  * **Options:**
      * `--skip-build`: Skips the Docker build phase.
      * `--web`: Mounts the interactive web UI via standard `ENABLE_WEB_INTERFACE`.

### 2. Inference

The `inference.sh` script manages the LLM execution pipeline. It supports both Hugging Face API inference and local Ollama execution, handling API endpoints, environment variables, and logging autonomously.

```bash
chmod +x scripts/inference.sh
./scripts/inference.sh --hf --model Qwen/Qwen2.5-72B-Instruct # requires API_KEY to be set in .env
```

**Inference Script Parameters:**

  * `--hf` / `--ollama`: Toggle between remote Hugging Face endpoints and local Ollama (`http://127.0.0.1:11434`).
  * `--model <name>`: Specify the LLM identifier.
  * `--max-steps <num>`: Configure the maximum allowed steps per episode (Default: 40).
  * `--dev`: Enables verbose debugging mode.

Logs are automatically generated and timestamped in the `/logs` directory.

## Environment Details

The environment communicates using the standard OpenEnv Pydantic models via WebSocket for low-latency terminal interaction.

### Action

**`AgentrologyAction`**: Contains the exact shell command the agent intends to execute.

  * `command` *(str)*: A valid Linux shell command (e.g., `'netstat -tulpn'`, `'kill -9 402'`, `'crontab -r'`).

### Observation

**`AgentrologyObservation`**: Returns the terminal output and the deterministic evaluation of the system state.

  * `stdout` *(str)*: Standard output stream.
  * `stderr` *(str)*: Error output stream.
  * `active_threats` *(int)*: Count of active policy violations remaining.
  * `threat_status` *(list[ThreatStatus])*: Array of threat metadata and neutralization flags.
  * `security_violation` *(str)*: Populated if the agent attempts a forbidden command.
  * `reward` *(float)*: Computed scalar reward for the current step.
  * `done` *(bool)*: Boolean flag; `True` if `active_threats == 0`.

### Reward & Scoring Logic

Grading is 100% deterministic. The evaluator parses the live Linux process table and filesystem state—not string matching.

  * **`+1.0`**: A specific threat is completely neutralized (e.g., process killed and persistence artifact removed).
  * **`+0.1`**: Partial progress (e.g., executing a valid diagnostic command like `ps` or `lsof`).
  * **`-0.1`**: Command execution failure (non-zero exit code).
  * **`-0.5`**: Destructive negligence or security sandbox violation.

## Testing and Deployment

To protect the host infrastructure the environment utilizes a strict `CommandValidator` middleware that intercepts commands before subprocess execution.

#### Running the Tests

The repository contains a test script to ensure the command validator correctly blocks command injection attempts:

```bash
uv run python -m tests.test_command_validator
```

### Deployment to Hugging Face Spaces

Agentrology is optimized for low-resource execution and runs natively on Hugging Face Free Tier CPU spaces.

```bash
openenv push
```

The deployed space provides:

1.  **Interactive Web UI** (`/web`): Manual exploration of the environment.
2.  **OpenAPI Docs** (`/docs`): Schema verification.
3.  **Persistent WebSocket** (`/ws`): Primary interface for agent inference.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](./LICENSE) file for details. Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.
