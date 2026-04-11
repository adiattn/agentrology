#!/usr/bin/env python
"""
Inference Script
"""

import argparse
import asyncio
import json
import os
import random
import re
import string
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from prompts import (
    SYSTEM_PROMPT,
    SYSTEM_PROMPT_JSON,
    SYSTEM_PROMPT_NO_REASONING,
    SYSTEM_PROMPT_NO_REASONING_JSON,
    extract_command_json,
)
from utils import init_logging, send_direct_log


def cli_parse_args():
    parser = argparse.ArgumentParser(
        prog="Agentrology Inference Script",
        description="Run this script to execute the agent in inference mode. Make sure to set necessary environment variables or pass them as command-line arguments.",
    )
    parser.add_argument("--dev", action="store_true", help="Enable dev mode")
    parser.add_argument("--ollama", action="store_true", help="Use Ollama (local)")
    parser.add_argument("--hf", action="store_true", help="Use HuggingFace (default)")
    parser.add_argument("--model", type=str, help="Model name")
    parser.add_argument("--task", type=str, help="Task name")
    parser.add_argument("--benchmark", type=str, help="Benchmark name")
    parser.add_argument("--api-url", type=str, help="Override API base URL")
    parser.add_argument("--max-steps", help="Max steps to run the agent", type=int)
    parser.add_argument("--temperature", help="Temperature for the LLM", type=float)
    parser.add_argument("--max-tokens", help="Max tokens for the LLM", type=int)
    parser.add_argument("--task-ids", nargs="+", help="Task IDs to run")
    parser.add_argument(
        "--reasoning-effort",
        "--re",
        type=str,
        help="Reasoning effort for the LLM (none/low/medium/high) (default is low)",
    )
    parser.add_argument(
        "--reasoning",
        help="Enable reasoning mode",
        action="store_true",
    )
    parser.add_argument(
        "--interactive",
        help="Enable interactive mode",
        action="store_true",
        default=False,
    )
    parser.add_argument("--image", help="Docker image name")
    parser.add_argument("--log-file", help="Log file")
    parser.add_argument(
        "--benchmark-dir",
        help="Benchmark directory",
    )
    parser.add_argument(
        "--port",
        help="Port for the environment, default: docker managed",
        type=int,
        default=0,
    )

    return parser.parse_args()


args = cli_parse_args()

import dotenv

dotenv.load_dotenv()

IS_DEV = args.dev or (os.getenv("IS_DEV", "false").lower() == "true")

default_api_base_url = "https://router.huggingface.co/v1"
if args.ollama:
    default_api_base_url = "http://127.0.0.1:11434/v1"

API_KEY = (
    os.getenv("HF_TOKEN")
    or os.getenv("API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or "[NONE]"
)
API_BASE_URL = args.api_url or os.getenv("API_BASE_URL") or default_api_base_url
MODEL_NAME = args.model or os.getenv("MODEL_NAME") or "openai/gpt-oss-20b"
BENCHMARK = args.benchmark or os.getenv("BENCHMARK", "agentrology-benchmark")
MAX_STEPS = args.max_steps or int(os.getenv("MAX_STEPS", "45"))
REASONING_MODE = (
    True if args.reasoning else (os.getenv("REASONING_MODE", "false").lower() == "true")
)
TASK_IDS = args.task_ids or os.getenv("TASK_IDS", "T01,T02,T03,T04,T05,T06").split(",")
IS_SUBMISSION_ENV = os.getenv("SHELL", "") != "/usr/bin/zsh"

IMAGE_NAME = (
    args.image
    or os.getenv("LOCAL_IMAGE_NAME")
    or (
        "adityacd3/agentrology-env:latest"
        if IS_SUBMISSION_ENV
        else "agentrology-env:latest"
    )
)
LOG_FILE = os.getenv(
    "LOG_FILE",
    f"logs/{BENCHMARK}_{MODEL_NAME.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
)
TEMPERATURE = args.temperature or float(os.getenv("TEMPERATURE", "0.08"))
REASONING_EFFORT = "low"
if args.reasoning_effort and args.reasoning_effort in ["none", "low", "medium", "high"]:
    REASONING_EFFORT = args.reasoning_effort
MAX_TOKENS = args.max_tokens or int(os.getenv("MAX_TOKENS", "500"))
INTERACTIVE_MODE = (
    args.interactive or os.getenv("INTERACTIVE_MODE", "false").lower() == "true"
)
WS_CONNECTION_TIMEOUT = int(os.getenv("WS_CONNECTION_TIMEOUT", "60"))
BENCHMARK_DIR = os.getenv("BENCHMARK_DIR", "benchmarks")
EXPOSE_PORT = int(os.getenv("EXPOSE_PORT", "0"))
if args.port:
    EXPOSE_PORT = args.port

if IS_DEV:
    IS_SUBMISSION_ENV = False

if IS_SUBMISSION_ENV:
    REASONING_MODE = True  # reasoning improves perf
    REASONING_EFFORT = None  # requires checking model and provider impl

from colorama import Fore, Style, init

init(autoreset=True)

init_logging(LOG_FILE, IS_SUBMISSION_ENV)


def color_print(msg, color, file=sys.stdout, flush=True):

    if file.isatty():
        print(f"{color}{msg}{Style.RESET_ALL}", file=file, flush=flush)
    else:
        print(msg, file=file, flush=flush)


def print_config(task_ids: list[str]) -> None:
    config_vars = {
        "IMAGE_NAME": IMAGE_NAME,
        "API_BASE_URL": API_BASE_URL,
        "MODEL_NAME": MODEL_NAME,
        "BENCHMARK": BENCHMARK,
        "TASKS": ", ".join(task_ids),
        "MAX_STEPS": MAX_STEPS,
        "LLM_MODE": "ollama" if args.ollama else "external",
        "REASONING_MODE": REASONING_MODE,
        "TEMPERATURE": TEMPERATURE,
        "MAX_TOKENS": MAX_TOKENS,
        "IS_DEV": IS_DEV,
        "LOG_FILE": LOG_FILE,
        "INTERACTIVE_MODE": INTERACTIVE_MODE,
        "WS_CONNECTION_TIMEOUT": WS_CONNECTION_TIMEOUT,
        "BENCHMARK_DIR": BENCHMARK_DIR,
        "EXPOSE_PORT": EXPOSE_PORT,
        "OS": os.name,
    }
    if not IS_DEV:
        send_direct_log(
            json.dumps({"event": "inference_config", "config": config_vars}, indent=2),
            is_submission_env=IS_SUBMISSION_ENV,
        )
        return

    color_print(
        "============================================================", Fore.CYAN
    )
    color_print(
        "              AGENTROLOGY INFERENCE OPTIONS                 ", Fore.CYAN
    )
    color_print(
        "============================================================", Fore.CYAN
    )

    for k, v in config_vars.items():
        color_print(f"[ INFO ] {k:<25} = {v}", Fore.BLUE)
    color_print(
        "============================================================", Fore.CYAN
    )


def debug_print(msg: str, allow_in_submission=True) -> None:
    if IS_DEV:
        color_print(f"[DEBUG] {msg}", Fore.YELLOW)
    elif allow_in_submission:
        send_direct_log(f"[DEBUG] {msg}", IS_SUBMISSION_ENV)


def log_error(msg: str) -> None:
    color_print(f"[ERROR] {msg}", Fore.RED, file=sys.stderr)


def log_info(msg: str) -> None:
    color_print(f"[INFO] {msg}", Fore.BLUE)


def log_start(task: str, env: str, model: str, provider_url: str) -> None:
    msg = f"[START] task={task} env={env} model={model} provider_url={provider_url}"
    color_print(msg, Fore.GREEN)


def log_step(
    step: int,
    action: str,
    reward: float,
    active_threats: int,
    done: bool,
    error: Optional[str],
) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    # Replace newlines/quotes in action string to keep log on a single line
    safe_action = action.replace("\n", " ").replace('"', "'")
    msg = f'[STEP] step={step} action="{safe_action}" reward={reward:.2f} active_threats={active_threats} done={done_val} error={error_val}'
    color_print(msg, Fore.CYAN)


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    score_str = str(clamp_score(score))
    msg = f"[END] success={str(success).lower()} steps={steps} score={score_str} rewards={rewards_str}"
    color_print(msg, Fore.MAGENTA)


USER_PROMPT_TEMPLATE = """\
[STEP]: {step}
## OBSERVATION (OF LAST COMMAND)
{security_violation_block}
[STDOUT]: {stdout}
[STDERR]: {stderr}
[ACTIVE THREATS]: {active_threats}

## FEEDBACK
[LAST REWARD]: {last_reward:.2f}

[RECENT HISTORY]:
{history_block}

{footer}
"""

# USER_PROMPT_FOOTER_TEMPLATE_NO_REASONING = """Formulate your [COMMAND]."""
# USER_PROMPT_FOOTER_TEMPLATE_REASONING = """Formulate your [THOUGHT] and [COMMAND]."""
USER_PROMPT_FOOTER_TEMPLATE_NO_REASONING = (
    """Formulate your response as a JSON object with the following keys: "command"."""
)
USER_PROMPT_FOOTER_TEMPLATE_REASONING = """Formulate your response as a JSON object with the following keys: "thought" and "command"."""

SECURITY_VIOLATION_BLOCK_TEMPLATE = """\
[SYSTEM SECURITY VIOLATION!!]: {security_violation_message}"""

HISTORY_PREFIX_TEMPLATE = "[S{step}] CMD={command} R={reward:+.2f} T={active_threats} {violation_part} {execution_result_part}"
HISTORY_PREFIX_TEMPLATE_SAME_STEP = (
    "[S{step}] CMD={command} R={reward:+.2f} T={active_threats}"
)


HISTORY_ITEMS_COUNT = 4


def build_user_prompt(
    step: int,
    stdout: str,
    stderr: str,
    security_violation_message: Optional[str],
    active_threats: int,
    last_reward: float,
    history: List[Dict],
) -> str:

    history_block = ""
    for item in history[-HISTORY_ITEMS_COUNT:]:
        execution_result_part = ""
        if item.get("step", 0) != step - 1:
            execution_result_part += (
                f'stdout={item["stdout"]} ' if item.get("stdout") else ""
            )
            execution_result_part += (
                f'stderr={item["stderr"]}' if item.get("stderr") else ""
            )
        history_block += (
            HISTORY_PREFIX_TEMPLATE.format(
                step=item.get("step", 0),
                command=item.get("command", ""),
                reward=item.get("reward", 0.0),
                active_threats=item.get("threats_count", 0),
                violation_part=(
                    "COMMAND_BLOCKED=True" if item.get("blocked", False) else ""
                ),
                execution_result_part=execution_result_part.strip(),
            ).strip()
            + "\n"
        )

    template = USER_PROMPT_TEMPLATE
    footer = (
        USER_PROMPT_FOOTER_TEMPLATE_REASONING
        if REASONING_MODE
        else USER_PROMPT_FOOTER_TEMPLATE_NO_REASONING
    )

    security_violation_block = ""
    if security_violation_message:
        security_violation_block = SECURITY_VIOLATION_BLOCK_TEMPLATE.format(
            security_violation_message=security_violation_message
        )

    return (
        textwrap.dedent(template)
        .format(
            step=step,
            stdout=stdout,
            stderr=stderr,
            active_threats=active_threats,
            last_reward=last_reward,
            security_violation_block=security_violation_block,
            history_block=history_block,
            footer=footer,
        )
        .strip()
    )


def parse_command(response_text: str) -> Optional[str]:
    return extract_command_json(response_text)


import httpx
from openai import AsyncOpenAI
from openenv.core.env_client import LocalDockerProvider

from client import AgentrologyEnv
from models import AgentrologyAction

BRIDGE_API = "http://127.0.0.1:8080"


async def chat_with_ui(user_prompt: str) -> str:
    async with httpx.AsyncClient() as client:
        # send prompt
        await client.post(f"{BRIDGE_API}/send", json={"text": user_prompt})
        debug_print("[++BRIDGE++] Prompt sent to UI, waiting for response...")

        # wait for response
        while True:
            res = await client.get(f"{BRIDGE_API}/latest")
            data = res.json()

            if data["response"]:
                debug_print("[++BRIDGE++] Response received from UI.")
                return data["response"].strip()

            await asyncio.sleep(1)


async def reset_bridge():
    if not INTERACTIVE_MODE:
        return
    try:
        response = httpx.post(f"{BRIDGE_API}/send", json={"text": "[RESET]"})
        if response.status_code == 200:
            debug_print("[++BRIDGE++] Bridge reset request sent.")
            # small delay to ensure bridge resets before next interaction
            await asyncio.sleep(2)
        else:
            log_error(f"Failed to reset bridge, status code: {response.status_code}")
    except Exception as e:
        log_error(f"Error resetting bridge: {e}")


async def get_model_action(
    client: AsyncOpenAI,
    step: int,
    stdout: str,
    stderr: str,
    active_threats: int,
    last_security_violation: Optional[str],
    last_reward: float,
    history: List[Dict],
) -> Tuple[str, Optional[str], Optional[str]]:
    user_prompt = build_user_prompt(
        step=step,
        stdout=stdout,
        stderr=stderr,
        security_violation_message=last_security_violation,
        active_threats=active_threats,
        last_reward=last_reward,
        history=history,
    )

    ## TODO: comment when not debugging
    # debug_print(f"[PROMPT] {user_prompt}")

    try:
        if INTERACTIVE_MODE:
            # text = "[THOUGHT] [REASONING DISABLED]\n[COMMAND] pwd"
            if step == 1:
                user_prompt = SYSTEM_PROMPT + "\n\n" + user_prompt
            text = await chat_with_ui(user_prompt)
            # add random delay to simulate thinking time and make it more natural in the UI
            debug_print(
                f"Model response received: {text}, adding random delay to simulate thinking..."
            )
            await asyncio.sleep(random.uniform(0.5, 2.0))
        else:
            kwargs = {}
            if REASONING_EFFORT:
                kwargs["reasoning_effort"] = REASONING_EFFORT
            completion = await client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            SYSTEM_PROMPT_JSON
                            if REASONING_MODE
                            else SYSTEM_PROMPT_NO_REASONING_JSON
                        ),
                    },
                    {"role": "user", "content": user_prompt},
                ],
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
                stream=False,
                **kwargs,
            )
            debug_print(
                f"Model response received: {completion.choices[0].message.content}",
                False,
            )
            text = (completion.choices[0].message.content or "").strip()

        command = parse_command(text)
        return (text, command, None)
    except Exception as exc:
        log_error(f"Model request failed: {exc}, type={type(exc).__name__}")
        # TOOD: detect Error code: 402 - {'error': 'You have depleted your monthly included credits. Purchase pre-paid credits to continue using Inference Providers. Alternatively, subscribe to PRO to get 20x more included usage.'}
        return "Model Failed", "", str(exc)


def clamp_score(score: float) -> float:
    return round(max(0.001, min(0.9999, score)), 5)


class DockerProviderWithRandomPort(LocalDockerProvider):
    def __init__(self):
        super().__init__()
        self._url = None

    def start_container(
        self,
        image: str,
        port: Optional[int] = None,
        env_vars: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> str:
        url = super().start_container(image, port, env_vars, **kwargs)
        self._url = url
        if isinstance(port, int) and port > 0:
            return url

        container_id: str | None = self._container_id
        if not container_id:
            raise RuntimeError("Container ID not found after starting container")

        result = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True,
            text=True,
            check=True,
        )

        data = json.loads(result.stdout)
        ports = data[0]["NetworkSettings"]["Ports"]["8000/tcp"]
        port = int(ports[0]["HostPort"])

        self._url = f"http://localhost:{port}"
        return self._url


async def fetch_tasks(task_ids: Optional[List[str]], base_url: str) -> List[dict]:
    from urllib import request

    try:
        with request.urlopen(f"{base_url}/tasks") as response:
            if response.status != 200:
                raise RuntimeError(
                    f"Failed to fetch tasks, status code: {response.status}"
                )
            data = response.read()
            tasks: List[dict] = json.loads(data)
            if task_ids:
                tasks = [t for t in tasks if t["threat_id"] in task_ids]
            return sorted(tasks, key=lambda x: x["threat_id"])
    except Exception as e:
        log_error(f"Failed to fetch tasks from environment: {e}")
        sys.exit(1)


async def initialize_environment() -> Tuple[AgentrologyEnv, str]:
    debug_print(f"Connecting to environment with image: {IMAGE_NAME}")
    provider = None
    kwargs = {"port": EXPOSE_PORT}
    provider = DockerProviderWithRandomPort()

    try:
        env = await AgentrologyEnv.from_docker_image(
            IMAGE_NAME,
            provider=provider,
            **kwargs,
            env_vars={"ENABLE_WEB_INTERFACE": "true" if IS_DEV else "false"},
        )
    except Exception as e:
        log_error(f"Failed to create environment from image '{IMAGE_NAME}': {e}")
        sys.exit(1)

    docker_container_name = (
        provider._container_name
        if provider and provider._container_name
        else "[unknown]"
    )
    debug_print(
        "Environment connected successfully on container: " + docker_container_name
    )
    debug_print(
        f"Environment container exposed. Open your browser to {provider._url}/dashboard to view the web interface"
    )

    if not provider._url:
        log_error("Failed to determine environment URL from Docker provider.")
        sys.exit(1)

    return env, provider._url


async def run_task(
    env: AgentrologyEnv, client: AsyncOpenAI, task_id: str
) -> Tuple[float, dict]:
    if not task_id:
        log_error("Task ID is required to run the inference script.")
        sys.exit(1)

    TASK_NAME = task_id

    start_time = None
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    final_score: float = 0.0
    success = False
    steps_history = []
    neutralization_checkpoints = []
    stop_reason = "Max steps reached without neutralizing all threats"
    total_threats = 0

    def add_command(
        step: int,
        raw_response: str,
        command: Optional[str],
        thought: Optional[str],
        error: Optional[str],
        reward: float = 0.0,
        done: bool = False,
        blocked: bool = False,
        security_violation: Optional[str] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        threats_count: Optional[int] = None,
    ) -> None:
        steps_history.append(
            {
                "step": step,
                "raw_response": raw_response,
                "command": command,
                "thought": thought,
                "blocked": blocked,
                "reward": reward,
                "done": done,
                "error": error,
                "stdout": stdout,
                "stderr": stderr,
                "security_violation": security_violation,
                "threats_count": threats_count,
            }
        )

    log_start(
        task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME, provider_url=API_BASE_URL
    )

    try:
        result = await env.reset(task_id=TASK_NAME)
        obs = result.observation

        total_threats = obs.active_threats
        last_stdout = obs.stdout
        last_stderr = obs.stderr
        last_threats = obs.active_threats
        last_threat_ids = [t.threat_id for t in obs.threat_status if not t.neutralised]
        last_security_violation = None
        last_reward = 0.0
        start_time = datetime.now()
        consistent_errors = 0
        consisten_empty_llm_response_count = 0
        step = 0

        while step != MAX_STEPS:
            if result.done:
                stop_reason = "Episode completed (done=True)"
                break

            await env.connect()

            # send ping
            # await env._send({"type": "ping"})

            # Get raw text (for history) and parsed command (for execution)
            raw_response, command, llm_inference_error = await get_model_action(
                client=client,
                step=step + 1,
                stdout=last_stdout,
                stderr=last_stderr,
                active_threats=last_threats,
                last_security_violation=last_security_violation,
                last_reward=last_reward,
                history=steps_history,
            )

            if llm_inference_error:
                # must not count towards step
                consistent_errors += 1
                debug_print(
                    "LLM inference error, skipping step without incrementing step count."
                )
                if consistent_errors >= 3:
                    stop_reason = (
                        "Terminating due to consistent error in LLM API calls."
                        + f" Occurred {consistent_errors} times. Last error: {llm_inference_error}"
                    )
                    log_error(stop_reason)
                    break
                continue

            step += 1
            consistent_errors = 0  # reset error count on successful inference
            debug_print(f"[{step}] {raw_response}", False)

            if not command or command.strip() == "":
                consisten_empty_llm_response_count += 1
                debug_print("No.Invalid command generated by model, skipping step.")
                command = "[INVALID RESPONSE, Command must be after [COMMAND] block]"
                add_command(
                    step=step,
                    raw_response=raw_response,
                    command=command,
                    thought=None,
                    reward=0.0,
                    done=False,
                    error=llm_inference_error or "No command generated",
                    blocked=False,
                    stdout=None,
                    stderr=None,
                    security_violation=None,
                    threats_count=last_threats,
                )

                if consisten_empty_llm_response_count >= 5:
                    stop_reason = "Terminating due to consistent invalid responses from the model."
                    debug_print(stop_reason)
                    break

                continue

            consisten_empty_llm_response_count = 0  # reset empty response count

            if not AgentrologyAction.is_actionable_command(command):
                limit = AgentrologyAction.get_command_len_limit()
                debug_print(f"Command exceeds length limit {limit} chars")
                msg = f"[ AGENTROLOGY ERROR ] ERR_BUF_OVERFLOW | LIMIT: {limit} chars | REASON: Input exceeded secure execution buffer. Command discarded."
                add_command(
                    step=step,
                    raw_response=raw_response,
                    command=command,
                    thought=None,
                    reward=0.0,
                    done=False,
                    error=f"Command length exceeds limit of {limit} chars",
                    blocked=True,
                    stdout=None,
                    stderr=None,
                    security_violation=msg,
                    threats_count=last_threats,
                )
                command = command[: min(len(command), 20)] + "... [TRUNCATED]"
                last_security_violation = msg
                last_stderr = ""
                last_stdout = ""
                last_reward = -0.05
                rewards.append(-0.05)
                steps_taken = step

                continue

            blocked = False

            try:
                result = await env.step(AgentrologyAction(command=command))
                obs = result.observation

                if result.observation.security_violation:
                    debug_print("[COMMAND BLOCKED] Security violation", False)
                else:
                    debug_print(
                        f"[COMMAND OUTPUT] stdout: {obs.stdout} stderr: {obs.stderr}",
                        False,
                    )

                reward = result.reward or 0.0
                done = result.done
                blocked = bool(obs.security_violation)
                # If the security validator blocks it, we might catch it in observation metadata
                error = (
                    obs.security_violation
                    if hasattr(obs, "security_violation") and obs.security_violation
                    else None
                )

                add_command(
                    step=step,
                    raw_response=raw_response,
                    command=command,
                    thought=None,
                    error=error,
                    blocked=blocked,
                    reward=reward,
                    done=done,
                    stdout=obs.stdout,
                    stderr=obs.stderr,
                    security_violation=(
                        obs.security_violation
                        if hasattr(obs, "security_violation")
                        else None
                    ),
                    threats_count=(
                        obs.active_threats if hasattr(obs, "active_threats") else None
                    ),
                )
            except Exception as exc:
                log_error(f"Unexpected step error: {exc}")
                stop_reason = f"Step execution error: {exc}"
                break

            rewards.append(reward)
            steps_taken = step

            if obs.active_threats < last_threats:
                debug_print(
                    f"---------> Threat neutralized! Remaining: {obs.active_threats} <---------",
                    False,
                )
                neutralized_threat_ids = list(
                    set(last_threat_ids)
                    - set(t.threat_id for t in obs.threat_status if not t.neutralised)
                )
                for id in neutralized_threat_ids:
                    neutralization_checkpoints.append(
                        {
                            "step": step,
                            "threat_id": id,
                            "time": datetime.now().isoformat(),
                            "reward": reward,
                        }
                    )

            last_stdout = obs.stdout
            last_stderr = obs.stderr
            last_reward = reward
            last_threats = obs.active_threats
            last_security_violation = obs.security_violation
            last_threat_ids = [
                t.threat_id for t in obs.threat_status if not t.neutralised
            ]

            log_step(
                step=step,
                action=command,
                active_threats=obs.active_threats,
                reward=reward,
                done=done,
                error=error,
            )

            if done:
                stop_reason = "Episode completed (done=True)"
                break

        end_time = datetime.now()
        success = (
            len(neutralization_checkpoints) == total_threats
        ) and total_threats > 0

        # Score vs. Reward distinction
        # SCORE: success-based metric in (0, 1).
        neutralized = total_threats - last_threats
        if total_threats > 0 and success:
            # Efficiency bonus: solving faster = higher score
            efficiency = 1.0 - (steps_taken / MAX_STEPS)
            score = 0.70 + 0.30 * efficiency
        elif total_threats > 0:
            score = 0.70 * (neutralized / total_threats)
        else:
            score = 0.001
        score = clamp_score(score)
        final_score = score

        benchmark_info = {
            "benchmark": BENCHMARK,
            "task": TASK_NAME,
            "model": MODEL_NAME,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "max_steps": MAX_STEPS,
            "reasoning_on": REASONING_MODE,
            "reasoning_effort": REASONING_EFFORT,
            "summary": {
                "start_time": start_time.isoformat() if start_time else None,
                "end_time": end_time.isoformat() if end_time else None,
                "time_taken": (
                    (end_time - start_time).total_seconds()
                    if start_time and end_time
                    else None
                ),
                "total_threats": total_threats,
                "neutralized_threats": total_threats - last_threats,
                "stop_reason": stop_reason,
                "steps_taken": steps_taken,
                "final_score": final_score,
                "success": success,
            },
            "checkpoints": neutralization_checkpoints,
            "api_base_url": API_BASE_URL,
            "reasoning_mode": REASONING_MODE,
            "system_prompt": (
                SYSTEM_PROMPT if REASONING_MODE else SYSTEM_PROMPT_NO_REASONING
            ),
            "steps": steps_history,
        }

        if IS_SUBMISSION_ENV:
            not_important_keys = ["steps", "system_prompt", "checkpoints"]
            for k in not_important_keys:
                if k in benchmark_info:
                    del benchmark_info[k]
            send_direct_log(
                json.dumps(
                    {"event": "benchmark_result", "result": benchmark_info}, indent=2
                ),
                is_submission_env=IS_SUBMISSION_ENV,
            )
            time.sleep(1)

            pass

    finally:
        log_end(success=success, steps=steps_taken, score=final_score, rewards=rewards)

    print()
    print()
    return final_score, benchmark_info


async def main():
    task_ids = sorted(TASK_IDS)
    print_config(task_ids=task_ids)
    client = AsyncOpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    env, env_url = await initialize_environment()
    if not IS_SUBMISSION_ENV:
        tasks_info = await fetch_tasks(task_ids, base_url=env_url)
    else:
        tasks_info = [
            {
                "threat_id": tid,
            }
            for tid in task_ids
        ]
    scores = []

    try:
        for task_info in tasks_info:
            task_id = task_info["threat_id"]
            if not IS_SUBMISSION_ENV:
                debug_print(
                    f"[INFO] Running task: {task_id} [{task_info['difficulty']}] [{task_info['severity']}] - {task_info['label']}",
                    False,
                )
            final_task_score, benchmark_info = await run_task(
                env, client, task_id=task_id
            )
            scores.append(
                {
                    "task_id": task_id,
                    "score": final_task_score,
                    "benchmark_info": benchmark_info,
                }
            )
            await reset_bridge()
    finally:
        debug_print(
            json.dumps(
                {
                    "event": "final_scores",
                    "scores": [
                        {"task_id": s["task_id"], "score": s["score"]} for s in scores
                    ],
                },
                indent=2,
            ),
            False,
        )

        if not IS_SUBMISSION_ENV and scores:
            try:
                identifier = "".join(
                    random.choices(string.ascii_letters + string.digits, k=4)
                )
                benchmark_file_name = f"{BENCHMARK}_{MODEL_NAME}_{identifier}.json"
                benchmark_file_name = re.sub(r'[<>:"/\\|?*]', "_", benchmark_file_name)
                os.makedirs(BENCHMARK_DIR, exist_ok=True)
                benchmark_path = os.path.join(BENCHMARK_DIR, benchmark_file_name)

                with open(benchmark_path, "w") as f:
                    json.dump(
                        {
                            "benchmark": BENCHMARK,
                            "model": MODEL_NAME,
                            "timestamp": datetime.now().isoformat(),
                            "total_tasks_run": len(scores),
                            "run_details": [s["benchmark_info"] for s in scores],
                            "average_score": (
                                sum(s["score"] for s in scores) / len(scores)
                                if scores
                                else 0.0
                            ),
                        },
                        f,
                        indent=4,
                    )
                debug_print(f"Overall run benchmark saved to {benchmark_path}")
            except Exception as e:
                log_error(f"Failed to save overall benchmark: {e}")

        try:
            debug_print("Closing environment connection...")
            await env.close()

        except Exception as e:
            log_error(f"env.close() error (container cleanup): {e}")

    time.sleep(2)
    print("[INFO] Inference run completed.")


if __name__ == "__main__":
    asyncio.run(main())
