"""
Inference Script Example
===================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.
    LOCAL_IMAGE_NAME The name of the local image to use for the environment if you are using from_docker_image()
                     method

- Defaults are set only for API_BASE_URL and MODEL_NAME
    (and should reflect your active inference setup):
    API_BASE_URL = os.getenv("API_BASE_URL", "<your-active-endpoint>")
    MODEL_NAME = os.getenv("MODEL_NAME", "<your-active-model>")

- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables

STDOUT FORMAT
- The script must emit exactly three line types to stdout, in this order:

    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>

  Rules:
    - One [START] line at episode begin.
    - One [STEP] line per step, immediately after env.step() returns.
    - One [END] line after env.close(), always emitted (even on exception).
    - reward and rewards are formatted to 2 decimal places.
    - done and success are lowercase booleans: true or false.
    - error is the raw last_action_error string, or null if none.
    - All fields on a single line with no newlines within a line.
    - Each tasks should return score in [0, 1]

  Example:
    [START] task=click-test env=miniwob model=Qwen3-VL-30B
    [STEP] step=1 action=click('123') reward=0.00 done=false error=null
    [STEP] step=2 action=fill('456','text') reward=0.00 done=false error=null
    [STEP] step=3 action=click('789') reward=1.00 done=true error=null
    [END] success=true steps=3 score=1.00 rewards=0.00,0.00,1.00
"""

import asyncio
import os
import random
import re
import string
import textwrap
from datetime import datetime
from typing import List, Optional, Tuple

from openai import OpenAI

from client import AgentrologyEnv
from models import AgentrologyAction

IMAGE_NAME = os.getenv("IMAGE_NAME") or "agentrology-env:latest"
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
IS_DEV = os.getenv("IS_DEV", "false").lower() == "true"

API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"
TASK_NAME = os.getenv("AGENTROLOGY_TASK", "agentrology-task")
BENCHMARK = os.getenv("BENCHMARK", "agentrology-benchmark")
MAX_STEPS = int(os.getenv("MAX_STEPS", "45"))
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.06"))
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "150"))
SUCCESS_SCORE_THRESHOLD = 0.1  # normalized score in [0, 1]
INTERACTIVE_MODE = os.getenv("INTERACTIVE_MODE", "false").lower() == "true"
WS_CONNECTION_TIMEOUT = int(os.getenv("WS_CONNECTION_TIMEOUT", "60"))
BENCHMARK_DIR = os.getenv("BENCHMARK_DIR", "benchmarks")


def debug_print(msg: str) -> None:
    if IS_DEV:
        print(f"[DEBUG] {msg}", flush=True)


# Max possible reward: each token contributes 0.1, across all steps
_MAX_REWARD_PER_STEP = MAX_TOKENS * 0.1
MAX_TOTAL_REWARD = MAX_STEPS * _MAX_REWARD_PER_STEP

SYSTEM_PROMPT = textwrap.dedent(
    """
You are an Autonomous L2 Security Operations Center (SOC) Analyst operating within a headless, containerized Linux environment.

Your primary objective is to detect, diagnose, and neutralize active security threats on the host system.

# ENVIRONMENT & CAPABILITIES
1. You interact with the system entirely through a standard non-interactive bash shell.
2. For every action you take, you will receive an observation containing:
   - `stdout`: The standard output of your command.
   - `stderr`: Any error output.
   - `active_threats`: An integer indicating how many policy-violating threats are currently active on the system.
   - `reward`: A float indicating your progress (positive for neutralizing threats, negative for destructive actions).
3. The episode ends successfully when `active_threats` reaches 0.

# RULES OF ENGAGEMENT
1. NO INTERACTIVE COMMANDS: Never run commands that require user input or open interactive visual interfaces.
2. Do not perform destructive system actions (reboot, shutdown, network disable). You will be heavily penalized for destructive negligence.
3. REFRAIN FROM KILLING THE ENVIRONMENT: Be sure to avoid killing the process that you are currently using to execute commands, as this will end your episode prematurely and result in failure.
4. In History: R := reward, T := active_threats after executing the command
5. Do not try to use any tool. Stick to the format specified.
6. The /app/env directory contains your interface server, Do NOT attempt to kill or delete files from that location.

# REASONING FRAMEWORK
For every turn, you must structure your response in two parts:
1. [THOUGHT]: Analyze the previous `stdout`/`stderr` and the current `active_threats` count. Formulate a hypothesis about where the threat might be hiding and decide on the next logical command to gather information or neutralize it.
2. [COMMAND]: Provide exactly ONE valid Linux shell command to execute.

Example 1:
[THOUGHT] I need to find any suspicious background processes. A backdoor might be running. I will check the process tree.
[COMMAND] ps auxf

Example 2:
[THOUGHT] The previous output showed a python process named 'reverse_shell.py' running with PID 405. This is clearly unauthorized. I need to terminate it immediately.
[COMMAND] kill -9 405

Example 3:
[THOUGHT] I killed PID 405, but active_threats is still 1. The process must have restarted. I will check the crontab for scheduled tasks.
[COMMAND] crontab -l

Your output must always end with the [COMMAND] block. Do not wrap the command in markdown code blocks, just output the raw command string after the [COMMAND] tag.
"""
).strip()


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


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
    print(
        f'[STEP] step={step} action="{safe_action}" reward={reward:.2f} active_threats={active_threats} done={done_val} error={error_val}',
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


USER_PROMPT_TEMPLATE = """
[STEP]: {step}

## OBSERVATION
[STDOUT]: {stdout}
[STDERR]: {stderr}
[ACTIVE THREATS]: {active_threats}

## FEEDBACK
[LAST REWARD]: {last_reward:.2f}

[RECENT HISTORY]:
{history_block}

Formulate your [THOUGHT] and [COMMAND].
"""


def build_user_prompt(
    step: int,
    stdout: str,
    stderr: str,
    active_threats: int,
    last_reward: float,
    history: List[str],
) -> str:
    history_block = "\n".join(history[-4:]) if history else "None"

    return (
        textwrap.dedent(USER_PROMPT_TEMPLATE)
        .format(
            step=step,
            stdout=stdout,
            stderr=stderr,
            active_threats=active_threats,
            last_reward=last_reward,
            history_block=history_block,
        )
        .strip()
    )


def parse_command(response_text: str) -> str:
    """Extracts the command from the LLM's ReAct output format."""
    match = re.search(r"\[COMMAND\]\s*(.+)", response_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return ""


def get_model_action(
    client: OpenAI,
    step: int,
    stdout: str,
    stderr: str,
    active_threats: int,
    last_reward: float,
    history: List[str],
) -> Tuple[str, str]:
    user_prompt = build_user_prompt(
        step, stdout, stderr, active_threats, last_reward, history
    )

    try:
        if INTERACTIVE_MODE:
            print()
            print("[PROMPT]")
            print(user_prompt)
            print()
            text = str(input("Enter model response: "))
        else:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
                stream=False,
            )
            print(
                f"[DEBUG] Model response received: {completion.choices[0].message.content}",
                flush=True,
            )
            text = (completion.choices[0].message.content or "").strip()
        command = parse_command(text)
        return text, command, None
    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        # TOOD: detect Error code: 402 - {'error': 'You have depleted your monthly included credits. Purchase pre-paid credits to continue using Inference Providers. Alternatively, subscribe to PRO to get 20x more included usage.'}
        return "Model Failed", "", str(exc)


async def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    debug_print(f"Connecting to environment with image: {IMAGE_NAME}")
    env = await AgentrologyEnv.from_docker_image(IMAGE_NAME)
    debug_print("Environment connected successfully")

    start_time = None
    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False
    command_history = []
    neutralization_checkpoints = []
    stop_reason = "Max steps reached without neutralizing all threats"

    def add_command(
        step: int,
        raw_response: str,
        command: str,
        error: Optional[str],
        blocked: bool = False,
    ) -> None:
        command_history.append(
            {
                "step": step,
                "raw_response": raw_response,
                "command": command,
                "blocked": blocked,
                "error": error,
            }
        )

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    try:
        result = await env.reset()
        obs = result.observation

        last_stdout = obs.stdout
        last_stderr = obs.stderr
        last_threats = obs.active_threats
        last_threat_ids = [t.threat_id for t in obs.threat_status if not t.neutralised]
        last_reward = 0.0
        start_time = datetime.now()
        consistent_errors = 0

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                stop_reason = "Episode completed (done=True)"
                break

            await env.connect()

            # Get raw text (for history) and parsed command (for execution)
            raw_response, command, llm_inference_error = get_model_action(
                client,
                step,
                last_stdout,
                last_stderr,
                last_threats,
                last_reward,
                history,
            )

            debug_print(f"[{step}] {raw_response}")

            if not command or command.strip() == "":
                consistent_errors += 1
                debug_print("No command generated by model, skipping step.")
                add_command(
                    step=step,
                    raw_response=raw_response,
                    command=command,
                    error=llm_inference_error or "No command generated",
                )

                command = "[INVALID RESPONSE, Command must be after [COMMAND] block]"
                history.append(f"[S{step}] CMD={command} R=0.0 T={last_threats}")

                if consistent_errors >= 5:
                    stop_reason = "Terminating due to consistent invalid responses from the model."
                    debug_print(stop_reason)
                    break

                continue

            if not AgentrologyAction.is_actionable_command(command):
                limit = AgentrologyAction.get_command_len_limit()
                debug_print(f"Command exceeds length limit {limit} chars")
                add_command(
                    step=step,
                    raw_response=raw_response,
                    command=command,
                    error=f"Command length exceeds limit of {limit} chars",
                    blocked=True,
                )
                command = f"[COMMAND TOO LONG, skipped execution, allowable length is {limit} chars]"
                history.append(f"[S{step}] CMD={command} R=0.0 T={last_threats}")
                continue

            consistent_errors = 0  # reset error count

            try:
                result = await env.step(AgentrologyAction(command=command))
                obs = result.observation

                if result.observation.security_violation:
                    debug_print("[COMMAND BLOCKED] Security violation")
                else:
                    debug_print(
                        f"[COMMAND OUTPUT] stdout: {obs.stdout} stderr: {obs.stderr}"
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
                    error=error,
                    blocked=blocked,
                )
            except Exception as exc:
                print(f"[DEBUG] Unexpected step error: {exc}", flush=True)
                stop_reason = f"Step execution error: {exc}"
                break

            rewards.append(reward)
            steps_taken = step

            # Update state for next prompt
            did_neutralize = obs.active_threats < last_threats
            neutralized_threat_ids = []
            if did_neutralize:
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
            last_threats = obs.active_threats
            last_threat_ids = [
                t.threat_id for t in obs.threat_status if not t.neutralised
            ]
            last_reward = reward

            log_step(
                step=step,
                action=command,
                active_threats=obs.active_threats,
                reward=reward,
                done=done,
                error=error,
            )

            if did_neutralize:
                debug_print(
                    f"---------> Threat neutralized! Remaining: {obs.active_threats} <---------"
                )

            # threats = ""
            # for t in obs.threat_status:
            #     if t.neutralised:
            #         continue
            #     threats += f"{t.threat_id}({t.severity}), "

            # Log history so the model doesn't get stuck in a loop
            history.append(f"[S{step}] CMD={command} R={reward:+.2f} T={last_threats}")

            if done:
                stop_reason = "Episode completed (done=True)"
                break

        # Calculate final score
        # We only sum positive rewards to avoid negative formatting penalties ruining the final score
        total_positive_reward = sum(r for r in rewards if r > 0)
        score = (
            total_positive_reward / MAX_TOTAL_REWARD if MAX_TOTAL_REWARD > 0 else 0.0
        )
        score = min(max(score, 0.0), 1.0)  # clamp to [0, 1]
        success = score >= SUCCESS_SCORE_THRESHOLD

        end_time = datetime.now()
        benchmark_info = {
            "benchmark": BENCHMARK,
            "task": TASK_NAME,
            "model": MODEL_NAME,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
            "max_steps": MAX_STEPS,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "time_taken": (
                (end_time - start_time).total_seconds()
                if start_time and end_time
                else None
            ),
            "stop_reason": stop_reason,
            "steps_taken": steps_taken,
            "final_score": score,
            "success": success,
            "checkpoints": neutralization_checkpoints,
            "api_base_url": API_BASE_URL,
            "system_prompt": SYSTEM_PROMPT,
            "command_history": command_history,
        }

        identifier = "".join(random.choices(string.ascii_letters + string.digits, k=4))
        benchmark_file_name = f"{BENCHMARK}_{TASK_NAME}_{MODEL_NAME}_{identifier}.json"

        # escape any characters in model name that might not be allowed in file names
        benchmark_file_name = re.sub(r'[<>:"/\\|?*]', "_", benchmark_file_name)

        benchmark_path = os.path.join(
            BENCHMARK_DIR,
            benchmark_file_name,
        )
        os.makedirs(BENCHMARK_DIR, exist_ok=True)
        with open(benchmark_path, "w") as f:
            import json

            json.dump(benchmark_info, f, indent=4)
            debug_print(f"Benchmark info saved to {benchmark_path}")

    finally:
        try:
            debug_print("Closing environment connection...")
            await env.close()
        except Exception as e:
            print(f"[DEBUG] env.close() error (container cleanup): {e}", flush=True)
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


if __name__ == "__main__":
    asyncio.run(main())
