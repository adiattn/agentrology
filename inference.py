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
import re
import textwrap
from typing import List, Optional, Tuple

from fastapi import websockets
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


def debug_print(msg: str) -> None:
    if IS_DEV:
        print(f"[DEBUG] {msg}", flush=True)


# Max possible reward: each token contributes 0.1, across all steps
_MAX_REWARD_PER_STEP = MAX_TOKENS * 0.1
MAX_TOTAL_REWARD = MAX_STEPS * _MAX_REWARD_PER_STEP

SYSTEM_PROMPT = textwrap.dedent("""
You are an Autonomous L2 Security Operations Center (SOC) Analyst operating within a headless, containerized Linux environment.

Your primary objective is to detect, diagnose, and neutralize active security threats (rogue background processes, unauthorized open ports, and persistent backdoors) on the host system.

# ENVIRONMENT & CAPABILITIES
1. You interact with the system entirely through a standard non-interactive bash shell. 
2. For every action you take, you will receive an observation containing:
   - `stdout`: The standard output of your command.
   - `stderr`: Any error output.
   - `active_threats`: An integer indicating how many policy-violating threats are currently active on the system.
   - `reward`: A float indicating your progress (positive for neutralizing threats, negative for destructive actions).
3. The episode ends successfully when `active_threats` reaches 0.

# RULES OF ENGAGEMENT (CRITICAL)
1. NO INTERACTIVE COMMANDS: You are in a headless environment. Never run commands that require user input or open interactive visual interfaces.
2. BE SURGICAL, NOT DESTRUCTIVE: Do not attempt to reboot the system, shut down the network interface, or indiscriminately kill system-critical processes (like `systemd`, `bash`, or the SSH daemon). You will be heavily penalized for destructive negligence.
3. REFRAIN FROM KILLING THEN ENVIRONMENT: Be sure to avoid killing the process that you are currently using to execute commands, as this will end your episode prematurely and result in failure.

# REASONING FRAMEWORK
For every turn, you must structure your response in two parts:
1. [THOUGHT]: Analyze the previous `stdout`/`stderr` and the current `active_threats` count. Formulate a hypothesis about where the threat might be hiding and decide on the next logical command to gather information or neutralize it.
2. [COMMAND]: Provide exactly ONE valid Linux shell command to execute.

Example 1:
[THOUGHT] The active_threats count is 1. I need to find any suspicious background processes. A crypto miner or backdoor might be running. I will check the process tree.
[COMMAND] ps auxf

Example 2:
[THOUGHT] The previous output showed a python process named 'reverse_shell_sim.py' running with PID 405. This is clearly unauthorized. I need to terminate it immediately.
[COMMAND] kill -9 405

Example 3:
[THOUGHT] I killed PID 405, but active_threats is still 1. The process must have restarted. I will check the crontab for scheduled tasks.
[COMMAND] crontab -l

Your output must always end with the [COMMAND] block. Do not wrap the command in markdown code blocks, just output the raw command string after the [COMMAND] tag.
        """).strip()


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


def build_user_prompt(
    step: int,
    stdout: str,
    stderr: str,
    active_threats: int,
    last_reward: float,
    history: List[str],
) -> str:
    history_block = "\n".join(history[-4:]) if history else "None"
    return textwrap.dedent(f"""
        Step: {step}
        --- Previous Observation ---
        [STDOUT]:
        {stdout}
        [STDERR]:
        {stderr}
        [ACTIVE THREATS]: {active_threats}
        [LAST REWARD]: {last_reward:.2f}

        Recent History:
        {history_block}

        Formulate your [THOUGHT] and [COMMAND].
        """).strip()


def parse_command(response_text: str) -> str:
    """Extracts the command from the LLM's ReAct output format."""
    match = re.search(r"\[COMMAND\]\s*(.+)", response_text, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Fallback if the model forgets the [COMMAND] tag
    lines = [line.strip() for line in response_text.strip().split("\n") if line.strip()]
    if lines:
        return lines[-1].replace("`", "").strip()
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
        text = (completion.choices[0].message.content or "").strip()
        command = parse_command(text)
        return text, command
    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        # TOOD: detect Error code: 402 - {'error': 'You have depleted your monthly included credits. Purchase pre-paid credits to continue using Inference Providers. Alternatively, subscribe to PRO to get 20x more included usage.'}
        return "Model Failed", ""


async def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    debug_print(f"Connecting to environment with image: {IMAGE_NAME}")
    env = await AgentrologyEnv.from_docker_image(IMAGE_NAME)
    debug_print("Environment connected successfully")

    history: List[str] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=TASK_NAME, env=BENCHMARK, model=MODEL_NAME)

    try:
        result = await env.reset()
        obs = result.observation

        last_stdout = obs.stdout
        last_stderr = obs.stderr
        last_threats = obs.active_threats
        last_reward = 0.0

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            # Get raw text (for history) and parsed command (for execution)
            raw_response, command = get_model_action(
                client,
                step,
                last_stdout,
                last_stderr,
                last_threats,
                last_reward,
                history,
            )

            debug_print(f"[{step}] {raw_response}")

            try:
                result = await env.step(AgentrologyAction(command=command))
                obs = result.observation

                reward = result.reward or 0.0
                done = result.done
                # If the security validator blocks it, we might catch it in observation metadata
                error = (
                    obs.security_violation
                    if hasattr(obs, "security_violation") and obs.security_violation
                    else None
                )
            except websockets.exceptions.ConnectionClosedError:
                print(
                    "[DEBUG] WebSocket closed unexpectedly. The agent likely crashed the container.",
                    flush=True,
                )
                reward = -1.0
                done = True
                error = "CRITICAL: Environment server terminated unexpectedly."
                rewards.append(reward)
                log_step(
                    step=step,
                    action=command,
                    reward=reward,
                    active_threats=last_threats,
                    done=done,
                    error=error,
                )
                break
            except Exception as exc:
                print(f"[DEBUG] Unexpected step error: {exc}", flush=True)
                break

            rewards.append(reward)
            steps_taken = step

            # Update state for next prompt
            last_stdout = obs.stdout
            last_stderr = obs.stderr
            last_threats = obs.active_threats
            last_reward = reward

            log_step(
                step=step,
                action=command,
                active_threats=obs.active_threats,
                reward=reward,
                done=done,
                error=error,
            )

            threats = ""
            for t in obs.threat_status:
                if t.neutralised:
                    continue
                threats += f"{t.threat_id}({t.severity}), "

            # Log history so the model doesn't get stuck in a loop
            history.append(
                f"Step {step} Cmd: {command} -> reward: {reward:+.2f}, threats remaining: {last_threats} {threats}"
            )

            if done:
                break

        # Calculate final score (e.g. 5 threats killed out of 6 max = 0.833)
        # We only sum positive rewards to avoid negative formatting penalties ruining the final score
        total_positive_reward = sum(r for r in rewards if r > 0)
        score = (
            total_positive_reward / MAX_TOTAL_REWARD if MAX_TOTAL_REWARD > 0 else 0.0
        )
        score = min(max(score, 0.0), 1.0)  # clamp to [0, 1]
        success = score >= SUCCESS_SCORE_THRESHOLD

    finally:
        try:
            await env.close()
        except Exception as e:
            print(f"[DEBUG] env.close() error (container cleanup): {e}", flush=True)
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


if __name__ == "__main__":
    asyncio.run(main())
