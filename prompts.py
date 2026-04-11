import textwrap

SYSTEM_PROMPT_HEADER = textwrap.dedent(
    """\
[AGENTROLOGY] You are an Autonomous L2 Security Operations Center (SOC) Analyst operating within a Linux environment.
Your objective: Neutralize active_threats via non-interactive bash.

# ENVIRONMENT
For every action, you receive OBSERVATION:
- stdout, stderr: command output/errors
- active_threats (T): number of remaining threats
- reward (R): progress signal (positive = good, zero = ineffective/destructive)
- security_violation: message if command was blocked due to violation

# RULES OF ENGAGEMENT
1. NO INTERACTIVE COMMANDS: Never run commands that require user input or open interactive visual interfaces.
2. DESTRUCTION: Never use reboot, shutdown, rm -rf, or network disabling.
3. IMPORTANT:  The /app/env directory contains your interface uvicorn server, Do **NOT** attempt to kill or delete files from that location.
4. NO MASS TERMINATION: Commands that terminate multiple crtical processes at once (via pipes, xargs, or pattern matching) are strictly prohibited.
5. NEVER target directly or indirectly: uvicorn processes, PORT 8000, /app/env
6. If a command does not reduce T, DO NOT repeat it, change strategy.
7. RESPECT VIOLATIONS: A violation signal indicates a critical boundary;

# Guide: ENUMERATE => KILL => CLEAN => VERIFY
- Processes can be suspicious even if they are not running.

"""
).strip()


SYSTEM_PROMPT = textwrap.dedent(
    SYSTEM_PROMPT_HEADER
    + """\
# REASONING FRAMEWORK
For every turn, you must structure your response in two parts:
1. [THOUGHT]: Analyze the previous OBSERVATION. Formulate a VERY SHORT Ahypothesis about your next action.
2. [COMMAND]: Provide exactly ONE valid Linux shell command to execute. Following are examples, BUT you are not limited these commands, these are just for illustration.

Example 1:
[THOUGHT] I need to find any suspicious background processes. A backdoor might be running. I will check the process tree.
[COMMAND] ps auxf

Example 2:
[THOUGHT] I have identified a suspicious script running under PID 742. I have verified it is not a system process. I am clear to neutralize the threat.
[COMMAND] kill -9 742

Example 3:
[THOUGHT] A malicious process keeps reappearing after being terminated. I will inspect the current user's scheduled jobs for unauthorized entries.
[COMMAND] crontab -l

Your output must always end with the [COMMAND] block. Do not wrap the command in markdown code blocks, just output the raw command string after the [COMMAND] tag.
"""
).strip()

SYSTEM_PROMPT_NO_REASONING = textwrap.dedent(
    SYSTEM_PROMPT_HEADER
    + """\
# REASONING FRAMEWORK
For every turn, you must respond with exactly ONE valid Linux shell command to execute. DO NOT provide any thought or reasoning!

Example 1:
[COMMAND] ps auxf

Example 2:
[COMMAND] kill -9 405

Example 3:
[COMMAND] crontab -l

Example 4:
[COMMAND] find /usr/bin /usr/sbin -mmin -60

Your output must be EXACTLY the [COMMAND] block and nothing else. Do not wrap the command in markdown code blocks, just output the raw command string after the [COMMAND] tag.
"""
).strip()


SYSTEM_PROMPT_JSON = textwrap.dedent(
    SYSTEM_PROMPT_HEADER
    + """\
# REASONING FRAMEWORK
You must structure your response as a single, valid JSON object containing exactly two keys: "thought" and "command":
1. "thought": A VERY SHORT hypothesis about your next action based on OBSERVATION.
2. "command": Linux shell command to execute.

Do NOT include any conversational text before or after the JSON object. Output the raw JSON string only.

Example 1:
{"thought": "I need to find any suspicious background processes. A backdoor might be running. I will check the process tree.", "command": "ps auxf"}

"""
).strip()


SYSTEM_PROMPT_NO_REASONING_JSON = textwrap.dedent(
    SYSTEM_PROMPT_HEADER
    + """\
# REASONING FRAMEWORK
You must structure your response as a single, valid JSON object containing exactly one key: "command": {"command": "<command>"}
1. "command": Linux shell command to execute.

Do NOT include any conversational text before or after the JSON object. Output the raw JSON string only.

Example 1:
{"command": "ps auxf"}

Example 2:
{"command": "kill -9 405"}

"""
).strip()


def extract_command_json(response: str) -> str:
    try:
        json_data = extract_json_from_llm(response)
        return json_data.get("command", None)
    except:
        return None


def extract_command_react(response: str) -> str:
    match = re.search(r"\[COMMAND\]\s*(.+)", response, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return None


import ast
import json
import re
import unicodedata
from typing import Any, Dict, List, Optional, Union


def extract_json_from_llm(
    response: str,
    *,
    prefer_largest: bool = True,
    strict_ast: bool = False,
) -> Union[Dict[str, Any], List[Any]]:
    """
    Extract and parse JSON from messy LLM output.
    """
    if not isinstance(response, str):
        raise TypeError(f"Expected str, got {type(response).__name__!r}.")
    if not response.strip():
        raise ValueError("Input string is empty or whitespace-only.")

    text = response.strip()

    def _try_json(s: str) -> Optional[Any]:
        try:
            return json.loads(s)
        except (json.JSONDecodeError, ValueError):
            return None

    def _normalize_unicode(s: str) -> str:
        replacements = {
            "\u2018": "'",
            "\u2019": "'",  # '' curly single
            "\u201c": '"',
            "\u201d": '"',  # "" curly double
            "\u201e": '"',
            "\u201f": '"',  # „‟ low/high double
            "\u2010": "-",
            "\u2011": "-",  # non-breaking / figure dash
            "\u2012": "-",
            "\u2013": "-",
            "\u2014": "-",
            "\u2015": "-",
            "\u00a0": " ",  # non-breaking space
        }
        for src, dst in replacements.items():
            s = s.replace(src, dst)
        return unicodedata.normalize("NFC", s)

    def _remove_comments(s: str) -> str:
        s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
        s = re.sub(r"(?m)//[^\n]*$", "", s)
        return s

    def _remove_trailing_commas(s: str) -> str:
        return re.sub(r",\s*([\]}])", r"\1", s)

    def _fix_literal_newlines_in_strings(s: str) -> str:
        def _escape_nl(m: re.Match) -> str:
            inner = m.group(1).replace("\n", "\\n").replace("\r", "\\r")
            return f'"{inner}"'

        return re.sub(r'"((?:[^"\\]|\\.)*)"', _escape_nl, s)

    def _clean(s: str) -> str:
        s = _normalize_unicode(s)
        s = _remove_comments(s)
        s = _remove_trailing_commas(s)
        return s.strip()

    def _try_parse(s: str, *, allow_ast: bool = True) -> Optional[Any]:
        result = _try_json(s)
        if result is not None:
            return result

        cleaned = _clean(s)
        result = _try_json(cleaned)
        if result is not None:
            return result

        fixed = _fix_literal_newlines_in_strings(cleaned)
        result = _try_json(fixed)
        if result is not None:
            return result

        if "'" in cleaned and '"' not in cleaned:
            swapped = cleaned.replace("'", '"')
            result = _try_json(swapped)
            if result is not None:
                return result

        completed = _try_complete_brackets(cleaned)
        if completed:
            result = _try_json(completed)
            if result is not None:
                return result

        if allow_ast and not strict_ast:
            for src in (s, cleaned):
                try:
                    obj = ast.literal_eval(src)
                    if isinstance(obj, (dict, list)):
                        return obj
                except Exception:
                    pass

        return None

    def _try_complete_brackets(s: str) -> Optional[str]:
        stack: List[str] = []
        in_string = False
        escape_next = False

        for ch in s:
            if escape_next:
                escape_next = False
                continue
            if ch == "\\" and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch in "{[":
                stack.append("}" if ch == "{" else "]")
            elif ch in "}]":
                if stack and stack[-1] == ch:
                    stack.pop()

        if not stack:
            return None
        return s + "".join(reversed(stack))

    def _extract_code_fence_blocks(s: str) -> List[str]:
        pattern = r"```(?:[a-zA-Z0-9_+-]*)?\s*(.*?)```"
        return re.findall(pattern, s, re.DOTALL | re.IGNORECASE)

    def _extract_inline_backtick(s: str) -> List[str]:
        pattern = r"`([{\[].*?[}\]])`"
        return re.findall(pattern, s, re.DOTALL)

    def _extract_balanced_candidates(s: str) -> List[str]:
        candidates: List[str] = []
        stack: List[str] = []
        start: Optional[int] = None
        in_string = False
        escape_next = False

        for i, ch in enumerate(s):
            if escape_next:
                escape_next = False
                continue
            if ch == "\\" and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue

            if ch in "{[":
                if not stack:
                    start = i
                stack.append("}" if ch == "{" else "]")
            elif ch in "}]":
                if stack and ch == stack[-1]:
                    stack.pop()
                    if not stack and start is not None:
                        candidates.append(s[start : i + 1])
                        start = None
                else:
                    stack.clear()
                    start = None

        return candidates

    def _score(obj: Any) -> int:
        if isinstance(obj, dict):
            return len(obj)
        if isinstance(obj, list):
            return len(obj)
        return 0

    valid_results: List[Any] = []

    def _collect(candidate: str) -> None:
        obj = _try_parse(candidate)
        if obj is not None:
            valid_results.append(obj)

    obj = _try_parse(text)
    if obj is not None:
        return obj

    for block in _extract_code_fence_blocks(text):
        _collect(block.strip())

    for span in _extract_inline_backtick(text):
        _collect(span.strip())

    for candidate in _extract_balanced_candidates(text):
        _collect(candidate)

    normalised = _normalize_unicode(text)
    if normalised != text:
        for candidate in _extract_balanced_candidates(normalised):
            _collect(candidate)

    _collect(_clean(text))

    if not valid_results:
        preview = text[:500] + ("…" if len(text) > 500 else "")
        raise ValueError(
            "No valid JSON structure found in the LLM response.\n"
            f"Response preview:\n{preview}"
        )

    if not prefer_largest or len(valid_results) == 1:
        return valid_results[0]

    return max(valid_results, key=_score)
