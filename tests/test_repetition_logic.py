import sys

from server.agentrology_environment import AgentrologyEnvironment


class C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


def log(msg, color=C.RESET):
    print(f"{color}{msg}{C.RESET}", flush=True)


class DummyEnv(AgentrologyEnvironment):
    def __init__(self):
        self._trace_steps = []


def run_tests():
    log("[TEST] Running repetition and pipeline spam logic tests...", C.CYAN)
    env = DummyEnv()

    spam_payloads = [
        # (Command, Should Be Flagged)
        ("whoami whoami whoami whoami whoami", True),
        ("whoami", False),
        ("ls -la && ls -la && ls -la && ls -la && ls -la", True),
        ("cat text.txt | cat text.txt | cat text.txt | cat text.txt | cat | cat", True),
        ("ls -la && whoami", False),
        ("ps aux | grep -v a | grep -v b | grep -v c | grep -v d | grep -v e", True),
        ("ps aux | grep -v a | grep -v b | grep -v c | grep -v d", False),
        ("find / -name auth | grep foo | grep bar | grep baz", False),  # 3 greps
        (
            "ps aux | awk '{print $2}' | grep 554 | grep -v grep | grep -v uvicorn | grep -v bash | grep root",
            True,
        ),  # 5 greps
    ]

    passed = 0
    failed = 0

    log("\n1. Structural Spam & Base Binary Repetition\n", C.YELLOW)

    for cmd, should_block in spam_payloads:
        blocked = env.is_repeating_bad_command(cmd, threshold=5)

        if blocked == should_block:
            expected = "FLAGGED" if should_block else "ALLOWED"
            log(f"[{expected}] {cmd}", C.GREEN if should_block else C.CYAN)
            passed += 1
        else:
            info = f"Expected {'FLAGGED' if should_block else 'ALLOWED'}, but got {'FLAGGED' if blocked else 'ALLOWED'}"
            log(f"[FAIL!] {cmd} - {info}", C.RED)
            failed += 1

    log("\n2. Hallucination Pipeline Appending (Empty Output Building)\n", C.YELLOW)

    building_payloads = [
        # (Prev Cmd, Previous Output, Previous Err, Command, Should Be Flagged)
        ("ps aux | grep uvicorn", "", "", "ps aux | grep uvicorn | grep -v PID", True),
        ("ls -l", "", "", "ls -la", False),
        ("ps aux", "", "", "ps aux | grep uvicorn", True),
        (
            "ps aux | grep uvicorn",
            "root 1234 python",
            "",
            "ps aux | grep uvicorn | grep -v PID",
            False,
        ),
        (
            "ps aux | grep -v uvicorn | grep -v cron",
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
            "",
            "ps aux | grep -v uvicorn | grep -v cron | grep -v ps",
            True,
        ),
        (
            "ps aux | grep -v uvicorn | grep -v cron | grep -v ps",
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
            "",
            "ps aux | grep -v uvicorn | grep -v cron | grep -v ps | grep -v grep",
            True,
        ),
    ]

    for prev_cmd, prev_out, prev_err, cmd, should_block in building_payloads:
        # Mock the previous state
        env._trace_steps = [
            {"command": prev_cmd, "stdout": prev_out, "stderr": prev_err}
        ]

        blocked = env.is_building_on_empty_output(cmd)

        if blocked == should_block:
            expected = "FLAGGED" if should_block else "ALLOWED"
            log(
                f"[{expected}] {cmd} (prev_out={bool(prev_out)})",
                C.GREEN if should_block else C.CYAN,
            )
            passed += 1
        else:
            info = f"Expected {'FLAGGED' if should_block else 'ALLOWED'}, but got {'FLAGGED' if blocked else 'ALLOWED'}"
            log(f"[FAIL!] {cmd} - {info}", C.RED)
            failed += 1

    log("\n========== SUMMARY ==========", C.CYAN)
    log(f"Passed: {passed}", C.GREEN)
    log(f"Failed: {failed}", C.RED)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
