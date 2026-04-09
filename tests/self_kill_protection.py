import asyncio
import os
import random
from typing import List, Tuple

from client import AgentrologyEnv
from models import AgentrologyAction
from server.security import CommandValidator

IMAGE_NAME = "agentrology-env:latest"


class C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


def log(msg, color=C.RESET):
    print(f"{color}{msg}{C.RESET}", flush=True)


def parse_processes(stdout: str):
    lines = stdout.strip().split("\n")
    processes = []

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 11:
            continue

        pid = int(parts[1])
        cmd = " ".join(parts[10:]).lower()

        processes.append({"pid": pid, "cmd": cmd})

    return processes


def find_targets(processes):
    server_pids = []
    other_pids = []

    for p in processes:
        if "uvicorn" in p["cmd"]:
            server_pids.append(p["pid"])
        else:
            other_pids.append(p["pid"])

    return server_pids, other_pids


def generate_payloads(server_pids, other_pids) -> List[Tuple[str, bool]]:
    payloads = []

    if server_pids:
        for server_pid in server_pids:
            payloads.extend(
                [
                    (f"kill -9 {server_pid}", True),
                    (f"kill {server_pid}", True),
                    (f"kill -15 {server_pid}", True),
                ]
            )

    payloads.extend(
        [
            ("pkill -f uvicorn", True),
            ("pkill -f server.app", True),
            ("killall uvicorn", True),
            ("kill -9 $$", True),
            ("kill -9 1", True),
            ("kill -9 $(pgrep -f uvicorn)", True),
        ]
    )

    if other_pids:
        payloads.append((f"kill -9 {other_pids[0]}", False))

    payloads.append(("ps aux", False))

    return payloads


def is_blocked(security_violation) -> bool:
    if security_violation and security_violation != "":
        return True
    return False


async def test_method():
    log("[TEST] Running self-kill protection test...", C.CYAN)
    log("[INFO] Fetching processes...", C.CYAN)
    process_ids = [
        os.getpid(),  # current process
        os.getppid(),  # parent (uvicorn launcher)
    ]
    log(f"[INFO] Current PID: {process_ids[0]}, Parent PID: {process_ids[1]}", C.YELLOW)


async def main(check_method=False):
    log("[INIT] Connecting to environment...", C.CYAN)

    if not check_method:
        env = await AgentrologyEnv.from_docker_image(IMAGE_NAME)

    try:
        if not check_method and env:
            await env.connect()
            await env.reset()

        log("[INFO] Fetching processes...", C.CYAN)
        if not check_method:
            result = await env.step(AgentrologyAction(command="ps aux"))
            stdout = result.observation.stdout

            processes = parse_processes(stdout)
            server_pids, other_pids = find_targets(processes)

            log(f"[INFO] Server PIDs: {server_pids}", C.YELLOW)
            log(f"[INFO] Other PID sample: {other_pids[:3]}", C.YELLOW)
        else:
            server_pids = [os.getppid(), os.getppid()]
            other_pids = [random.randint(1000, 5000) for _ in range(3)]

        payloads = generate_payloads(server_pids, other_pids)

        passed = 0
        failed = 0

        log("\n[TEST] Running protection tests...\n", C.CYAN)

        for cmd, should_block in payloads:
            if not check_method:
                security_violation = (
                    await env.step(AgentrologyAction(command=cmd))
                ).observation.security_violation
            else:  # Simulate security violation for self-kill attempts
                security_violation = (
                    "Simulated violation"
                    if CommandValidator.is_kill_self_command(cmd)
                    else ""
                )

            blocked = is_blocked(security_violation)

            if blocked == should_block:
                expected = "BLOCKED" if should_block else "ALLOWED"
                log(f"[{expected}] {cmd}", C.GREEN if should_block else C.YELLOW)
                passed += 1
            else:
                info = f"Expected {'BLOCKED' if should_block else 'ALLOWED'}, but got {'BLOCKED' if blocked else 'ALLOWED'}"
                log(f"[BYPASS!] {cmd} - {info}", C.RED)

                failed += 1

        log("\n========== SUMMARY ==========", C.CYAN)
        log(f"Passed: {passed}", C.GREEN)
        log(f"Failed: {failed}", C.RED)

        if failed > 0:
            exit(1)

    except Exception as e:
        print()
        if "ConnectionClosed" in type(e).__name__:
            print(
                f"{C.RED}[ERROR] Connection was closed, likely due to a self-kill attempt.{C.RESET}"
            )
        else:
            print(f"{C.RED}[ERROR] {e}{C.RESET}", type(e))

    finally:
        log("\n[CLEANUP] Closing environment...", C.CYAN)
        if not check_method and env:
            await env.close()


if __name__ == "__main__":
    asyncio.run(main(True))
