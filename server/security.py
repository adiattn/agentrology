"""Command security validator for the Agentrology environment.

This module enforces a strict command policy to prevent agents (or malicious
actors probing the API) from executing commands that could exfiltrate secrets,
escalate privileges, or damage the host system. Every shell command passes
through CommandValidator.validate() before execution.

Assumptions for Hugging Face environment:
- SSH is already not present in Dockerfile
"""

import os
import re
import shlex
import urllib.parse
from dataclasses import dataclass
from typing import Optional

MAX_COMMAND_LENGTH = 512

BLOCKED_EXECUTABLES = frozenset(
    [
        # "ssh",
        "scp",
        "sftp",
        "rsync",
        "telnet",
        "rlogin",
        "rsh",
        "ftp",
        "ncat",
        "netcat",
        "nmap",
        "masscan",
        "curl",
        "wget",
        "http",
        "sudo",
        "su",
        "doas",
        "pkexec",
        "runuser",
        "chroot",
        "nsenter",
        "unshare",
        "strace",
        "ltrace",
        "gdb",
        "ptrace",
        "mount",
        "umount",
        "mkfs",
        "fdisk",
        "parted",
        "cryptsetup",
        "openssl",
        "gpg",
        "at",
        "batch",
        "systemctl",
        "service",
        "passwd",
        "chpasswd",
        "useradd",
        "usermod",
        "userdel",
        "groupadd",
        "visudo",
    ]
)

BLOCKED_PATTERNS = [
    # (r"\bssh\b", "Remote shell access is forbidden."),
    (r"\bscp\b", "Secure copy is forbidden."),
    (r"(?:^|[;&]\s*|\|\s*)nc(?:\s|$)", "Raw TCP connections via netcat are forbidden."),
    (r"\bncat\b", "Raw TCP connections via ncat are forbidden."),
    (r"\bcurl\b", "Outbound HTTP requests are forbidden."),
    (r"\bwget\b", "Outbound HTTP requests are forbidden."),
    (r"\bsudo\b", "Privilege escalation via sudo is forbidden."),
    (r"\bsu\s", "Privilege escalation via su is forbidden."),
    (r"\bsu\s*$", "Privilege escalation via su is forbidden."),
    (r"\b(nano|vi|vim)\b", "Interactive text editors are forbidden."),
    (r"/etc/shadow", "Reading the shadow password database is forbidden."),
    (r"/etc/gshadow", "Reading the shadow group database is forbidden."),
    (r"/root/", "Accessing the root home directory is forbidden."),
    (r"/proc/\d+/environ", "Reading process environment memory is forbidden."),
    (r"/proc/\d+/mem", "Reading raw process memory is forbidden."),
    (r">\s*/etc/passwd", "Overwriting /etc/passwd is forbidden."),
    (r">>\s*/etc/passwd", "Appending to /etc/passwd is forbidden."),
    (r">\s*/etc/sudoers", "Overwriting /etc/sudoers is forbidden."),
    (r">\s*/etc/crontab", "Writing to /etc/crontab is forbidden."),
    (r">\s*/etc/cron\.d/", "Writing to /etc/cron.d/ is forbidden."),
    (r">\s*/etc/profile", "Writing to /etc/profile is forbidden."),
    (r">\s*/etc/bashrc", "Writing to /etc/bashrc is forbidden."),
    (r">\s*/etc/ld\.so", "Writing to ld.so configuration is forbidden."),
    (r"\|\s*bash\b", "Piping to bash is forbidden."),
    (r"\|\s*sh\b", "Piping to sh is forbidden."),
    (r"\|\s*zsh\b", "Piping to zsh is forbidden."),
    (r"\beval\s+", "eval execution is forbidden."),
    (r"chmod\s+[ugoa]*\+s", "Setting SUID/SGID bits is forbidden."),
    (r"chmod\s+[0-7]*[4-7][0-7]{3}", "Setting SUID/SGID bits is forbidden."),
    (r"\bdd\s+.*of=/dev/", "Direct disk writes via dd are forbidden."),
    (r">\s*/dev/sd", "Writing directly to block devices is forbidden."),
    (r"\bnsenter\b", "Namespace entry is forbidden."),
    (r"python3?\s+-c\s+['\"].*socket", "Socket-based Python one-liners are forbidden."),
    (
        r"python3?\s+-c\s+['\"].*subprocess.*Popen.*\[.*(nc|bash|sh)",
        "Shell-spawning Python one-liners are forbidden.",
    ),
    (r"\x00", "Null bytes in commands are forbidden."),
    (r"\\x[0-9a-fA-F]{2}", "Hex-escaped characters in commands are forbidden."),
    (
        r"\$\(.*\b(bash|sh|zsh|curl|wget|nc|ncat|python\d*\s+-c)\b.*\)",
        "Dangerous command substitution is forbidden.",
    ),
]

ALLOWED_CRONTAB_SUBCOMMANDS = frozenset(["-r", "-l"])

PROTECTED_PIDS = {
    1,  # container init
    os.getpid(),  # current process
    os.getppid(),  # parent (uvicorn launcher)
}

PROTECTED_KEYWORDS = ["uvicorn", "server.app", "/app/env"]

# Allowlist for read-only diagnostic/forensic commands.
# These are the commands a threat-neutralization agent legitimately needs.
# A pipeline is safe if EVERY segment's first token is in this set.
SAFE_DIAGNOSTIC_EXECUTABLES = frozenset(
    [
        "netstat",
        "ss",
        "systemctl",
        "ps",
        "lsof",
        "who",
        "w",
        "last",
        "lastlog",
        "grep",
        "egrep",
        "fgrep",
        "awk",
        "sed",
        "cut",
        "sort",
        "uniq",
        "head",
        "tail",
        "cat",
        "less",
        "more",
        "wc",
        "find",
        "ls",
        "stat",
        "file",
        "du",
        "df",
        "id",
        "whoami",
        "uname",
        "hostname",
        "uptime",
        "top",
        "htop",
        "pgrep",
        "pstree",
        "env",
        "printenv",
        "ip",
        "ifconfig",
        "arp",
        "route",
        "kill",
        "pkill",  # for neutralization; self-kill guard handles abuse
    ]
)

SAFE_SYSTEMCTL_SUBCOMMANDS = frozenset(
    [
        "list-units",
        "list-unit-files",
        "list-sockets",
        "list-timers",
        "list-jobs",
        "list-machines",
        "list-dependencies",
        "status",
        "show",
        "cat",
        "is-active",
        "is-enabled",
        "is-failed",
        "help",
    ]
)


@dataclass
class ValidationResult:
    """Result of a command security validation.

    Attributes:
        is_allowed: True if the command passes all security checks.
        reason: Human readable explanation when the command is blocked.
            None when is_allowed is True.
    """

    is_allowed: bool
    reason: Optional[str] = None


class CommandValidator:
    """Enforces a deny-first security policy on all shell commands.

    Commands are evaluated in the following order:
        1. Length limit check.
        2. Explicit allowlist for safe crontab subcommands.
        3. Safe diagnostic pipeline allowlist (read-only forensic commands).
        4. Regex pattern blocklist (catches obfuscated variants).
        5. First-token executable blocklist.

    Example:
        >>> validator = CommandValidator()
        >>> result = validator.validate("ps aux | grep python")
        >>> result.is_allowed
        True
        >>> result = validator.validate("sudo bash")
        >>> result.is_allowed
        False
        >>> result.reason
        'Privilege escalation via sudo is forbidden.'
    """

    def __init__(self) -> None:
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), reason)
            for pattern, reason in BLOCKED_PATTERNS
        ]

    @staticmethod
    def is_kill_self_command(command: str) -> bool:
        """Detect commands that attempt to kill the agent process itself.

        Args:
            command: The raw shell command string submitted by the agent.
        """
        command = command.lower()
        protected_keywords = ["uvicorn", "server.app", "/app/env"]

        if (
            command.startswith("pkill")
            or command.startswith("killall")
            or command.startswith("kill")
        ):
            if any(keyword in command for keyword in protected_keywords):
                return True

        if "$$" in command or "$(pgrep -f uvicorn)" in command:
            return True

        def extract_kill_pids(command: str) -> list[int]:
            match = re.match(r"^kill(?:\s+-(\d+))?\s+((?:\d+\s*)+)$", command)
            if not match:
                return []
            _ = match.group(1)
            pid_part = match.group(2)
            pids = re.findall(r"\b\d+\b", pid_part)
            return [int(pid) for pid in pids]

        def _get_process_cmd(pid: int) -> str:
            import subprocess

            try:
                result = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "cmd="],
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
                return result.stdout.lower()
            except Exception:
                return ""

        pids = extract_kill_pids(command)
        if not pids:
            return False

        for pid in pids:
            # direct PID protection
            if pid in PROTECTED_PIDS:
                return True

            # Process-level protection
            cmdline = _get_process_cmd(pid)
            if any(k in cmdline for k in protected_keywords):
                return True
        return False

    @staticmethod
    def _is_safe_diagnostic_pipeline(command: str) -> bool:
        """Return True if every pipe segment starts with a known safe executable.

        This allows commands like:
            netstat -tulnp | grep -v 'grep' | grep -iE 'ssh|nc|netcat|python|bash|sh'

        Args:
            command: The stripped shell command string.
        """
        segments = re.split(r"\|", command)
        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue
            # extract first token of this segment
            try:
                tokens = shlex.split(seg)
            except ValueError:
                tokens = seg.split()
            if not tokens:
                continue
            first = tokens[0].split("/")[-1].lower()
            if first not in SAFE_DIAGNOSTIC_EXECUTABLES:
                return False
        return True

    def validate(self, command: str) -> ValidationResult:
        """Validate a shell command against the security policy.

        Args:
            command: The raw shell command string submitted by the agent.

        Returns:
            A ValidationResult indicating whether execution is permitted.
        """
        if not command or not command.strip():
            return ValidationResult(is_allowed=False, reason="Empty command rejected.")

        if len(command) > MAX_COMMAND_LENGTH:
            return ValidationResult(
                is_allowed=False,
                reason=f"Command exceeds maximum length of {MAX_COMMAND_LENGTH} characters.",
            )

        command = urllib.parse.unquote(command)
        stripped = command.strip()

        if self._is_safe_crontab(stripped):
            return ValidationResult(is_allowed=True)

        if self._is_safe_diagnostic_pipeline(stripped):
            if (
                "kill" in stripped or "pkill" in stripped
            ) and CommandValidator.is_kill_self_command(stripped):
                return ValidationResult(
                    is_allowed=False,
                    reason="Policy violation: attempted termination of server process.",
                )
            return ValidationResult(is_allowed=True)

        first_token = self._extract_first_token(stripped)

        if first_token == "curl":
            LOCALHOST_REGEX = re.compile(
                r"^curl\s+(-I\s+)?http://(127\.0\.0\.1|localhost):\d+(/[^\s]*)?$"
            )
            if LOCALHOST_REGEX.match(stripped):
                return ValidationResult(is_allowed=True)
            else:
                return ValidationResult(
                    is_allowed=False,
                    reason="Only curl requests to http://localhost with explicit ports are allowed.",
                )

        if first_token == "cat" and (
            re.search(r"/etc/(shadow|gshadow|passwd)", stripped)
            or re.search(r"\.env", stripped)
        ):
            return ValidationResult(
                is_allowed=False,
                reason="Reading sensitive system files is forbidden.",
            )

        if "rm " in stripped:
            if re.search(r"\brm\s+(?:-[a-zA-Z]+\s+)*/\*?(?:\s|$)", stripped):
                return ValidationResult(
                    is_allowed=False,
                    reason="Dangerous use of 'rm' targeting the root directory is forbidden.",
                )

        if first_token == "systemctl":
            try:
                tokens = shlex.split(stripped)
            except ValueError:
                tokens = stripped.split()
            subcmd = tokens[1] if len(tokens) > 1 else ""
            if subcmd in SAFE_SYSTEMCTL_SUBCOMMANDS:
                return ValidationResult(is_allowed=True)
            else:
                return ValidationResult(
                    is_allowed=False,
                    reason=f"systemctl '{subcmd}' is not permitted. Only read-only subcommands are allowed.",
                )

        for pattern, reason in self._compiled_patterns:
            if pattern.search(stripped):
                return ValidationResult(is_allowed=False, reason=reason)

        if first_token and first_token.lower() in BLOCKED_EXECUTABLES:
            return ValidationResult(
                is_allowed=False,
                reason=f"Execution of '{first_token}' is not permitted in this environment.",
            )

        # since this blocks many possible variants
        if "xargs kill" in stripped or "| kill" in stripped:
            return ValidationResult(
                is_allowed=False,
                reason="Piping into kill or using xargs kill is forbidden to prevent self-termination attempts. Prefer using 'kill' with explicit PIDs.",
            )

        if (
            "kill" in stripped or "pkill" in stripped
        ) and CommandValidator.is_kill_self_command(stripped):
            return ValidationResult(
                is_allowed=False,
                reason="[CRITICAL POLICY VIOLATION] Self-termination attempt detected. Target process is part of the agent runtime. This action is prohibited and MUST NOT be executed.",
            )

        return ValidationResult(is_allowed=True)

    def _is_safe_crontab(self, command: str) -> bool:
        """Check whether a crontab invocation uses only permitted subcommands.

        Args:
            command: The stripped shell command string.

        Returns:
            True if the command is a safe crontab invocation.
        """
        parts = command.split()
        if not parts or parts[0] != "crontab":
            return False
        if len(parts) == 2 and parts[1] in ALLOWED_CRONTAB_SUBCOMMANDS:
            return True
        return False

    def _extract_first_token(self, command: str) -> Optional[str]:
        """Extract the first executable token from a shell command string.

        Handles common shell constructs like environment variable assignments
        that precede the actual executable (e.g. ``FOO=bar python3 script.py``).

        Args:
            command: The stripped shell command string.

        Returns:
            The first non-assignment token, or None if parsing fails.
        """
        try:
            tokens = shlex.split(command)
        except ValueError:
            return command.split()[0] if command.split() else None

        for token in tokens:
            if "=" not in token:
                return token.split("/")[-1]
        return None
