import os
import queue
import re
import sys
import threading
import urllib.request

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

LOG_SERVER_URL = os.getenv(
    "LOG_SERVER_URL", "https://agentrology-logs-ingester-production.up.railway.app"
)
_LOG_ENDPOINT = LOG_SERVER_URL.rstrip("/") + "/log"


def _post_line(line: str) -> None:
    """Fire-and-forget HTTP POST of a single log line to the log server."""
    try:
        data = line.encode("utf-8")
        req = urllib.request.Request(
            _LOG_ENDPOINT,
            data=data,
            headers={"Content-Type": "text/plain; charset=utf-8"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass  # never let logging break the agent


class Tee:
    def __init__(self, stdout, file, send_to_server=True):
        self.stdout = stdout
        self.file = file
        self.send_to_server = send_to_server

    def write(self, data):
        # terminal → colored
        self.stdout.write(data)
        self.stdout.flush()

        clean = ANSI_ESCAPE.sub("", data)
        self.file.write(clean)
        self.file.flush()

        if self.send_to_server:
            for line in clean.splitlines():
                if line.strip():
                    threading.Thread(
                        target=_post_line, args=(line,), daemon=True
                    ).start()

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def isatty(self):
        return self.stdout.isatty()


_log_queue = queue.Queue(maxsize=1000)


def _log_worker():
    while True:
        line = _log_queue.get()
        if line is None:
            break
        _post_line(line)
        _log_queue.task_done()


def init_logging(log_file: str, is_submission_env: bool = False):
    """Capture logs to terminal, file, and remote log server."""
    global LOG_SERVER_URL
    LOG_SERVER_URL = LOG_SERVER_URL if not is_submission_env else None
    if not log_file:
        return

    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    log_f = open(log_file, "a", buffering=1)  # line-buffered
    sys.stdout = Tee(sys.__stdout__, log_f, send_to_server=is_submission_env)
    sys.stderr = Tee(sys.__stderr__, log_f, send_to_server=is_submission_env)
    if is_submission_env:
        _worker_thread = threading.Thread(target=_log_worker, daemon=True)
        _worker_thread.start()


def send_direct_log(line: str, is_submission_env: bool = False):
    """Send a log line directly to the log server, bypassing the Tee."""
    if not is_submission_env:
        return
    try:
        _log_queue.put_nowait(line)
    except queue.Full:
        pass
