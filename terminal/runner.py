"""Process execution engine and output streaming.

Executes security tools safely as isolated subprocesses, streams standard
output and error in real time, and enforces timeouts and process cancellation.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

from storage.models import ExecutionStatus


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProcessExecutionResult:
    command: List[str]
    status: ExecutionStatus
    exit_code: Optional[int]
    stdout: str
    stderr: str
    started_at: str
    finished_at: str
    duration_seconds: float


OutputCallback = Callable[[str, str], None]  # (chunk: str, stream: "stdout"|"stderr")


class ProcessRunner:
    """Manages the isolated execution, streaming, and lifecycle of a process."""

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._is_cancelled: bool = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    def cancel(self) -> bool:
        """Cancel the actively running process."""
        with self._lock:
            if self._process is None or self._process.poll() is not None:
                return False
            self._is_cancelled = True
            try:
                # Terminate the process group to kill child processes as well
                pgid = os.getpgid(self._process.pid)
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                try:
                    self._process.terminate()
                except OSError:
                    pass
            return True

    def run(
        self,
        command: List[str],
        timeout: Optional[float] = None,
        on_output: Optional[OutputCallback] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> ProcessExecutionResult:
        """Execute a command list synchronously, streaming output to callback."""
        if not command or not isinstance(command, list):
            raise ValueError("Command must be a non-empty list of arguments.")

        started_at = _utc_now_iso()
        start_time = time.time()
        self._is_cancelled = False

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []

        # Use start_new_session=True so we can kill process group on cancel
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            cwd=cwd,
            env=env,
            start_new_session=True,
        )

        with self._lock:
            self._process = process

        def _reader(pipe, stream_name: str, collector: List[str]):
            for line in iter(pipe.readline, ""):
                collector.append(line)
                if on_output:
                    try:
                        on_output(line, stream_name)
                    except Exception:
                        pass
            pipe.close()

        stdout_thread = threading.Thread(
            target=_reader, args=(process.stdout, "stdout", stdout_chunks)
        )
        stderr_thread = threading.Thread(
            target=_reader, args=(process.stderr, "stderr", stderr_chunks)
        )

        stdout_thread.start()
        stderr_thread.start()

        status = ExecutionStatus.RUNNING
        timed_out = False

        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            with self._lock:
                try:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    process.kill()

        stdout_thread.join()
        stderr_thread.join()

        duration = round(time.time() - start_time, 3)
        finished_at = _utc_now_iso()

        if self._is_cancelled:
            status = ExecutionStatus.CANCELLED
            exit_code = process.poll() or -1
        elif timed_out:
            status = ExecutionStatus.TIMEOUT
            exit_code = -1
        elif process.returncode == 0:
            status = ExecutionStatus.COMPLETED
            exit_code = 0
        else:
            status = ExecutionStatus.FAILED
            exit_code = process.returncode

        with self._lock:
            self._process = None

        return ProcessExecutionResult(
            command=command,
            status=status,
            exit_code=exit_code,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
        )
