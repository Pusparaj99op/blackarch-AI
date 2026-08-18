"""Safe subprocess execution for wrapped CLI security tools.

Every tool wrapper in this project MUST go through `run_tool()`. It never
takes a shell string — only a literal argument list — so there is no
command-injection surface from user-supplied fields (targets, wordlists,
etc.) reaching a shell.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

DEFAULT_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 1_000_000  # 1 MB cap per stream, to keep tool results bounded


@dataclass(frozen=True)
class ToolResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool


class ToolNotInstalledError(RuntimeError):
    pass


def require_binary(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise ToolNotInstalledError(
            f"required binary '{name}' was not found on PATH. Is it installed?"
        )
    return path


def _cap(text: str) -> tuple[str, bool]:
    raw = text.encode("utf-8", errors="replace")
    if len(raw) <= MAX_OUTPUT_BYTES:
        return text, False
    return raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace") + "\n...[truncated]", True


def run_tool(args: list[str], timeout: int = DEFAULT_TIMEOUT_SECONDS) -> ToolResult:
    """Run a wrapped CLI tool safely.

    `args` MUST be a literal list (e.g. ["nmap", "-sV", target]) — never a
    string built with f-strings/concatenation, and shell is always disabled.
    """
    if not args:
        raise ValueError("args must be a non-empty list")

    require_binary(args[0])

    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout, stdout_truncated = _cap(proc.stdout)
        stderr, stderr_truncated = _cap(proc.stderr)
        return ToolResult(
            args=args,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            truncated=stdout_truncated or stderr_truncated,
        )
    except subprocess.TimeoutExpired as e:
        stdout, _ = _cap(e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or ""))
        stderr, _ = _cap(e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or ""))
        return ToolResult(
            args=args,
            returncode=-1,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            truncated=False,
        )
