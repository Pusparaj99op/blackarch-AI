"""Red-team tool wrappers. Every function here MUST check scope.is_authorized()
for its target as the first thing it does, before touching subprocess_utils.
"""

from __future__ import annotations

from urllib.parse import urlparse

from . import scope
from .subprocess_utils import ToolResult, run_tool

NMAP_PROFILE_ARGS = {
    "quick": ["-T4", "-F"],
    "full_tcp": ["-T4", "-p-"],
    "service": ["-T4", "-sV"],
    "udp": ["-T4", "-sU", "-F"],
}


class NotAuthorizedError(RuntimeError):
    pass


def _require_authorized(target: str) -> None:
    authorized, reason = scope.is_authorized(target)
    if not authorized:
        raise NotAuthorizedError(reason)


def _host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        return parsed.hostname or url_or_host
    return url_or_host


def nmap_scan(target: str, profile: str = "quick") -> ToolResult:
    if profile not in NMAP_PROFILE_ARGS:
        raise ValueError(f"unknown profile '{profile}', expected one of {list(NMAP_PROFILE_ARGS)}")
    _require_authorized(target)
    return run_tool(["nmap", *NMAP_PROFILE_ARGS[profile], target])


def gobuster_dir(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: list[str] | None = None,
) -> ToolResult:
    _require_authorized(_host_of(url))
    args = ["gobuster", "dir", "-u", url, "-w", wordlist]
    if extensions:
        args += ["-x", ",".join(extensions)]
    return run_tool(args)


def nikto_scan(target: str, port: int = 80) -> ToolResult:
    _require_authorized(target)
    return run_tool(["nikto", "-h", target, "-p", str(port)])


def hydra_bruteforce(
    target: str,
    service: str,
    userlist: str,
    passlist: str,
    confirm: bool = False,
) -> ToolResult:
    if not confirm:
        raise ValueError(
            "hydra_bruteforce requires confirm=True as an explicit double opt-in "
            "before attempting credential attacks."
        )
    _require_authorized(target)
    return run_tool(["hydra", "-L", userlist, "-P", passlist, target, service])


def check_scope(target: str) -> str:
    authorized, reason = scope.is_authorized(target)
    return reason
