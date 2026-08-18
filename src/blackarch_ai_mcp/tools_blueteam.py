"""Blue-team (local, defensive) tool wrappers.

None of these touch a third party, so they are not scope-gated.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from . import scope as _scope_mod  # noqa: F401  (kept for symmetry / future use)
from .subprocess_utils import ToolResult, run_tool

PROJECT_ROOT = Path(__file__).resolve().parents[2]
HASHES_DIR = PROJECT_ROOT / "data" / "hashes"

SSH_HARDENING_RULES = {
    "PermitRootLogin": {"expected": ("no", "prohibit-password"), "severity": "high"},
    "PasswordAuthentication": {"expected": ("no",), "severity": "medium"},
    "X11Forwarding": {"expected": ("no",), "severity": "low"},
    "Protocol": {"expected": ("2",), "severity": "high"},
}


def audit_listening_ports() -> ToolResult:
    ports = run_tool(["ss", "-tulnp"])
    if shutil.which("nft"):
        firewall = run_tool(["nft", "list", "ruleset"])
    elif shutil.which("iptables"):
        firewall = run_tool(["iptables", "-L", "-n"])
    else:
        firewall = ToolResult(
            args=[], returncode=0, stdout="(no nft/iptables found)", stderr="",
            timed_out=False, truncated=False,
        )
    combined_stdout = (
        "--- listening ports (ss -tulnp) ---\n"
        f"{ports.stdout}\n"
        "--- firewall rules ---\n"
        f"{firewall.stdout}"
    )
    return ToolResult(
        args=ports.args + firewall.args,
        returncode=ports.returncode,
        stdout=combined_stdout,
        stderr=ports.stderr + firewall.stderr,
        timed_out=ports.timed_out or firewall.timed_out,
        truncated=ports.truncated or firewall.truncated,
    )


def audit_suid_world_writable(paths: list[str] | None = None) -> ToolResult:
    paths = paths or ["/usr", "/etc", "/opt", "/home"]
    suid = run_tool(["find", *paths, "-xdev", "-perm", "-4000", "-type", "f"], timeout=120)
    world_writable = run_tool(
        ["find", *paths, "-xdev", "-perm", "-0002", "-type", "f"], timeout=120
    )
    combined_stdout = (
        "--- SUID files ---\n"
        f"{suid.stdout}\n"
        "--- world-writable files ---\n"
        f"{world_writable.stdout}"
    )
    return ToolResult(
        args=suid.args + world_writable.args,
        returncode=max(suid.returncode, world_writable.returncode),
        stdout=combined_stdout,
        stderr=suid.stderr + world_writable.stderr,
        timed_out=suid.timed_out or world_writable.timed_out,
        truncated=suid.truncated or world_writable.truncated,
    )


def review_auth_log(since: str = "24 hours ago") -> ToolResult:
    if shutil.which("journalctl"):
        return run_tool(["journalctl", "-u", "sshd", "--since", since, "--no-pager"])
    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        return run_tool(["tail", "-n", "500", str(auth_log)])
    return ToolResult(
        args=[], returncode=1, stdout="", stderr="no journalctl and no /var/log/auth.log found",
        timed_out=False, truncated=False,
    )


def lint_ssh_config(path: str = "/etc/ssh/sshd_config") -> str:
    config_path = Path(path)
    if not config_path.exists():
        return f"{path} does not exist"

    settings: dict[str, str] = {}
    for line in config_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            settings.setdefault(key, value.strip())

    findings = []
    for key, rule in SSH_HARDENING_RULES.items():
        actual = settings.get(key)
        if actual is None:
            findings.append(f"[{rule['severity']}] {key} not explicitly set (check sshd default)")
        elif actual.lower() not in rule["expected"]:
            findings.append(
                f"[{rule['severity']}] {key} is '{actual}', expected one of {rule['expected']}"
            )
    if not findings:
        return "No issues found against the baseline hardening ruleset."
    return "\n".join(findings)


def audit_pacman_packages() -> ToolResult:
    orphans = run_tool(["pacman", "-Qtdq"])
    updates = run_tool(["pacman", "-Qu"])
    integrity = run_tool(["pacman", "-Qk"], timeout=120)
    combined_stdout = (
        "--- orphan packages (pacman -Qtdq) ---\n"
        f"{orphans.stdout}\n"
        "--- available updates (pacman -Qu) ---\n"
        f"{updates.stdout}\n"
        "--- package integrity (pacman -Qk) ---\n"
        f"{integrity.stdout}"
    )
    return ToolResult(
        args=orphans.args + updates.args + integrity.args,
        returncode=0,
        stdout=combined_stdout,
        stderr=orphans.stderr + updates.stderr + integrity.stderr,
        timed_out=orphans.timed_out or updates.timed_out or integrity.timed_out,
        truncated=orphans.truncated or updates.truncated or integrity.truncated,
    )


def list_installed_tools() -> ToolResult:
    """Inventory of installed BlackArch security-tool packages, grouped by BlackArch category."""
    groups = run_tool(["pacman", "-Sg"], timeout=60)
    blackarch_groups = sorted(
        line.split()[0]
        for line in groups.stdout.splitlines()
        if line.split() and line.split()[0].startswith("blackarch-")
    )

    installed = set(run_tool(["pacman", "-Qq"], timeout=60).stdout.split())

    lines: list[str] = []
    for group in blackarch_groups:
        members = run_tool(["pacman", "-Sg", group], timeout=60)
        pkgs = [line.split()[1] for line in members.stdout.splitlines() if len(line.split()) == 2]
        installed_pkgs = sorted(p for p in pkgs if p in installed)
        if installed_pkgs:
            lines.append(f"{group} ({len(installed_pkgs)} installed): {', '.join(installed_pkgs)}")

    stdout = "\n".join(lines) if lines else "(no blackarch-* package groups found)"
    return ToolResult(
        args=["pacman", "-Sg", "<blackarch-*>"],
        returncode=0,
        stdout=stdout,
        stderr="",
        timed_out=False,
        truncated=False,
    )


def crack_hash_offline(hash_file: str, hash_mode: str, wordlist: str, tool: str = "hashcat") -> ToolResult:
    if tool not in ("hashcat", "john"):
        raise ValueError("tool must be 'hashcat' or 'john'")

    resolved = (HASHES_DIR / Path(hash_file).name).resolve()
    HASHES_DIR.mkdir(parents=True, exist_ok=True)
    if HASHES_DIR.resolve() not in resolved.parents and resolved != HASHES_DIR.resolve():
        raise ValueError(f"hash_file must resolve under {HASHES_DIR}")
    if not resolved.exists():
        raise FileNotFoundError(f"{resolved} does not exist — place hash files under {HASHES_DIR}")

    if tool == "hashcat":
        return run_tool(["hashcat", "-m", hash_mode, "-a", "0", str(resolved), wordlist], timeout=600)
    return run_tool(["john", f"--format={hash_mode}", f"--wordlist={wordlist}", str(resolved)], timeout=600)
