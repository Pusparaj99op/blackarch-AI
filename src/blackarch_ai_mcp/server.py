"""blackarch-ai MCP server entrypoint.

Registers red-team (scope-gated) and blue-team (local, non-gated) tools.
Run with: uv run python -m blackarch_ai_mcp.server
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from . import tools_blueteam, tools_redteam
from .subprocess_utils import ToolNotInstalledError, ToolResult
from .tools_redteam import NotAuthorizedError

app = MCPServer(
    name="blackarch-ai",
    instructions=(
        "Red-team tools require the target to be listed in scope.yaml with "
        "explicit authorization before they will run. Blue-team tools operate "
        "only on this local host and are always available."
    ),
)


def _format_result(result: ToolResult) -> str:
    lines = [f"$ {' '.join(result.args)}", f"(exit code {result.returncode})"]
    if result.timed_out:
        lines.append("[timed out]")
    if result.truncated:
        lines.append("[output truncated]")
    if result.stdout:
        lines.append("--- stdout ---\n" + result.stdout)
    if result.stderr:
        lines.append("--- stderr ---\n" + result.stderr)
    return "\n".join(lines)


def _guarded(fn):
    def wrapper(*args, **kwargs) -> str:
        try:
            result = fn(*args, **kwargs)
        except NotAuthorizedError as e:
            return f"REFUSED (not in scope): {e}"
        except ToolNotInstalledError as e:
            return f"ERROR (missing dependency): {e}"
        except (ValueError, FileNotFoundError) as e:
            return f"ERROR: {e}"
        if isinstance(result, ToolResult):
            return _format_result(result)
        return str(result)

    return wrapper


# --- Red-team (scope-gated) ---


@app.tool()
def check_scope(target: str) -> str:
    """Check whether `target` is authorized in scope.yaml before running any red-team tool."""
    return _guarded(tools_redteam.check_scope)(target)


@app.tool()
def nmap_scan(target: str, profile: str = "quick") -> str:
    """Run an nmap scan against `target` (profile: quick|full_tcp|service|udp). Refuses if target not in scope.yaml."""
    return _guarded(tools_redteam.nmap_scan)(target, profile)


@app.tool()
def gobuster_dir(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: list[str] | None = None) -> str:
    """Directory-brute-force `url` with gobuster. Refuses if the host is not in scope.yaml."""
    return _guarded(tools_redteam.gobuster_dir)(url, wordlist, extensions)


@app.tool()
def nikto_scan(target: str, port: int = 80) -> str:
    """Run a nikto web vulnerability scan against `target`:`port`. Refuses if target not in scope.yaml."""
    return _guarded(tools_redteam.nikto_scan)(target, port)


@app.tool()
def hydra_bruteforce(target: str, service: str, userlist: str, passlist: str, confirm: bool = False) -> str:
    """Credential brute-force `target`/`service` with hydra using local userlist/passlist files.
    Requires confirm=True as an explicit double opt-in, and target must be in scope.yaml."""
    return _guarded(tools_redteam.hydra_bruteforce)(target, service, userlist, passlist, confirm)


# --- Blue-team (local, not gated) ---


@app.tool()
def audit_listening_ports() -> str:
    """List listening ports (ss -tulnp) cross-referenced with firewall rules on this local host."""
    return _guarded(tools_blueteam.audit_listening_ports)()


@app.tool()
def audit_suid_world_writable(paths: list[str] | None = None) -> str:
    """Find SUID and world-writable files under `paths` (default /usr /etc /opt /home) on this local host."""
    return _guarded(tools_blueteam.audit_suid_world_writable)(paths)


@app.tool()
def review_auth_log(since: str = "24 hours ago") -> str:
    """Summarize sshd auth log entries on this local host since `since`."""
    return _guarded(tools_blueteam.review_auth_log)(since)


@app.tool()
def lint_ssh_config(path: str = "/etc/ssh/sshd_config") -> str:
    """Check sshd_config at `path` against a baseline hardening ruleset on this local host."""
    return _guarded(tools_blueteam.lint_ssh_config)(path)


@app.tool()
def list_installed_tools() -> str:
    """Inventory installed BlackArch security-tool packages, grouped by category (recon, exploitation, cracking, etc.)."""
    return _guarded(tools_blueteam.list_installed_tools)()


@app.tool()
def audit_pacman_packages() -> str:
    """Report orphan packages, available updates, and package integrity via pacman (read-only) on this local host."""
    return _guarded(tools_blueteam.audit_pacman_packages)()


@app.tool()
def crack_hash_offline(hash_file: str, hash_mode: str, wordlist: str, tool: str = "hashcat") -> str:
    """Run an offline password-strength audit with hashcat/john against a hash file placed in data/hashes/."""
    return _guarded(tools_blueteam.crack_hash_offline)(hash_file, hash_mode, wordlist, tool)


def main() -> None:
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
