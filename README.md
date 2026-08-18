# blackarch-AI

A scope-gated MCP server and set of Claude Code Skills for red-team and blue-team security workflows on BlackArch Linux.

## What this is

- **MCP server** (`src/blackarch_ai_mcp/`) — wraps local security tools (nmap, gobuster, nikto, hydra, plus local blue-team audits) as MCP tools, so any MCP-compatible client can call them.
- **Claude Code Skills** (`.claude/skills/`) — markdown playbooks that walk through red-team and blue-team workflows using those tools.

## Safety model: scope-gating

**No red-team tool will run against a target that isn't explicitly authorized.** Every tool that touches a network target (`nmap_scan`, `gobuster_dir`, `nikto_scan`, `hydra_bruteforce`) checks `scope.yaml` first and refuses with a clear message if the target isn't listed with valid, non-expired authorization.

```bash
cp scope.example.yaml scope.yaml
# edit scope.yaml: add host/cidr, authorized_by, authorization_ref, expires
```

`scope.yaml` is gitignored — it's local, never published. See [`docs/SCOPE.md`](docs/SCOPE.md) for the full contract.

Blue-team tools (`audit_listening_ports`, `audit_suid_world_writable`, `review_auth_log`, `lint_ssh_config`, `audit_pacman_packages`, `crack_hash_offline`) are local-only and not gated — they never touch a third party.

**This project does not grant authorization to test anything.** You are responsible for having explicit, written permission before pointing any red-team tool at a target. Unauthorized scanning/exploitation of systems you don't own or have written permission to test is illegal in most jurisdictions.

## Install

```bash
sudo pacman -S --needed python-uv
uv sync
```

## Run the MCP server standalone

```bash
uv run python -m blackarch_ai_mcp.server
```

## Register with Claude Code

```bash
claude mcp add blackarch-ai -- uv --directory /path/to/blackarch-ai run python -m blackarch_ai_mcp.server
```

Then in a Claude Code session, invoke a Skill (e.g. "run a host audit", or `/blue-team-host-audit` if slash-invocation is enabled) or call an `mcp__blackarch-ai__*` tool directly.

## Layout

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit together and [`docs/TOOLS.md`](docs/TOOLS.md) for the full tool reference.

## Tests

```bash
uv run pytest
```

## License

MIT — see [`LICENSE`](LICENSE).
