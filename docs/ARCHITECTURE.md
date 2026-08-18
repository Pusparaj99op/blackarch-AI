# Architecture

```
Claude Code session
  │
  ├── .claude/skills/*/SKILL.md  ── workflow playbooks, call MCP tools by name
  │
  └── MCP client ──(stdio)──► blackarch_ai_mcp.server (MCPServer)
                                  │
                                  ├── tools_redteam.py  ── scope.is_authorized() gate ──► subprocess_utils.run_tool() ──► nmap/gobuster/nikto/hydra
                                  │
                                  └── tools_blueteam.py ── (no gate, local only)      ──► subprocess_utils.run_tool() ──► ss/find/journalctl/pacman/hashcat/john
```

- `scope.py` is the single source of truth for authorization. Both the MCP tools and the Skills (via the `check_scope` tool) consult it.
- `subprocess_utils.run_tool()` is the single execution path for every wrapped CLI tool: literal arg lists, `shell=False`, timeouts, output caps, and a `shutil.which()` existence check.
- `server.py` wraps every tool function with `_guarded()`, which turns `NotAuthorizedError`/`ToolNotInstalledError`/`ValueError` into a clear string result instead of an unhandled exception reaching the MCP client.

## Adding a new tool

1. Decide: does it touch a network target (goes in `tools_redteam.py`, must call `scope.is_authorized()` first) or is it local-only (goes in `tools_blueteam.py`)?
2. Implement it using `subprocess_utils.run_tool(["binary", "-flag", value])` — always a literal list.
3. Register it in `server.py` with `@app.tool()`, wrapped in `_guarded(...)`.
4. Document it in `docs/TOOLS.md`.
5. If it's red-team, consider whether a Skill should call it (add/update a `SKILL.md`).
