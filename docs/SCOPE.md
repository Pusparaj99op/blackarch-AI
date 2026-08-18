# The scope-gate contract

`scope.yaml` (gitignored, never committed) is the single source of truth for what red-team tools are allowed to touch. `scope.example.yaml` is the committed template.

## Rule

Every tool that acts against a network target — anything other than the local machine — MUST call `blackarch_ai_mcp.scope.is_authorized(target)` as the **first line** of its implementation, and refuse if it returns `False`. This is enforced today in `tools_redteam.py` for `nmap_scan`, `gobuster_dir`, `nikto_scan`, and `hydra_bruteforce`.

Local/defensive tools in `tools_blueteam.py` do not call this — they never touch a third party.

## Adding a Phase 2 tool (sqlmap, aircrack-ng, Metasploit modules, etc.)

Any new tool that reaches outside this machine must:

1. Call `scope.is_authorized(target)` before doing anything else.
2. Raise/return a clear refusal (not a silent no-op) when unauthorized, so the caller (a Skill or a human) knows why nothing happened.
3. Be documented in `docs/TOOLS.md` alongside the existing tools, including its gate behavior.

This keeps enforcement in one function (`scope.py::is_authorized`) rather than reimplemented per-tool.

## Format

```yaml
version: 1
targets:
  - host: 192.168.56.10        # exact IP/hostname, OR:
    cidr: null                 # e.g. "192.168.56.0/24"
    authorized_by: "Jane Doe, CISO of Example Corp"
    authorization_ref: "pentest-agreement-2026-01.pdf"
    expires: "2026-12-31"      # entry stops authorizing after this date
```

`is_authorized()` checks, in order: exact host match, CIDR containment (via `ipaddress`), and that `expires` (if set) has not passed. An empty or missing `scope.yaml`, an unparseable `expires`, or no matching entry all fail closed (not authorized).
