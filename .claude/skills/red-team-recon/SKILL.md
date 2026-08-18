---
name: red-team-recon
description: Network reconnaissance playbook. Checks authorization scope, runs an nmap sweep against an in-scope target, and summarizes open ports/services.
allowed-tools: mcp__blackarch-ai__check_scope, mcp__blackarch-ai__nmap_scan, Read, Write
---

# Red-team recon

Use this when asked to do initial recon / a port scan against a target.

1. Call `check_scope` with the target. If it comes back not authorized, **stop** and tell the user to add the target to `scope.yaml` (with `authorized_by`, `authorization_ref`, `expires`) before proceeding. Do not attempt the scan anyway.
2. If authorized, call `nmap_scan` with `profile="quick"` first.
3. Summarize open ports and detected services in plain language.
4. If web ports (80, 443, 8080, 8443) are open, suggest following up with the `red-team-web-enum` skill.
5. Write a short findings summary to `reports/<target>-recon-<date>.md` (the `reports/` directory is gitignored — never commit scan output).
