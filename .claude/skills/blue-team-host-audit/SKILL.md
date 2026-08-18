---
name: blue-team-host-audit
description: Local host hardening audit — listening ports vs firewall, SUID/world-writable files, SSH config, and package integrity. No network target required.
allowed-tools: mcp__blackarch-ai__audit_listening_ports, mcp__blackarch-ai__audit_suid_world_writable, mcp__blackarch-ai__lint_ssh_config, mcp__blackarch-ai__audit_pacman_packages, Read, Write
---

# Blue-team host audit

Use this for a defensive self-check of this machine. Purely local — no scope check needed.

1. Call `audit_listening_ports` — flag any listening port that isn't clearly allowed by the firewall rules shown alongside it.
2. Call `audit_suid_world_writable` — flag any SUID binary or world-writable file that looks unexpected (a small known set is normal on Linux; call out anything unfamiliar).
3. Call `lint_ssh_config` — report any finding against the baseline hardening ruleset.
4. Call `audit_pacman_packages` — report orphan packages, pending updates, and any integrity check failures.
5. Produce a pass/fail checklist summarizing all four areas, and write it to `reports/host-audit-<date>.md` (gitignored, never committed).
