---
name: os-tool-inventory
description: Inventory installed BlackArch security tools on this machine, grouped by category (recon, exploitation, password attacks, wireless, etc.).
allowed-tools: mcp__blackarch-ai__list_installed_tools, Read, Write
---

# OS tool inventory

Use this when asked what security tools are available on this machine, or before recommending a tool for a task (check it's actually installed first).

1. Call `list_installed_tools`.
2. Present the results grouped by BlackArch category as returned (e.g. `blackarch-scanner`, `blackarch-exploitation`, `blackarch-cracker`, `blackarch-wireless`).
3. If the user asks about a specific capability (e.g. "can we do X"), check whether a relevant package appears in the inventory before answering, rather than assuming.
4. This tool only reports what's *installed* — it does not install, remove, or run anything.
