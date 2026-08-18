---
name: red-team-web-enum
description: Web application enumeration playbook. Directory brute-force plus a vulnerability scan against an in-scope web target.
allowed-tools: mcp__blackarch-ai__check_scope, mcp__blackarch-ai__gobuster_dir, mcp__blackarch-ai__nikto_scan, Read, Write
---

# Red-team web enumeration

Use this when asked to enumerate a web application that is already known to be in scope (e.g. after `red-team-recon` found an open web port).

1. Call `check_scope` on the target host. **Stop** if not authorized.
2. Call `gobuster_dir` against the target URL to discover paths.
3. Call `nikto_scan` against the target host/port to flag common web vulnerabilities.
4. Summarize discovered paths and flagged issues.
5. Do not suggest or attempt sqlmap or any exploitation — those are out of scope for this project (v1 only wraps recon/enum tools). If SQL injection is suspected from nikto output, report it as a finding for manual follow-up instead of running sqlmap.
6. Write findings to `reports/<target>-webenum-<date>.md` (gitignored, never committed).
