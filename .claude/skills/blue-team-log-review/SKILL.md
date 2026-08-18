---
name: blue-team-log-review
description: Auth log triage — spot brute-force or anomalous SSH login patterns on this local host.
allowed-tools: mcp__blackarch-ai__review_auth_log, Read, Write
---

# Blue-team log review

Use this to triage SSH authentication activity on this machine.

1. Call `review_auth_log` (default: last 24 hours; widen `since` if the user asks for a longer window).
2. Cluster failed login attempts by source IP and target username.
3. Flag any source IP with an unusually high failure count (a handful is normal internet background noise; dozens+ from one IP in a short window is worth flagging).
4. Note whether `fail2ban` (or similar) appears to already be acting on the noisy sources.
5. Summarize findings; write to `reports/log-review-<date>.md` (gitignored, never committed) if the user wants a saved record.
