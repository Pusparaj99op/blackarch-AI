---
name: password-hash-review
description: Offline password-hash strength audit against a user-supplied hash file. Never operates on a live target.
allowed-tools: mcp__blackarch-ai__crack_hash_offline, Read, Write
---

# Password hash review

**Guardrail: only ever operate on files the user has deliberately placed in `data/hashes/` for an authorized password-strength audit (e.g. their own exported password database).** This skill never touches a network target, and `crack_hash_offline` refuses any file outside `data/hashes/`.

1. Confirm with the user which file in `data/hashes/` to audit and what hash format it is (e.g. NTLM, bcrypt, SHA-256, /etc/shadow yescrypt).
2. Pick the matching `hash_mode` for hashcat, or `--format` value for john, and choose `tool` accordingly.
3. Call `crack_hash_offline` with a reasonable wordlist (e.g. `/usr/share/wordlists/rockyou.txt` if present).
4. Summarize the ratio of cracked/weak vs. uncracked/strong hashes — do not print recovered plaintext passwords in the summary, just counts and general weakness patterns (e.g. "12 of 40 accounts used a dictionary word").
5. Recommend remediation (password policy, forcing resets for cracked accounts) rather than listing the raw credentials.
