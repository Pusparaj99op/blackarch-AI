# Tool reference

## Red-team (scope-gated via `scope.yaml`)

| Tool | Wraps | Inputs | Gate |
|---|---|---|---|
| `check_scope` | — (reads `scope.yaml`) | `target` | n/a — this *is* the gate check |
| `nmap_scan` | `nmap` | `target`, `profile: quick\|full_tcp\|service\|udp` | yes |
| `gobuster_dir` | `gobuster dir` | `url`, `wordlist`, `extensions[]` | yes (host parsed from `url`) |
| `nikto_scan` | `nikto` | `target`, `port` | yes |
| `hydra_bruteforce` | `hydra` | `target`, `service`, `userlist`, `passlist`, `confirm` | yes, plus requires `confirm=True` |

## Blue-team (local only, not gated)

| Tool | Wraps | Inputs | Notes |
|---|---|---|---|
| `audit_listening_ports` | `ss -tulnp` + `nft`/`iptables` | — | cross-references ports against firewall rules |
| `audit_suid_world_writable` | `find` | `paths[]` (default `/usr /etc /opt /home`) | SUID (`-perm -4000`) and world-writable (`-perm -0002`) files |
| `review_auth_log` | `journalctl -u sshd` (or `/var/log/auth.log`) | `since` (default `"24 hours ago"`) | |
| `lint_ssh_config` | pure Python file read | `path` (default `/etc/ssh/sshd_config`) | checks against a baseline hardening ruleset |
| `audit_pacman_packages` | `pacman -Qtdq` / `-Qu` / `-Qk` | — | read-only queries only, never `-S`/`-R` |
| `list_installed_tools` | `pacman -Sg` / `-Qq` | — | inventories installed BlackArch security-tool packages by category |
| `crack_hash_offline` | `hashcat` or `john` | `hash_file` (must resolve under `data/hashes/`), `hash_mode`, `wordlist`, `tool` | operates on a user-supplied offline file, not a live target |

## Phase 2 (not yet implemented)

Deferred deliberately — each needs richer input modeling than v1 should rush:

- `sqlmap` — needs injection-point modeling (parameter, method, data), not just a target string.
- `aircrack-ng` — needs wireless interface / monitor-mode state management.
- Metasploit modules — needs exploit/payload selection and session handling.

Any Phase 2 addition must follow the scope-gate contract in `docs/SCOPE.md`.
