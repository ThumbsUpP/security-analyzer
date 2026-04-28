---
name: security-analyzer
description: Analyzes pi skills or code repositories for security threats, malicious patterns, and unsafe practices. Use when asked to review, audit, or check the safety of a skill fetched from GitHub, GitLab, or any remote repository before installing or executing it.
---

# Security Analyzer

Analyzes remote skill repositories for security threats before installation.

## Setup

No external dependencies required. Uses standard Unix tools.

## Usage

```bash
./scripts/analyze.sh <repository-url-or-path> [options]
```

### Options

- `--deep` : Enable deeper analysis (attempts heuristic obfuscation detection)
- `--json` : Output results as JSON

### Examples

```bash
./scripts/analyze.sh https://github.com/user/suspicious-skill
./scripts/analyze.sh /path/to/local/skill --deep
./scripts/analyze.sh https://github.com/user/skill --json
```

## What It Checks

- **Destructive commands**: `rm -rf /`, disk formatting, partition wiping
- **Data exfiltration**: `curl`/`wget` sending data to remote servers, netcat, `/dev/tcp`
- **Credential theft**: Accessing `~/.ssh`, `~/.aws`, env vars, tokens, cookies
- **Execution chains**: `curl | bash`, `base64 -d | bash`, `eval`, `exec`
- **Persistence mechanisms**: Cron jobs, `.bashrc`/`.profile` modifications, startup items
- **Supply chain risks**: npm/pip installs from git URLs or unverified sources
- **Privilege escalation**: Unnecessary `sudo`, SUID manipulation
- **Obfuscation**: Base64 blobs, hex encoding, suspicious Unicode/homoglyphs
- **Network backdoors**: Reverse shells, listeners, tunneling tools
- **Script safety**: Shellcheck on shell scripts (if available)

## Interpreting Results

- **CRITICAL**: Immediate danger — destructive actions, confirmed backdoors, credential theft
- **HIGH**: Serious risk — remote code execution, data exfiltration, privilege escalation
- **MEDIUM**: Suspicious patterns — obfuscation, unsafe curl|bash, credential access
- **LOW**: Best practice violations — missing validation, overly broad permissions
- **INFO**: Observations worth noting — network calls, file system access
