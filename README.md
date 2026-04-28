# 🔐 security-analyzer

A **pi skill** that analyzes code repositories — especially [pi skills](https://github.com/badlogic/pi-skills) — for security threats, malicious patterns, and unsafe practices **before** you install or run them.

> ⚠️ **Never blindly trust code from the internet.** This tool helps you make informed decisions.

---

## 🚀 Quick Start

```bash
# Clone into your pi skills directory
gh repo clone ThumbsUpP/security-analyzer ~/.pi/skills/security-analyzer

# Analyze a remote repository
~/.pi/skills/security-analyzer/scripts/analyze.sh https://github.com/user/suspicious-skill

# Or a local path
~/.pi/skills/security-analyzer/scripts/analyze.sh /path/to/skill --deep

# JSON output for programmatic use
~/.pi/skills/security-analyzer/scripts/analyze.sh https://github.com/user/skill --json
```

---

## 🛡️ What It Detects

| Severity | Threats Detected |
|----------|------------------|
| **🔴 CRITICAL** | `rm -rf /`, fork bombs, disk destruction (`mkfs`, `dd`) |
| **🟠 HIGH** | Reverse shells, `curl \| bash`, `/dev/tcp` backdoors, data exfiltration |
| **🟡 MEDIUM** | Credential access (`~/.ssh`, tokens), `eval`/`exec`, base64 obfuscation, cron persistence, shell config modifications |
| **🟢 LOW** | Unnecessary `sudo`, SUID manipulation, shellcheck warnings, supply-chain installs from git |
| **🔵 INFO** | Network downloads, missing tools, unusual file permissions |

---

## 📋 Usage

```bash
./scripts/analyze.sh <repository-url-or-path> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `--deep` | Enable heuristic obfuscation detection (long encoded strings) |
| `--json` | Output findings as JSON |

### Examples

```bash
# Basic scan
./scripts/analyze.sh https://github.com/StephanOrgiazzi/music-downloader

# Deep scan with JSON output
./scripts/analyze.sh https://github.com/user/skill --deep --json

# Scan a local skill
./scripts/analyze.sh ~/.pi/skills/my-skill
```

---

## 📊 Sample Output

```
═══════════════════════════════════════════════════════════════
              SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════════════════

  CRITICAL: 0
  HIGH:     0
  MEDIUM:   0
  LOW:      0
  INFO:     6

───────────────────────────────────────────────────────────────
  🔵 INFO
───────────────────────────────────────────────────────────────
  • [scripts/lib/binaries/ffmpeg.js:36] Network download via curl/wget/fetch
  • [scripts/lib/binaries/utils.js:23] Network download via curl/wget/fetch
  ...

═══════════════════════════════════════════════════════════════
  ✅ VERDICT: No major threats detected (basic scan)
═══════════════════════════════════════════════════════════════
```

---

## 🔧 How It Works

1. **Fetch** — Clones the repository (or uses local path)
2. **Scan** — Runs regex-based pattern matching across all source files
3. **Analyze** — Categorizes findings by severity with file:line references
4. **Report** — Outputs a verdict:
   - ✅ **SAFE** — No major threats
   - ⚠️ **REVIEW** — Suspicious patterns detected
   - 🔴 **DO NOT INSTALL** — Critical/High threats found

---

## 🧪 Tested On

- pi (Termux / Android)
- Any Unix-like environment with `bash`, `grep`, `find`, `mktemp`

Optional but recommended:
- [`shellcheck`](https://github.com/koalaman/shellcheck) — for static shell script analysis

---

## ⚠️ Limitations

- This is a **static pattern-based scanner**, not a full sandboxed execution analyzer
- It can miss novel obfuscation techniques or runtime-only malicious behavior
- Always combine automated scans with **manual code review** for high-risk code
- The tool itself requires network access to clone remote repositories

---

## 🤝 Contributing

Pull requests welcome! Useful additions:
- More language-specific patterns (Python, Ruby, Go, etc.)
- Integration with VirusTotal or other threat intelligence APIs
- Better obfuscation detection (entropy analysis, AST parsing)
- Support for analyzing npm/pip package dependencies

---

## 📄 License

MIT — use at your own risk. This tool is provided as-is with no warranty.

---

> **"Trust but verify."** 🔍
