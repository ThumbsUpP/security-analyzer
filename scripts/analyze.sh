#!/usr/bin/env bash
set -euo pipefail

# Security Analyzer for pi Skills
# Analyzes repositories for malicious patterns and unsafe practices

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET=""
DEEP=0
JSON=0
CLONE_TMP=""

declare -a CRITICAL=() HIGH=() MEDIUM=() LOW=() INFO=()

usage() {
    echo "Usage: $0 <repository-url-or-path> [--deep] [--json]"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --deep) DEEP=1; shift ;;
        --json) JSON=1; shift ;;
        -h|--help) usage ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
            else
                echo "Unknown argument: $1" >&2
                usage
            fi
            shift
            ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    usage
fi

cleanup() {
    if [[ -n "$CLONE_TMP" && -d "$CLONE_TMP" ]]; then
        rm -rf "$CLONE_TMP"
    fi
}
trap cleanup EXIT

# Resolve target to local path
resolve_target() {
    local target="$1"
    if [[ -d "$target" ]]; then
        echo "$target"
        return
    fi
    if [[ "$target" =~ ^(https?://|git@) ]]; then
        CLONE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/security-analyzer-XXXXXX")
        echo "Cloning repository..." >&2
        if ! git clone --depth 1 "$target" "$CLONE_TMP/repo" 2>/dev/null; then
            echo "ERROR: Failed to clone repository" >&2
            exit 1
        fi
        echo "$CLONE_TMP/repo"
        return
    fi
    echo "ERROR: Target not found: $target" >&2
    exit 1
}

add_finding() {
    local severity="$1"
    local file="$2"
    local line="$3"
    local desc="$4"
    local entry="[$file:$line] $desc"
    case "$severity" in
        CRITICAL) CRITICAL+=("$entry") ;;
        HIGH)     HIGH+=("$entry") ;;
        MEDIUM)   MEDIUM+=("$entry") ;;
        LOW)      LOW+=("$entry") ;;
        INFO)     INFO+=("$entry") ;;
    esac
}

scan_file() {
    local file="$1"
    local pattern="$2"
    local severity="$3"
    local desc="$4"
    local rel="$5"
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        local line
        line=$(echo "$match" | cut -d: -f2)
        add_finding "$severity" "$rel" "$line" "$desc"
    done < <(grep -nH -E "$pattern" "$file" 2>/dev/null || true)
}

analyze_repo() {
    local repo="$1"
    echo "Scanning: $repo" >&2

    # Validate skill structure
    if [[ ! -f "$repo/SKILL.md" ]]; then
        add_finding "MEDIUM" "SKILL.md" "-" "No SKILL.md found — may not be a valid pi skill"
    fi

    # Gather all text/script files
    local files
    files=$(find "$repo" -type f \( \
        -name "*.sh" -o -name "*.bash" -o -name "*.zsh" -o \
        -name "*.py" -o -name "*.js" -o -name "*.ts" -o \
        -name "*.pl" -o -name "*.rb" -o -name "*.php" -o \
        -name "*.awk" -o -name "*.sed" -o -name "Makefile" -o \
        -name "*.mk" -o -name "SKILL.md" -o -name "*.md" -o \
        -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o \
        -name "*.toml" -o -name "*.ini" -o -name "*.cfg" \
    \) 2>/dev/null || true)

    if [[ -z "$files" ]]; then
        add_finding "INFO" "repo" "-" "No recognizable source files found"
    fi

    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        local rel="${f#$repo/}"

        # === CRITICAL: Destructive commands ===
        scan_file "$f" 'rm\s+-[a-zA-Z]*f.*(/\s*\{|/\*|/[^/]|\$HOME|\$USER|\$PWD|~/)' "CRITICAL" "Dangerous rm command detected" "$rel"
        scan_file "$f" '(mkfs\.|dd\s+if=/dev/zero\s+of=/dev/[sh]d|mkfs\.ext|mkfs\.xfs|newfs|format\s+/dev)' "CRITICAL" "Disk destruction command detected" "$rel"
        scan_file "$f" ':(){ :|:& };:' "CRITICAL" "Fork bomb detected" "$rel"

        # === HIGH: Remote code execution / backdoors ===
        scan_file "$f" '(bash\s+-i\s+>|/bin/sh\s+-i\s+>|python[0-9]?\s+-c.*socket|nc\s+-[eln].*-[0-9]+|ncat.*--listen|python.*pty\.spawn)' "HIGH" "Possible reverse shell / listener" "$rel"
        scan_file "$f" '(/dev/tcp/|/dev/udp/)' "HIGH" "Bash network redirection (potential backdoor)" "$rel"
        scan_file "$f" 'curl.*\|.*(bash|sh|zsh)|wget.*\|.*(bash|sh|zsh)|fetch.*\|.*(bash|sh)' "HIGH" "Pipe from download to shell execution" "$rel"

        # === HIGH: Data exfiltration ===
        scan_file "$f" 'curl.*(-d|--data|--data-binary|-F|--form).*http|wget.*--post-data|curl.*@.*http' "HIGH" "Data exfiltration via curl/wget" "$rel"

        # === MEDIUM: Credential / secret access ===
        scan_file "$f" '\$HOME/\.ssh|~/.ssh|/\.aws/|/\.config/gcloud|/\.kube/config|/\.docker/config\.json|/\.env|/\.netrc|/\.git-credentials' "MEDIUM" "Access to sensitive credential files" "$rel"
        scan_file "$f" '(AWS_ACCESS_KEY|AWS_SECRET_KEY|GITHUB_TOKEN|GITLAB_TOKEN|OPENAI_API_KEY|API_KEY|PASSWORD|SECRET|TOKEN)\b' "MEDIUM" "Environment variable / secret reference" "$rel"

        # === MEDIUM: Obfuscation / eval / exec ===
        scan_file "$f" '\beval\b|\bexec\b' "MEDIUM" "Use of eval/exec (code injection risk)" "$rel"
        scan_file "$f" 'base64\s+-d|base64\s+--decode' "MEDIUM" "Base64 decoding before execution" "$rel"
        scan_file "$f" 'python.*-c.*__import__.*os\.system|python.*-c.*subprocess\.call|python.*-c.*subprocess\.run' "MEDIUM" "Python inline system command execution" "$rel"

        # === MEDIUM: Persistence ===
        scan_file "$f" '(crontab|cron\.|/etc/cron|/var/spool/cron)' "MEDIUM" "Cron / scheduled task manipulation" "$rel"
        scan_file "$f" '(>>\s*~/.bashrc|>>\s*~/.zshrc|>>\s*~/.profile|>>\s*~/.bash_profile)' "MEDIUM" "Shell config modification (persistence)" "$rel"

        # === LOW: Privilege escalation ===
        scan_file "$f" '\bsudo\b' "LOW" "Use of sudo (review necessity)" "$rel"
        scan_file "$f" 'chmod\s+.*[0-9]*[47].*\b|chmod\s+.*\+s' "LOW" "SUID / broad permission change" "$rel"

        # === LOW: Supply chain risks ===
        scan_file "$f" 'npm\s+install\s+git\+|pip\s+install\s+git\+|pip3\s+install\s+git\+' "LOW" "Package install from git URL (supply chain risk)" "$rel"

        # === INFO: Network calls ===
        scan_file "$f" '\bcurl\b|\bwget\b|\bfetch\b' "INFO" "Network download via curl/wget/fetch" "$rel"

        # Shellcheck on shell scripts
        if command -v shellcheck >/dev/null 2>&1; then
            if [[ "$f" =~ \.(sh|bash|zsh)$ ]]; then
                local sc_out
                sc_out=$(shellcheck -f gcc "$f" 2>/dev/null || true)
                if [[ -n "$sc_out" ]]; then
                    while IFS= read -r line; do
                        [[ -z "$line" ]] && continue
                        local sc_line
                        sc_line=$(echo "$line" | grep -oE '^[^:]+:[0-9]+:' | sed 's/:$//' | cut -d: -f2)
                        add_finding "LOW" "$rel" "$sc_line" "Shellcheck warning: $(echo "$line" | sed 's/^[^:]*:[0-9]*://')"
                    done <<< "$sc_out"
                fi
            fi
        fi

        # Deep analysis: high-entropy strings
        if [[ "$DEEP" -eq 1 ]]; then
            while IFS=: read -r lineno content; do
                [[ -z "$lineno" ]] && continue
                add_finding "MEDIUM" "$rel" "$lineno" "Long encoded string (possible obfuscation)"
            done < <(grep -nE '^[^#]*[A-Za-z0-9+/=]{100,}' "$f" 2>/dev/null || true)
        fi

        # File permissions check
        if [[ -x "$f" && "$f" =~ \.(md|txt|json|yaml|yml|toml|ini|cfg)$ ]]; then
            add_finding "LOW" "$rel" "-" "Unusual execute permission on config/text file"
        fi
    done <<< "$files"

    if ! command -v shellcheck >/dev/null 2>&1; then
        add_finding "INFO" "tools" "-" "shellcheck not installed — skipping static analysis"
    fi
}

print_report() {
    local total=$(( ${#CRITICAL[@]} + ${#HIGH[@]} + ${#MEDIUM[@]} + ${#LOW[@]} + ${#INFO[@]} ))

    if [[ "$JSON" -eq 1 ]]; then
        echo "{"
        echo "  \"summary\": {"
        echo "    \"critical\": ${#CRITICAL[@]},"
        echo "    \"high\": ${#HIGH[@]},"
        echo "    \"medium\": ${#MEDIUM[@]},"
        echo "    \"low\": ${#LOW[@]},"
        echo "    \"info\": ${#INFO[@]},"
        echo "    \"total\": $total"
        echo "  },"
        echo "  \"findings\": {"
        local first=1
        for sev in CRITICAL HIGH MEDIUM LOW INFO; do
            local -n arr="$sev"
            [[ "$first" -eq 0 ]] && echo ","
            first=0
            echo -n "    \"$(echo "$sev" | tr '[:upper:]' '[:lower:]')\": ["
            local ffirst=1
            for item in "${arr[@]}"; do
                [[ "$ffirst" -eq 0 ]] && echo -n ", "
                ffirst=0
                printf '"%s"' "$item"
            done
            echo -n "]"
        done
        echo ""
        echo "  }"
        echo "}"
        return
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "              SECURITY ANALYSIS REPORT"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  CRITICAL: ${#CRITICAL[@]}"
    echo "  HIGH:     ${#HIGH[@]}"
    echo "  MEDIUM:   ${#MEDIUM[@]}"
    echo "  LOW:      ${#LOW[@]}"
    echo "  INFO:     ${#INFO[@]}"
    echo ""

    print_section() {
        local title="$1"
        shift
        local arr=("$@")
        if [[ ${#arr[@]} -gt 0 ]]; then
            echo "───────────────────────────────────────────────────────────────"
            echo "  $title"
            echo "───────────────────────────────────────────────────────────────"
            for item in "${arr[@]}"; do
                echo "  • $item"
            done
            echo ""
        fi
    }

    print_section "🔴 CRITICAL" "${CRITICAL[@]}"
    print_section "🟠 HIGH" "${HIGH[@]}"
    print_section "🟡 MEDIUM" "${MEDIUM[@]}"
    print_section "🟢 LOW" "${LOW[@]}"
    print_section "🔵 INFO" "${INFO[@]}"

    if [[ ${#CRITICAL[@]} -gt 0 || ${#HIGH[@]} -gt 0 ]]; then
        echo "═══════════════════════════════════════════════════════════════"
        echo "  ⚠️  VERDICT: DO NOT INSTALL — Critical/High threats found"
        echo "═══════════════════════════════════════════════════════════════"
    elif [[ ${#MEDIUM[@]} -gt 0 ]]; then
        echo "═══════════════════════════════════════════════════════════════"
        echo "  ⚠️  VERDICT: REVIEW CAREFULLY — Suspicious patterns detected"
        echo "═══════════════════════════════════════════════════════════════"
    else
        echo "═══════════════════════════════════════════════════════════════"
        echo "  ✅ VERDICT: No major threats detected (basic scan)"
        echo "═══════════════════════════════════════════════════════════════"
    fi
}

# Main
REPO_PATH=$(resolve_target "$TARGET")
analyze_repo "$REPO_PATH"
print_report

exit 0
