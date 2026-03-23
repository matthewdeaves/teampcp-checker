#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

IS_MACOS=false
[[ "$OSTYPE" == "darwin"* ]] && IS_MACOS=true

# Get file modification date as YYYY-MM-DD (cross-platform)
file_date() {
    if $IS_MACOS; then
        stat -f '%Sm' -t '%Y-%m-%d' "$1" 2>/dev/null
    else
        stat -c '%y' "$1" 2>/dev/null | cut -d' ' -f1
    fi
}

# SHA-256 hash of a file (cross-platform)
sha256_file() {
    if $IS_MACOS; then
        shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    else
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    fi
}

# base64 decode (cross-platform)
b64decode() {
    if $IS_MACOS; then
        base64 -D
    else
        base64 -d
    fi
}

# List python processes with full command line (cross-platform)
python_procs() {
    ps -ax -o pid,command 2>/dev/null | grep -i python | grep -v grep || true
}

FINDINGS=0

pass() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC}  $1"; FINDINGS=$((FINDINGS + 1)); }
fail() { echo -e "${RED}✗${NC} $1"; FINDINGS=$((FINDINGS + 1)); }
info() { echo -e "  ${BOLD}→${NC} $1"; }

GH_USER=$(git config --global github.user 2>/dev/null || true)
if [ -z "$GH_USER" ] && command -v gh &>/dev/null; then
    GH_USER=$(gh api user --jq '.login' 2>/dev/null || true)
fi

echo ""
echo -e "${BOLD}TeamPCP / Trivy Compromise Checker${NC}"
echo "======================================"
echo "Checking: $(hostname) as $(whoami) at $(date -u)"
echo ""

# 1. Trivy version
echo -e "${BOLD}[1] Trivy installation${NC}"
if command -v trivy &>/dev/null; then
    TRIVY_VERSION=$(trivy --version 2>&1 | head -1 | awk '{print $2}')
    TRIVY_PATH=$(command -v trivy)
    TRIVY_MODIFIED=$(file_date "$TRIVY_PATH")
    if [ "$TRIVY_VERSION" = "0.69.4" ]; then
        fail "Trivy v0.69.4 installed — this is the COMPROMISED version"
        info "Path: $TRIVY_PATH"
        info "Modified: $TRIVY_MODIFIED"
    else
        pass "Trivy version $TRIVY_VERSION (not the compromised 0.69.4)"
        info "Path: $TRIVY_PATH | Modified: $TRIVY_MODIFIED"
        # Warn if installed during attack window
        if [ "$TRIVY_MODIFIED" = "2026-03-19" ] || [ "$TRIVY_MODIFIED" = "2026-03-20" ]; then
            warn "Trivy was installed/modified during the attack window (19-20 Mar 2026) — verify integrity"
        fi
    fi
else
    pass "Trivy not installed"
fi
echo ""

# 2. Persistence payloads (Trivy binary + CanisterWorm)
echo -e "${BOLD}[2] Persistence payloads${NC}"
PERSIST_FOUND=false
if [ -f "$HOME/.config/systemd/user/sysmon.py" ]; then
    fail "FOUND: ~/.config/systemd/user/sysmon.py — TeamPCP persistence script (Trivy payload)"
    info "$(ls -la "$HOME/.config/systemd/user/sysmon.py")"
    PERSIST_FOUND=true
fi
if [ -f "$HOME/.local/share/pgmon/service.py" ]; then
    fail "FOUND: ~/.local/share/pgmon/service.py — CanisterWorm backdoor script"
    info "$(ls -la "$HOME/.local/share/pgmon/service.py")"
    PERSIST_FOUND=true
fi
if [ -f "$HOME/.config/systemd/user/pgmon.service" ]; then
    fail "FOUND: ~/.config/systemd/user/pgmon.service — CanisterWorm systemd persistence unit"
    info "$(ls -la "$HOME/.config/systemd/user/pgmon.service")"
    PERSIST_FOUND=true
fi
if [ -f "/tmp/pglog" ]; then
    fail "FOUND: /tmp/pglog — CanisterWorm downloaded payload"
    info "$(ls -la /tmp/pglog)"
    PERSIST_FOUND=true
fi
if [ -f "/tmp/.pg_state" ]; then
    fail "FOUND: /tmp/.pg_state — CanisterWorm state tracking file"
    info "$(ls -la /tmp/.pg_state)"
    PERSIST_FOUND=true
fi
if ! $PERSIST_FOUND; then
    pass "No persistence payloads found (sysmon.py, pgmon/service.py, pglog, .pg_state)"
fi
echo ""

# 3. Systemd user services — show all, flag suspicious ones
echo -e "${BOLD}[3] Systemd user services${NC}"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
if [ -d "$SYSTEMD_USER_DIR" ]; then
    SERVICES=$(find "$SYSTEMD_USER_DIR" -not -type d \( -name "*.service" -o -name "*.timer" \) -not -type l 2>/dev/null || true)
    if [ -z "$SERVICES" ]; then
        pass "No user systemd services found"
    else
        KNOWN_SAFE=("snap.*.service" "snap.*.timer")
        while IFS= read -r svc; do
            BASENAME=$(basename "$svc")
            IS_KNOWN=false
            for safe in "${KNOWN_SAFE[@]}"; do
                # shellcheck disable=SC2254
                case "$BASENAME" in $safe) IS_KNOWN=true; break ;; esac
            done
            if $IS_KNOWN; then
                pass "Known service: $BASENAME"
            else
                warn "Unfamiliar service: $svc"
                info "$(head -5 "$svc" 2>/dev/null)"
            fi
        done <<< "$SERVICES"
    fi
else
    pass "No systemd user directory found"
fi
echo ""

# 4. Exfil archive
echo -e "${BOLD}[4] Exfil archive (tpcp.tar.gz)${NC}"
TPCP=$(find "$HOME" /tmp /var/tmp -maxdepth 3 -name "tpcp.tar.gz" 2>/dev/null || true)
if [ -n "$TPCP" ]; then
    fail "FOUND: tpcp.tar.gz — credential archive created by malware"
    info "$TPCP"
else
    pass "tpcp.tar.gz not found"
fi
echo ""

# 5. GitHub tpcp-docs repo
echo -e "${BOLD}[5] GitHub tpcp-docs repo${NC}"
if [ -n "$GH_USER" ]; then
    SAFE_USER=$(echo "$GH_USER" | tr -cd '[:alnum:]-')
    RESULT=$(curl -s "https://api.github.com/users/$SAFE_USER/repos?per_page=100" | grep -i "tpcp" || true)
    if [ -n "$RESULT" ]; then
        fail "tpcp-docs repo found on GitHub account $GH_USER — malware exfiltrated credentials here"
        info "$RESULT"
    else
        pass "No tpcp-docs repo found for GitHub user $GH_USER"
    fi
else
    warn "Could not determine GitHub username — check manually at https://github.com/<your-user>?tab=repositories for a tpcp-docs repo"
fi
echo ""

# 6. C2 domains in DNS/logs
echo -e "${BOLD}[6] C2 domain contact${NC}"
C2_DOMAINS=("aquasecurtiy" "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io" "plug-tab-protective-relay.trycloudflare.com")
C2_FOUND=false
for domain in "${C2_DOMAINS[@]}"; do
    DNS_HITS=$(grep -r --binary-files=without-match "$domain" /var/log/ 2>/dev/null || true)
    if $IS_MACOS; then
        JOURNAL_HITS=""
    else
        JOURNAL_HITS=$(journalctl --since "2026-03-01" 2>/dev/null | grep -i "$domain" || true)
    fi
    if [ -n "$DNS_HITS" ] || [ -n "$JOURNAL_HITS" ]; then
        fail "Found references to C2 domain $domain in logs"
        [ -n "$DNS_HITS" ] && info "/var/log hit: $(echo "$DNS_HITS" | head -3)"
        [ -n "$JOURNAL_HITS" ] && info "journalctl hit: $(echo "$JOURNAL_HITS" | head -3)"
        C2_FOUND=true
    fi
done
if ! $C2_FOUND; then
    pass "No C2 domain contact found in logs (checked aquasecurtiy.org, ICP canister, Cloudflare tunnel)"
fi
echo ""

# 7. C2 IP in logs
echo -e "${BOLD}[7] C2 IP contact (45.148.10.212)${NC}"
if $IS_MACOS; then
    IP_HITS=""
else
    IP_HITS=$(journalctl --since "2026-03-01" 2>/dev/null | grep "45.148.10.212" || true)
fi
IP_LOG_HITS=$(grep -r --binary-files=without-match "45.148.10.212" /var/log/ 2>/dev/null || true)
if [ -n "$IP_HITS" ] || [ -n "$IP_LOG_HITS" ]; then
    fail "Found connections to C2 IP 45.148.10.212 in logs"
    [ -n "$IP_HITS" ] && info "journalctl: $IP_HITS"
    [ -n "$IP_LOG_HITS" ] && info "/var/log: $IP_LOG_HITS"
else
    pass "No C2 IP contact found in logs"
fi
echo ""

# 8. Suspicious Python processes
echo -e "${BOLD}[8] Suspicious running processes${NC}"
PROC_FOUND=false
SYSMON_PROC=$(python_procs | grep -i "sysmon" || true)
if [ -n "$SYSMON_PROC" ]; then
    fail "sysmon.py Python process is currently running"
    info "$SYSMON_PROC"
    PROC_FOUND=true
fi
PGMON_PROC=$(python_procs | grep -iE "pgmon|\.local/share/pgmon/" || true)
if [ -n "$PGMON_PROC" ]; then
    fail "CanisterWorm pgmon/service.py Python process is currently running"
    info "$PGMON_PROC"
    PROC_FOUND=true
fi
if ! $PROC_FOUND; then
    pass "No sysmon.py or pgmon/service.py processes running"
fi
echo ""

# 9. Local tpcp-docs repo clone
echo -e "${BOLD}[9] Local tpcp-docs repo${NC}"
TPCP_DIR=$(find "$HOME" -maxdepth 4 -type d -name "tpcp-docs" 2>/dev/null || true)
if [ -n "$TPCP_DIR" ]; then
    fail "FOUND: tpcp-docs directory — malware cloned exfil repo locally"
    while IFS= read -r d; do
        info "$d"
    done <<< "$TPCP_DIR"
else
    pass "No tpcp-docs directory found"
fi
echo ""

# 10. Recently modified files in systemd user dir
echo -e "${BOLD}[10] Recent systemd user directory changes${NC}"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
if [ -d "$SYSTEMD_USER_DIR" ]; then
    RECENT=$(find "$SYSTEMD_USER_DIR" -type f -newermt "2026-03-19" 2>/dev/null || true)
    if [ -n "$RECENT" ]; then
        while IFS= read -r f; do
            MOD=$(file_date "$f")
            warn "File modified since 2026-03-19: $f ($MOD)"
        done <<< "$RECENT"
    else
        pass "No files modified since 2026-03-19 in systemd user dir"
    fi
else
    pass "No systemd user directory found"
fi
echo ""

# 11. CanisterWorm npm infection
echo -e "${BOLD}[11] npm global packages (CanisterWorm check)${NC}"
if command -v npm &>/dev/null; then
    NPM_GLOBAL=$(npm list -g --depth=0 2>/dev/null || true)
    SUSPICIOUS_NPM=$(echo "$NPM_GLOBAL" | grep -iE "canister|worm|postinstall" || true)
    if [ -n "$SUSPICIOUS_NPM" ]; then
        fail "Suspicious npm global package found"
        info "$SUSPICIOUS_NPM"
    else
        pass "No suspicious global npm packages"
    fi
    # Check .npm cache for packages modified during attack window
    if [ -d "$HOME/.npm" ]; then
        NPM_RECENT=$(find "$HOME/.npm" -maxdepth 3 -type f \( -newermt "2026-03-19" ! -newermt "2026-03-21" \) 2>/dev/null | head -20 || true)
        if [ -n "$NPM_RECENT" ]; then
            warn "npm cache files modified during attack window (19-20 Mar 2026)"
            info "$(echo "$NPM_RECENT" | wc -l) file(s) — first few:"
            echo "$NPM_RECENT" | head -5 | while IFS= read -r f; do info "$f"; done
        else
            pass "No npm cache files modified during attack window"
        fi
    else
        pass "No .npm cache directory"
    fi
else
    pass "npm not installed"
fi
echo ""

# 12. Unexpected SSH keys
echo -e "${BOLD}[12] SSH keys modified recently${NC}"
if [ -d "$HOME/.ssh" ]; then
    SSH_RECENT=$(find "$HOME/.ssh" -type f -newermt "2026-03-19" 2>/dev/null || true)
    if [ -n "$SSH_RECENT" ]; then
        while IFS= read -r f; do
            MOD=$(file_date "$f")
            warn "SSH file modified since 2026-03-19: $(basename "$f") ($MOD)"
        done <<< "$SSH_RECENT"
    else
        pass "No SSH files modified since 2026-03-19"
    fi
else
    pass "No .ssh directory found"
fi
echo ""

# 13. Unexpected cron jobs
echo -e "${BOLD}[13] Cron jobs${NC}"
CRON_FOUND=false
CRONTAB_OUT=$(crontab -l 2>/dev/null || true)
if [ -n "$CRONTAB_OUT" ]; then
    SUSPICIOUS_CRON=$(echo "$CRONTAB_OUT" | grep -vE '^\s*#|^\s*$' | grep -iE 'python|curl|wget|bash' || true)
    if [ -n "$SUSPICIOUS_CRON" ]; then
        CRON_FOUND=true
        warn "Crontab contains potentially suspicious entries"
        while IFS= read -r line; do info "$line"; done <<< "$SUSPICIOUS_CRON"
    fi
fi
CURRENT_USER=$(whoami)
for crondir in /etc/cron.d /var/spool/cron/crontabs; do
    if [ -d "$crondir" ]; then
        CRON_FILES=$(find "$crondir" -type f -name "$CURRENT_USER" 2>/dev/null || true)
        if [ -n "$CRON_FILES" ]; then
            while IFS= read -r cf; do
                SUSPICIOUS=$(grep -vE '^\s*#|^\s*$' "$cf" 2>/dev/null | grep -iE 'python|curl|wget|bash' || true)
                if [ -n "$SUSPICIOUS" ]; then
                    CRON_FOUND=true
                    warn "Suspicious entry in $cf"
                    while IFS= read -r line; do info "$line"; done <<< "$SUSPICIOUS"
                fi
            done <<< "$CRON_FILES"
        fi
    fi
done
if ! $CRON_FOUND; then
    pass "No suspicious cron jobs found"
fi
echo ""

# 14. Cloud credential files modified recently
echo -e "${BOLD}[14] Cloud credential files${NC}"
CLOUD_FOUND=false
for dir in "$HOME/.aws" "$HOME/.config/gcloud" "$HOME/.azure"; do
    if [ -d "$dir" ]; then
        CLOUD_RECENT=$(find "$dir" -type f -newermt "2026-03-19" 2>/dev/null || true)
        if [ -n "$CLOUD_RECENT" ]; then
            while IFS= read -r f; do
                MOD=$(file_date "$f")
                CLOUD_FOUND=true
                warn "Cloud credential modified since 2026-03-19: $f ($MOD)"
            done <<< "$CLOUD_RECENT"
        fi
    fi
done
if ! $CLOUD_FOUND; then
    pass "No cloud credential files modified since 2026-03-19"
fi
echo ""

# 15. Compromised Docker images
echo -e "${BOLD}[15] Trivy Docker images${NC}"
if command -v docker &>/dev/null; then
    MALICIOUS_IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E "aquasec/trivy:(0\.69\.4|0\.69\.5|0\.69\.6)$" || true)
    if [ -n "$MALICIOUS_IMAGES" ]; then
        fail "Found compromised Trivy Docker image(s)"
        while IFS= read -r img; do info "$img"; done <<< "$MALICIOUS_IMAGES"
    else
        pass "No compromised Trivy Docker images found (checked 0.69.4, 0.69.5, 0.69.6)"
    fi
else
    pass "Docker not installed — skipping image check"
fi
echo ""

# 16. Trivy binary hash verification
echo -e "${BOLD}[16] Trivy binary hash check${NC}"
if command -v trivy &>/dev/null; then
    TRIVY_PATH=$(command -v trivy)
    TRIVY_HASH=$(sha256_file "$TRIVY_PATH")
    KNOWN_BAD=(
        "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0"
        "f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d"
        "bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce143e04bc1113243"
    )
    HASH_MATCH=false
    for bad in "${KNOWN_BAD[@]}"; do
        if [ "$TRIVY_HASH" = "$bad" ]; then
            fail "Trivy binary matches KNOWN MALICIOUS hash: $TRIVY_HASH"
            HASH_MATCH=true
            break
        fi
    done
    if ! $HASH_MATCH; then
        pass "Trivy binary hash does not match known malicious hashes"
        info "SHA256: $TRIVY_HASH"
    fi
else
    pass "Trivy not installed — skipping hash check"
fi
echo ""

# 17. Compromised npm package scopes (CanisterWorm)
echo -e "${BOLD}[17] CanisterWorm compromised npm packages${NC}"
WORM_FOUND=false
COMPROMISED_SCOPES=("@EmilGroup" "@opengov" "@teale.io" "@airtm" "@pypestream")
# Check node_modules in common locations
for search_dir in "$HOME" /tmp /var/tmp; do
    while IFS= read -r nm_dir; do
        for scope in "${COMPROMISED_SCOPES[@]}"; do
            if [ -d "$nm_dir/$scope" ]; then
                fail "Found compromised npm scope $scope in $nm_dir"
                info "$(ls "$nm_dir/$scope" 2>/dev/null)"
                WORM_FOUND=true
            fi
        done
        # Check for deploy.js (CanisterWorm spreader)
        if [ -f "$nm_dir/.cache/deploy.js" ] || find "$nm_dir" -maxdepth 2 -name "deploy.js" -newer "$nm_dir" 2>/dev/null | grep -q deploy; then
            warn "deploy.js found near node_modules — possible CanisterWorm spreader"
            WORM_FOUND=true
        fi
    done < <(find "$search_dir" -maxdepth 4 -type d -name "node_modules" 2>/dev/null | head -20)
done
if ! $WORM_FOUND; then
    pass "No compromised npm package scopes found (@EmilGroup, @opengov, @teale.io, @airtm, @pypestream)"
fi
echo ""

# 18. GitHub Actions workflow references to compromised actions
echo -e "${BOLD}[18] GitHub Actions workflow check${NC}"
WORKFLOW_FOUND=false
while IFS= read -r wf; do
    # Check for trivy-action or setup-trivy pinned to compromised tags (not SHA-pinned)
    TRIVY_ACTION_HIT=$(grep -n "aquasecurity/trivy-action@v\|aquasecurity/setup-trivy@v" "$wf" 2>/dev/null || true)
    if [ -n "$TRIVY_ACTION_HIT" ]; then
        warn "Workflow references trivy-action/setup-trivy by tag (verify pinned to safe commit): $wf"
        while IFS= read -r line; do info "$line"; done <<< "$TRIVY_ACTION_HIT"
        WORKFLOW_FOUND=true
    fi
done < <(find "$HOME" -maxdepth 5 -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" 2>/dev/null | head -50)
if ! $WORKFLOW_FOUND; then
    pass "No GitHub Actions workflows referencing trivy-action/setup-trivy by tag found"
fi
echo ""

# 19. GitHub repos using Trivy in workflows (via API)
echo -e "${BOLD}[19] GitHub repos using Trivy${NC}"
if [ -n "$GH_USER" ] && command -v gh &>/dev/null; then
    TRIVY_REPO_FOUND=false
    while IFS= read -r repo; do
        WORKFLOWS=$(gh api "repos/$GH_USER/$repo/contents/.github/workflows" --jq '.[].name' 2>/dev/null || true)
        for wf in $WORKFLOWS; do
            CONTENT=$(gh api "repos/$GH_USER/$repo/contents/.github/workflows/$wf" --jq '.content' 2>/dev/null | b64decode 2>/dev/null || true)
            if [ -z "$CONTENT" ]; then continue; fi
            # Check for trivy-action/setup-trivy pinned to tag (not SHA)
            TAG_REFS=$(echo "$CONTENT" | grep -n "aquasecurity/trivy-action@v\|aquasecurity/setup-trivy@v" || true)
            if [ -n "$TAG_REFS" ]; then
                fail "$repo/.github/workflows/$wf references trivy by mutable tag — pin to a SHA"
                while IFS= read -r line; do info "$line"; done <<< "$TAG_REFS"
                TRIVY_REPO_FOUND=true
            fi
            # Check for SHA-pinned trivy (informational pass)
            SHA_REFS=$(echo "$CONTENT" | grep -n "aquasecurity/trivy-action@[0-9a-f]\{40\}\|aquasecurity/setup-trivy@[0-9a-f]\{40\}" || true)
            if [ -n "$SHA_REFS" ]; then
                pass "$repo/.github/workflows/$wf — trivy pinned to SHA"
                TRIVY_REPO_FOUND=true
            fi
        done
    done < <(gh repo list "$GH_USER" --limit 100 --json name -q '.[].name' 2>/dev/null)
    if ! $TRIVY_REPO_FOUND; then
        pass "No GitHub repos using trivy-action/setup-trivy found"
    fi
else
    if [ -z "$GH_USER" ]; then
        warn "Could not determine GitHub username — cannot check remote repos"
    else
        warn "gh CLI not installed — cannot check remote repos"
    fi
fi
echo ""

# 20. GitHub account security log
echo -e "${BOLD}[20] GitHub account security log${NC}"
if [ -n "$GH_USER" ]; then
    info "Review your GitHub security log for unexpected activity during the attack window:"
    info "https://github.com/settings/security-log?q=created%3A2026-03-19..2026-03-21"
    info "Look for: new SSH keys, PATs created, OAuth apps authorized, repos created/deleted"
    # Check for SSH keys added during attack window via API
    if command -v gh &>/dev/null; then
        SSH_KEYS=$(gh ssh-key list 2>/dev/null || true)
        if [ -n "$SSH_KEYS" ]; then
            ATTACK_KEYS=$(echo "$SSH_KEYS" | awk '{print $NF}' | grep -E "2026-03-(19|20)" || true)
            if [ -n "$ATTACK_KEYS" ]; then
                fail "GitHub SSH key(s) added during attack window"
                while IFS= read -r k; do info "$k"; done <<< "$(echo "$SSH_KEYS" | grep -E "2026-03-(19|20)" || true)"
            else
                pass "No GitHub SSH keys added during attack window"
            fi
        else
            pass "No GitHub SSH keys found (or gh not authenticated)"
        fi
    else
        warn "gh CLI not installed — cannot check GitHub SSH keys programmatically"
    fi
else
    warn "Could not determine GitHub username — review your security log manually:"
    info "https://github.com/settings/security-log"
fi
echo ""

# Summary
echo "======================================"
if [ "$FINDINGS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}RESULT: No signs of compromise found.${NC}"
else
    echo -e "${RED}${BOLD}RESULT: $FINDINGS potential issue(s) found — review the warnings above.${NC}"
    echo ""
    echo "If any checks FAILED, take these steps immediately:"
    echo "  1. Disconnect the machine from the network"
    echo "  2. Rotate all credentials accessible from this machine:"
    echo "     - GitHub tokens and SSH keys"
    echo "     - AWS/GCP/Azure credentials"
    echo "     - Any API keys or database passwords"
    if [ -n "$GH_USER" ]; then
        echo "  3. Check https://github.com/$GH_USER?tab=repositories for a tpcp-docs repo and delete it"
    else
        echo "  3. Check your GitHub account repositories for a tpcp-docs repo and delete it"
    fi
    echo "  4. Rebuild from a known-good image if fully compromised"
fi
echo ""
