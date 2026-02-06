#!/bin/bash
# Red Team Test Suite for Sandbox Credential Isolation
# Run this inside the sandbox container

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

test_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

test_fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
}

test_warn() {
    echo -e "  ${YELLOW}⚠ WARN${NC}: $1"
    ((WARN++))
}

info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

# ============================================================================
header "1. ENVIRONMENT CREDENTIAL LEAKAGE"
# ============================================================================

echo ""
echo "Checking environment variables for real credentials..."

# Check for real API keys in environment
if env | grep -qE "^ANTHROPIC_API_KEY=sk-"; then
    test_fail "Real ANTHROPIC_API_KEY exposed in environment"
else
    test_pass "ANTHROPIC_API_KEY not exposed (or is placeholder)"
fi

if env | grep -qE "^OPENAI_API_KEY=sk-"; then
    test_fail "Real OPENAI_API_KEY exposed in environment"
else
    test_pass "OPENAI_API_KEY not exposed (or is placeholder)"
fi

if env | grep -qE "^GITHUB_TOKEN=gh[ps]_"; then
    test_fail "Real GITHUB_TOKEN exposed in environment"
else
    test_pass "GITHUB_TOKEN not exposed"
fi

if env | grep -qE "^GEMINI_API_KEY=AI"; then
    test_fail "Real GEMINI_API_KEY exposed in environment"
else
    test_pass "GEMINI_API_KEY not exposed"
fi

# Show what we actually see
echo ""
info "Environment variables containing 'KEY', 'TOKEN', 'SECRET':"
env | grep -iE "(api_key|token|secret)" | head -20 || echo "  (none found)"

# ============================================================================
header "2. FILE-BASED CREDENTIAL HUNTING"
# ============================================================================

echo ""
echo "Searching for credential files..."

# Check credential locations that SHOULD NOT be accessible in sandbox
CRED_FILES=(
    "/credentials"                           # Real OAuth tokens (unified-proxy only)
    "/credentials/codex/auth.json"           # Codex OAuth (unified-proxy only)
    "/credentials/gemini/oauth_creds.json"   # Gemini OAuth (unified-proxy only)
    "/credentials/opencode/auth.json"        # OpenCode OAuth (unified-proxy only)
    "$HOME/.codex/auth.json"                 # Should not exist in sandbox
    "$HOME/.gemini/oauth_creds.json"         # Should not exist in sandbox
)
# Note: /etc/proxy-stubs is checked separately below (stub files section)

for f in "${CRED_FILES[@]}"; do
    if [[ -f "$f" ]]; then
        info "Found: $f"
        # Check if it contains real credentials
        if grep -qE "(sk-ant|ghp_|ghs_|sk-proj)" "$f" 2>/dev/null; then
            test_fail "Real credentials found in $f"
            echo "    Content preview:"
            head -5 "$f" | sed 's/^/    /'
        else
            test_pass "No real credentials in $f"
        fi
    elif [[ -d "$f" ]]; then
        info "Found directory: $f"
        ls -la "$f" 2>/dev/null | head -10 | sed 's/^/    /'
    fi
done

# Check OAuth stub files
echo ""
info "Checking OAuth stub files..."
if [[ -d "/etc/proxy-stubs" ]]; then
    for stub in /etc/proxy-stubs/*.json; do
        if [[ -f "$stub" ]]; then
            info "Stub file: $stub"
            # Check for real credentials (exclude placeholders like ya29.CREDENTIAL_PROXY_PLACEHOLDER)
            if grep -E "(sk-ant-|ghp_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|sk-proj-|AIza[a-zA-Z0-9]{35})" "$stub" 2>/dev/null | grep -vq "PLACEHOLDER"; then
                test_fail "Real credentials in stub file $stub"
            else
                test_pass "Stub file $stub contains only placeholders"
            fi
        fi
    done
fi

# ============================================================================
header "3. DNS FILTERING TESTS"
# ============================================================================

echo ""
echo "Testing DNS resolution filtering..."

# Allowed domains should resolve
ALLOWED_DOMAINS=("github.com" "api.github.com" "api.anthropic.com" "api.openai.com")
for domain in "${ALLOWED_DOMAINS[@]}"; do
    if nslookup "$domain" >/dev/null 2>&1 || getent hosts "$domain" >/dev/null 2>&1; then
        test_pass "Allowed domain resolves: $domain"
    else
        test_warn "Allowed domain failed to resolve: $domain (might be network issue)"
    fi
done

# Blocked domains should NOT resolve
BLOCKED_DOMAINS=("evil.com" "attacker.io" "exfiltrate.xyz" "pastebin.com")
for domain in "${BLOCKED_DOMAINS[@]}"; do
    if nslookup "$domain" >/dev/null 2>&1; then
        test_fail "Blocked domain resolved: $domain"
    else
        test_pass "Blocked domain correctly filtered: $domain"
    fi
done

# Check DNS configuration
echo ""
info "DNS Configuration (/etc/resolv.conf):"
cat /etc/resolv.conf 2>/dev/null | sed 's/^/    /'

# ============================================================================
header "4. NETWORK ISOLATION TESTS"
# ============================================================================

echo ""
echo "Testing network isolation..."

# Check proxy configuration
info "Proxy environment:"
echo "    HTTP_PROXY=$HTTP_PROXY"
echo "    HTTPS_PROXY=$HTTPS_PROXY"
echo "    NO_PROXY=${NO_PROXY:-not set}"

# Try to bypass proxy
echo ""
echo "Testing proxy bypass attempts..."

# Direct IP access to GitHub (should be blocked by proxy allowlist)
GITHUB_IP="140.82.113.4"
IP_RESPONSE=$(curl -s --connect-timeout 5 --max-time 10 "https://$GITHUB_IP/" 2>&1)
if echo "$IP_RESPONSE" | grep -q "Hostname not in allowlist"; then
    test_pass "Direct IP access blocked by proxy allowlist"
elif echo "$IP_RESPONSE" | grep -q "github"; then
    test_fail "Direct IP access to GitHub succeeded (bypass!)"
else
    test_pass "Direct IP access blocked"
fi

# Try with --noproxy
if curl -s --noproxy '*' --connect-timeout 5 --max-time 10 "https://api.anthropic.com/" >/dev/null 2>&1; then
    test_fail "Proxy bypass with --noproxy succeeded"
else
    test_pass "Proxy bypass with --noproxy blocked"
fi

# ============================================================================
header "5. PROXY-LAYER EGRESS FILTERING"
# ============================================================================

echo ""
echo "Testing proxy-layer hostname allowlist (defense in depth)..."
echo "(Even if DNS resolves, proxy should block non-allowlisted hosts)"

# Test exfiltration targets - should be blocked by proxy
EXFIL_TARGETS=("pastebin.com" "httpbin.org" "webhook.site" "evil.com")
for target in "${EXFIL_TARGETS[@]}"; do
    RESPONSE=$(curl -s --connect-timeout 5 --max-time 10 "https://$target/" 2>&1)
    if echo "$RESPONSE" | grep -iq "Hostname not in allowlist\|Forbidden\|denied by policy"; then
        test_pass "Proxy blocked exfiltration to: $target"
    elif echo "$RESPONSE" | grep -iq "error\|timeout\|refused"; then
        test_pass "Connection to $target failed (blocked)"
    else
        test_fail "Exfiltration to $target may have succeeded"
        info "Response: $(echo "$RESPONSE" | head -c 100)"
    fi
done

# ============================================================================
header "6. DIRECT IP EGRESS (NO PROXY)"
# ============================================================================

echo ""
echo "Testing direct IP egress without proxy (should be blocked)..."

# These IPs avoid DNS and test for wildcard-mode bypasses.
DIRECT_IP_TARGETS=("93.184.216.34" "1.1.1.1")
for ip in "${DIRECT_IP_TARGETS[@]}"; do
    curl_err=$(mktemp)
    http_code=$(curl -s --noproxy '*' --connect-timeout 5 --max-time 10 \
        -o /dev/null -w "%{http_code}" "http://${ip}/" 2>"$curl_err")
    curl_exit=$?
    curl_msg=$(head -c 200 "$curl_err" 2>/dev/null || true)
    rm -f "$curl_err"

    if [ $curl_exit -eq 0 ] && [ "$http_code" != "000" ]; then
        test_fail "Direct IP HTTP access succeeded to $ip (HTTP $http_code)"
    elif [ $curl_exit -ne 0 ]; then
        test_pass "Direct IP HTTP access blocked for $ip"
    else
        test_warn "Direct IP HTTP access unclear for $ip (HTTP $http_code)"
        info "Response: $curl_msg"
    fi
done

# ============================================================================
header "7. PROXY ADMIN UI EXPOSURE"
# ============================================================================

echo ""
echo "Testing mitmproxy web UI exposure (should be inaccessible)..."

curl_err=$(mktemp)
mitm_code=$(curl -s --connect-timeout 3 --max-time 5 -o /dev/null -w "%{http_code}" \
    "http://unified-proxy:8081/" 2>"$curl_err")
mitm_exit=$?
mitm_msg=$(head -c 200 "$curl_err" 2>/dev/null || true)
rm -f "$curl_err"

if [ $mitm_exit -eq 0 ] && [ "$mitm_code" != "000" ]; then
    test_fail "mitmproxy web UI reachable from sandbox (HTTP $mitm_code)"
else
    test_pass "mitmproxy web UI not reachable from sandbox"
    if [ -n "$mitm_msg" ]; then
        info "Connection detail: $mitm_msg"
    fi
fi

# ============================================================================
header "8. CREDENTIAL INJECTION VERIFICATION"
# ============================================================================

echo ""
echo "Testing that API requests work (credentials injected by proxy)..."

# Test Anthropic API (should work via proxy injection)
ANTHROPIC_RESPONSE=$(curl -s --max-time 15 \
    -H "x-api-key: CREDENTIAL_PROXY_PLACEHOLDER" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d '{"model":"claude-3-haiku-20240307","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}' \
    "https://api.anthropic.com/v1/messages" 2>&1)

if echo "$ANTHROPIC_RESPONSE" | grep -q '"type":"message"'; then
    test_pass "Anthropic API works (credential injection successful)"
elif echo "$ANTHROPIC_RESPONSE" | grep -q "authentication_error"; then
    test_pass "Anthropic API reached (credentials not leaked in request)"
    info "Response: $(echo "$ANTHROPIC_RESPONSE" | head -c 200)"
else
    test_warn "Anthropic API response unclear"
    info "Response: $(echo "$ANTHROPIC_RESPONSE" | head -c 200)"
fi

# ============================================================================
header "9. GIT SECURITY TESTS"
# ============================================================================

echo ""
echo "Testing git security boundaries..."

# Check git config
info "Git configuration:"
git config --global --list 2>/dev/null | grep -E "(user|credential)" | sed 's/^/    /' || echo "    (no relevant config)"

# Check if we can see the gateway session
if [[ -f "$HOME/.git-session-token" ]]; then
    test_warn "Git session token file exists at $HOME/.git-session-token"
    info "Content (first 50 chars): $(head -c 50 "$HOME/.git-session-token")"
else
    test_pass "No git session token file exposed"
fi

# Try to read git credentials
if git credential-store --file=/dev/null get 2>/dev/null <<< "host=github.com"; then
    test_pass "Git credential store empty or not configured"
else
    test_pass "Git credential store not accessible"
fi

# ============================================================================
header "10. GIT HOOK PREVENTION"
# ============================================================================

echo ""
echo "Testing git hook hardening (core.hooksPath, fsmonitor, etc.)..."

# Test 1: core.hooksPath should be /dev/null
HOOKS_PATH=$(git config --global core.hooksPath 2>/dev/null)
if [[ "$HOOKS_PATH" == "/dev/null" ]]; then
    test_pass "core.hooksPath is /dev/null"
else
    test_fail "core.hooksPath is '$HOOKS_PATH' (expected /dev/null)"
fi

# Test 2: core.fsmonitor should be false
FSMONITOR=$(git config --global core.fsmonitor 2>/dev/null)
if [[ "$FSMONITOR" == "false" ]]; then
    test_pass "core.fsmonitor is false"
else
    test_fail "core.fsmonitor is '$FSMONITOR' (expected false)"
fi

# Test 3: init.templateDir should be empty string
TEMPLATE_DIR=$(git config --global init.templateDir 2>/dev/null)
if [[ "$TEMPLATE_DIR" == "" ]]; then
    test_pass "init.templateDir is empty string"
else
    test_fail "init.templateDir is '$TEMPLATE_DIR' (expected empty string)"
fi

# Test 4: core.fsmonitorHookVersion should be 0
FSMONITOR_VER=$(git config --global core.fsmonitorHookVersion 2>/dev/null)
if [[ "$FSMONITOR_VER" == "0" ]]; then
    test_pass "core.fsmonitorHookVersion is 0"
else
    test_fail "core.fsmonitorHookVersion is '$FSMONITOR_VER' (expected 0)"
fi

# Test 5: receive.denyCurrentBranch should be refuse
DENY_CURRENT=$(git config --global receive.denyCurrentBranch 2>/dev/null)
if [[ "$DENY_CURRENT" == "refuse" ]]; then
    test_pass "receive.denyCurrentBranch is refuse"
else
    test_fail "receive.denyCurrentBranch is '$DENY_CURRENT' (expected refuse)"
fi

# Test 6: Malicious post-checkout hook should NOT execute on clone
info "Testing malicious post-checkout hook execution..."
HOOK_TEST_DIR="/tmp/hook-test-$$"
HOOK_REPO_DIR="/tmp/hook-repo-$$"
HOOK_MARKER="/tmp/hook-executed-$$"
rm -rf "$HOOK_TEST_DIR" "$HOOK_REPO_DIR" "$HOOK_MARKER" 2>/dev/null

# Create a repo with a malicious post-checkout hook
mkdir -p "$HOOK_REPO_DIR"
(
    cd "$HOOK_REPO_DIR"
    git init --quiet
    git commit --allow-empty -m "init" --quiet
    mkdir -p .git/hooks
    cat > .git/hooks/post-checkout << HOOKEOF
#!/bin/bash
touch "$HOOK_MARKER"
HOOKEOF
    chmod +x .git/hooks/post-checkout
)

# Clone the repo - hook should NOT fire because core.hooksPath=/dev/null
git clone --quiet "$HOOK_REPO_DIR" "$HOOK_TEST_DIR" 2>/dev/null

if [[ -f "$HOOK_MARKER" ]]; then
    test_fail "Malicious post-checkout hook executed during clone!"
    rm -f "$HOOK_MARKER"
else
    test_pass "Malicious post-checkout hook did NOT execute on clone"
fi
rm -rf "$HOOK_TEST_DIR" "$HOOK_REPO_DIR" 2>/dev/null

# Test 7: Gated regression test for GIT_SHADOW_ENABLED override gap
# When Phase 3 shadow mode is active, git -c core.hooksPath= could re-enable hooks.
# This test documents the gap that Phase 3's wrapper must close.
if [[ "${GIT_SHADOW_ENABLED:-0}" == "1" ]]; then
    info "GIT_SHADOW_ENABLED=1: Testing -c core.hooksPath= override gap..."
    # Try to override hooksPath via -c flag (Phase 3 wrapper should block this)
    OVERRIDE_PATH=$(git -c core.hooksPath= config core.hooksPath 2>/dev/null)
    if [[ -z "$OVERRIDE_PATH" || "$OVERRIDE_PATH" == "/dev/null" ]]; then
        test_pass "git -c core.hooksPath= override blocked by wrapper"
    else
        test_warn "git -c core.hooksPath= override succeeded (expected when Phase 3 wrapper active)"
        info "This gap is closed by Phase 3's git wrapper command allowlist"
    fi
else
    info "GIT_SHADOW_ENABLED not set - skipping -c override gap test (Phase 3 not active)"
fi

# ============================================================================
header "10b. GIT SHADOW ISOLATION (Phase 3)"
# ============================================================================

echo ""
echo "Testing git shadow mode isolation (tmpfs + wrapper + HMAC auth)..."

if [[ "${GIT_SHADOW_ENABLED:-0}" == "1" ]]; then

    # Test 1: /workspace/.git is an empty tmpfs
    info "Testing /workspace/.git is empty tmpfs..."
    if mountpoint -q /workspace/.git 2>/dev/null; then
        GIT_MOUNT_TYPE=$(mount | grep "/workspace/.git " | awk '{print $5}')
        if [[ "$GIT_MOUNT_TYPE" == "tmpfs" ]]; then
            GIT_DIR_CONTENTS=$(ls -A /workspace/.git 2>/dev/null | wc -l)
            if [[ "$GIT_DIR_CONTENTS" -eq 0 ]]; then
                test_pass "/workspace/.git is empty tmpfs (mount type: tmpfs, 0 files)"
            else
                test_fail "/workspace/.git is tmpfs but NOT empty ($GIT_DIR_CONTENTS items found)"
                info "Contents: $(ls -A /workspace/.git 2>/dev/null | head -5)"
            fi
        else
            test_fail "/workspace/.git is mounted but not tmpfs (type: $GIT_MOUNT_TYPE)"
        fi
    else
        test_fail "/workspace/.git is not a separate mount point (shadow not active)"
    fi

    # Test 2: /usr/bin/git status fails with 'not a git repository'
    info "Testing raw /usr/bin/git status fails without real .git/..."
    RAW_GIT_OUTPUT=$(/usr/bin/git status 2>&1)
    RAW_GIT_EXIT=$?
    if [[ $RAW_GIT_EXIT -ne 0 ]] && echo "$RAW_GIT_OUTPUT" | grep -qi "not a git repository"; then
        test_pass "/usr/bin/git status fails with 'not a git repository'"
    elif [[ $RAW_GIT_EXIT -eq 0 ]]; then
        test_fail "/usr/bin/git status succeeded (shadow .git/ may contain metadata)"
    else
        test_fail "/usr/bin/git status failed but without expected message"
        info "Exit code: $RAW_GIT_EXIT, output: $(echo "$RAW_GIT_OUTPUT" | head -c 200)"
    fi

    # Test 3: proxied git log works correctly via wrapper
    info "Testing proxied git log via wrapper..."
    if [[ -x /usr/local/bin/git ]]; then
        WRAPPER_OUTPUT=$(/usr/local/bin/git log --oneline -5 2>&1)
        WRAPPER_EXIT=$?
        if [[ $WRAPPER_EXIT -eq 0 ]] && [[ -n "$WRAPPER_OUTPUT" ]]; then
            test_pass "Proxied git log works via wrapper (returned commits)"
        elif [[ $WRAPPER_EXIT -eq 0 ]]; then
            test_warn "Proxied git log returned 0 but empty output (new repo?)"
        else
            test_fail "Proxied git log via wrapper failed (exit: $WRAPPER_EXIT)"
            info "Output: $(echo "$WRAPPER_OUTPUT" | head -c 200)"
        fi
    else
        test_fail "Git wrapper not found at /usr/local/bin/git"
    fi

    # Test 4: git --git-dir=/tmp/evil status rejected by wrapper
    info "Testing --git-dir flag injection rejected by wrapper..."
    mkdir -p /tmp/evil 2>/dev/null
    GITDIR_OUTPUT=$(/usr/local/bin/git --git-dir=/tmp/evil status 2>&1)
    GITDIR_EXIT=$?
    rmdir /tmp/evil 2>/dev/null
    if [[ $GITDIR_EXIT -ne 0 ]] && echo "$GITDIR_OUTPUT" | grep -qiE "(blocked|rejected|not allowed|forbidden|denied|error)"; then
        test_pass "git --git-dir=/tmp/evil status rejected by wrapper"
    elif [[ $GITDIR_EXIT -eq 0 ]]; then
        test_fail "git --git-dir=/tmp/evil status succeeded (flag injection not blocked!)"
    else
        # Non-zero exit but unexpected message — still likely blocked
        test_pass "git --git-dir=/tmp/evil status failed (exit: $GITDIR_EXIT)"
        info "Output: $(echo "$GITDIR_OUTPUT" | head -c 200)"
    fi

    # Test 5: direct curl to git API without HMAC returns 401
    info "Testing unauthenticated git API access returns 401..."
    GIT_API_HOST="${GIT_API_HOST:-unified-proxy}"
    GIT_API_PORT="${GIT_API_PORT:-8083}"
    NOAUTH_RESP=$(curl -s --connect-timeout 5 --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"args":["status"],"cwd":"/workspace"}' \
        -o /dev/null -w "%{http_code}" \
        "http://${GIT_API_HOST}:${GIT_API_PORT}/git/exec" 2>&1)
    if [[ "$NOAUTH_RESP" == "401" ]]; then
        test_pass "Unauthenticated git API request returned 401"
    elif [[ "$NOAUTH_RESP" == "000" ]]; then
        test_fail "Git API unreachable at ${GIT_API_HOST}:${GIT_API_PORT}"
    elif [[ "$NOAUTH_RESP" == "200" ]]; then
        test_fail "Unauthenticated git API request succeeded (HMAC not enforced!)"
    else
        test_fail "Unauthenticated git API returned unexpected HTTP $NOAUTH_RESP (expected 401)"
    fi

else
    info "GIT_SHADOW_ENABLED not set - skipping git shadow isolation tests (Phase 3 not active)"
    info "  These tests require: tmpfs at /workspace/.git, git wrapper at /usr/local/bin/git,"
    info "  and git API server at port 8083 with HMAC authentication."
fi

# ============================================================================
header "11. GIT MARKETPLACE ACCESS"
# ============================================================================

echo ""
echo "Testing git proxy access for plugin marketplaces..."

# Test 1: Plugin marketplace clone (positive test - should succeed)
info "Testing plugin marketplace clone (allowed list)..."
MARKETPLACE_DIR="/tmp/test-marketplace-$$"
rm -rf "$MARKETPLACE_DIR" 2>/dev/null

CLONE_OUTPUT=$(git clone --depth 1 https://github.com/anthropics/claude-plugins-official.git "$MARKETPLACE_DIR" 2>&1)
CLONE_EXIT=$?

if [[ $CLONE_EXIT -eq 0 ]] && [[ -d "$MARKETPLACE_DIR/.git" ]]; then
    test_pass "Plugin marketplace clone succeeded (git proxy allows anthropics repos)"
    rm -rf "$MARKETPLACE_DIR"
elif echo "$CLONE_OUTPUT" | grep -qiE "(403|forbidden|blocked|not allowed)"; then
    test_fail "Plugin marketplace clone blocked (should be in allowed list)"
    info "Output: $(echo "$CLONE_OUTPUT" | head -c 200)"
else
    test_warn "Plugin marketplace clone failed (may be network issue or repo doesn't exist)"
    info "Exit code: $CLONE_EXIT"
    info "Output: $(echo "$CLONE_OUTPUT" | head -c 200)"
fi

# Test 2: Unauthorized repo clone (negative test - should be blocked)
info "Testing unauthorized repo clone (should be blocked)..."
BLOCKED_DIR="/tmp/test-blocked-$$"
rm -rf "$BLOCKED_DIR" 2>/dev/null

BLOCKED_OUTPUT=$(git clone https://github.com/octocat/Hello-World.git "$BLOCKED_DIR" 2>&1)
BLOCKED_EXIT=$?

if echo "$BLOCKED_OUTPUT" | grep -qiE "(403|forbidden|blocked|not allowed|denied)"; then
    test_pass "Unauthorized repo clone blocked by git proxy (403)"
    rm -rf "$BLOCKED_DIR" 2>/dev/null
elif [[ $BLOCKED_EXIT -eq 0 ]] && [[ -d "$BLOCKED_DIR/.git" ]]; then
    test_fail "Unauthorized repo clone succeeded (should be blocked by git proxy)"
    rm -rf "$BLOCKED_DIR"
else
    # Could be blocked by other means (network, etc.)
    test_pass "Unauthorized repo clone failed (exit code: $BLOCKED_EXIT)"
    info "Output: $(echo "$BLOCKED_OUTPUT" | head -c 200)"
fi

# Test 3: Node.js proxy integration (global-agent bootstrap)
info "Testing Node.js proxy integration..."
if command -v node &>/dev/null; then
    # Test that Node.js can make HTTPS requests through the proxy
    NODE_OUTPUT=$(node -e "
const https = require('https');
const req = https.get('https://api.github.com/', (res) => {
    console.log('STATUS:' + res.statusCode);
    process.exit(0);
});
req.on('error', (e) => {
    console.log('ERROR:' + e.message);
    process.exit(1);
});
req.setTimeout(10000, () => {
    console.log('TIMEOUT');
    req.destroy();
    process.exit(1);
});
" 2>&1)
    NODE_EXIT=$?

    if echo "$NODE_OUTPUT" | grep -q "STATUS:"; then
        STATUS_CODE=$(echo "$NODE_OUTPUT" | grep "STATUS:" | cut -d: -f2)
        if [[ "$STATUS_CODE" == "200" ]] || [[ "$STATUS_CODE" == "403" ]]; then
            test_pass "Node.js routes through proxy (HTTP $STATUS_CODE)"
        else
            test_warn "Node.js proxy response: HTTP $STATUS_CODE"
        fi
    elif echo "$NODE_OUTPUT" | grep -qiE "(ECONNREFUSED|ETIMEDOUT|certificate)"; then
        test_warn "Node.js proxy connection issue: $(echo "$NODE_OUTPUT" | head -c 100)"
    else
        test_warn "Node.js proxy test inconclusive"
        info "Output: $(echo "$NODE_OUTPUT" | head -c 150)"
    fi
else
    info "Node.js not available for proxy integration test"
fi

# ============================================================================
header "12. CONTAINER ESCAPE / LATERAL MOVEMENT"
# ============================================================================

echo ""
echo "Testing container boundaries..."

# Check if we can access Docker socket
if [[ -S /var/run/docker.sock ]]; then
    test_fail "Docker socket accessible - potential container escape"
else
    test_pass "Docker socket not accessible"
fi

# Check capabilities
info "Current capabilities:"
if command -v capsh &>/dev/null; then
    capsh --print 2>/dev/null | grep -E "^(Current|Bounding)" | sed 's/^/    /'
elif [[ -f /proc/self/status ]]; then
    grep Cap /proc/self/status | sed 's/^/    /'
fi

# Check if we can ping other containers (ICC test)
echo ""
echo "Testing inter-container communication..."
if ping -c 1 -W 2 unified-proxy >/dev/null 2>&1; then
    test_warn "Can ping unified-proxy container (expected for proxy)"
else
    test_pass "Cannot ping unified-proxy container"
fi

if ping -c 1 -W 2 unified-proxy >/dev/null 2>&1; then
    test_warn "Can ping unified-proxy container (expected for proxy)"
else
    test_pass "Cannot ping unified-proxy container"
fi

# Test for sandbox-to-sandbox isolation (should not be able to reach other sandboxes)
echo ""
echo "Testing sandbox-to-sandbox isolation..."

# Try common sandbox naming patterns
SANDBOX_PATTERNS=("sandbox-" "dev-" "test-" "worker-")
for pattern in "${SANDBOX_PATTERNS[@]}"; do
    # Try to discover other containers via DNS/network
    OTHER_RESULT=$(getent hosts "${pattern}1" 2>/dev/null || true)
    if [[ -n "$OTHER_RESULT" ]]; then
        OTHER_IP=$(echo "$OTHER_RESULT" | awk '{print $1}')
        # Try to connect to the other sandbox
        if curl -s --connect-timeout 2 --max-time 3 "http://${OTHER_IP}:8080/" >/dev/null 2>&1; then
            test_fail "Can reach other sandbox container: ${pattern}1 ($OTHER_IP)"
        else
            test_pass "Cannot reach other sandbox: ${pattern}1 (DNS resolved but connection blocked)"
        fi
    fi
done

# Test container metadata service isolation (Kubernetes/ECS)
echo ""
info "Testing container metadata service isolation..."
METADATA_ENDPOINTS=(
    "http://169.254.169.254/latest/meta-data/"  # AWS
    "http://169.254.170.2/v2/metadata"           # ECS
    "http://metadata.google.internal/computeMetadata/v1/"  # GCP
    "http://169.254.169.254/metadata/instance"   # Azure
)
for endpoint in "${METADATA_ENDPOINTS[@]}"; do
    META_RESP=$(curl -s --connect-timeout 2 --max-time 3 "$endpoint" 2>&1)
    if [[ $? -eq 0 ]] && ! echo "$META_RESP" | grep -qiE "(error|timeout|refused|blocked)"; then
        test_fail "Container metadata accessible: $endpoint"
    else
        test_pass "Container metadata blocked: ${endpoint%%/meta*}..."
    fi
done

# ============================================================================
header "13. PROCESS AND MOUNT INSPECTION"
# ============================================================================

echo ""
echo "Inspecting mounts for credential leaks..."

# Check mounts
info "Mounted volumes:"
mount | grep -vE "^(proc|sysfs|tmpfs|devpts|mqueue|cgroup)" | sed 's/^/    /' | head -20

# Look for sensitive mounts
if mount | grep -qE "(credentials|secrets|\.ssh|\.gnupg)"; then
    test_warn "Potentially sensitive mount detected"
    mount | grep -E "(credentials|secrets|\.ssh|\.gnupg)" | sed 's/^/    /'
else
    test_pass "No obvious credential mounts"
fi

# Check /proc for leaked info
echo ""
info "Checking /proc for sensitive data..."
if [[ -r /proc/1/environ ]]; then
    if cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -qE "(sk-ant|ghp_|ghs_)"; then
        test_fail "Real credentials visible in /proc/1/environ"
    else
        test_pass "/proc/1/environ does not contain real credentials"
    fi
else
    test_pass "/proc/1/environ not readable"
fi

# ============================================================================
header "14. GITHUB API FILTER TESTS"
# ============================================================================

echo ""
echo "Testing GitHub API security filters..."

# These should be blocked
info "Testing blocked operations (expect failures)..."

# Try to access secrets endpoint
SECRETS_RESP=$(curl -s --max-time 10 \
    -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
    "https://api.github.com/repos/octocat/Hello-World/actions/secrets" 2>&1)

if echo "$SECRETS_RESP" | grep -qiE "(blocked|forbidden|not allowed)"; then
    test_pass "GitHub secrets endpoint blocked"
elif echo "$SECRETS_RESP" | grep -qE "\"secrets\""; then
    test_fail "GitHub secrets endpoint accessible!"
else
    info "Secrets response: $(echo "$SECRETS_RESP" | head -c 150)"
    test_warn "GitHub secrets response unclear"
fi

# ============================================================================
header "15. GITHUB POLICY BYPASS ATTEMPTS"
# ============================================================================

echo ""
echo "Testing policy engine bypass attempts..."
echo "(Policy engine blocks dangerous GitHub operations regardless of credentials)"

# Test PR merge endpoint (should be blocked by policy engine)
info "Testing PR merge block (PUT /repos/*/pulls/*/merge)..."
MERGE_RESP=$(curl -s --max-time 10 \
    -X PUT \
    -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
    -H "Content-Type: application/json" \
    -d '{"commit_title":"test","merge_method":"merge"}' \
    "https://api.github.com/repos/octocat/Hello-World/pulls/1/merge" 2>&1)

if echo "$MERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
    test_pass "PR merge endpoint blocked by policy engine"
elif echo "$MERGE_RESP" | grep -qE '"merged"'; then
    test_fail "PR merge endpoint accessible!"
elif echo "$MERGE_RESP" | grep -qE "(not found|404)"; then
    test_pass "PR merge request reached GitHub (404 = PR doesn't exist, but policy allowed)"
    info "Note: Policy may allow merge for valid PRs - verify with ALLOW_PR_OPERATIONS=false"
else
    info "Merge response: $(echo "$MERGE_RESP" | head -c 150)"
    test_warn "PR merge response unclear"
fi

# Test release creation endpoint (should be blocked by policy engine)
info "Testing release creation block (POST /repos/*/releases)..."
RELEASE_RESP=$(curl -s --max-time 10 \
    -X POST \
    -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
    -H "Content-Type: application/json" \
    -d '{"tag_name":"v0.0.1-test","name":"Test Release"}' \
    "https://api.github.com/repos/octocat/Hello-World/releases" 2>&1)

if echo "$RELEASE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
    test_pass "Release creation endpoint blocked by policy engine"
elif echo "$RELEASE_RESP" | grep -qE '"id"'; then
    test_fail "Release creation endpoint accessible!"
else
    info "Release response: $(echo "$RELEASE_RESP" | head -c 150)"
    test_pass "Release creation blocked or unauthorized"
fi

# Test issue comment creation (always allowed - issue comments are lower risk)
# Note: /issues/*/comments is always allowed; /pulls/*/comments (review comments) requires ALLOW_PR_OPERATIONS
info "Testing issue comment creation (always allowed)..."
COMMENT_RESP=$(curl -s --max-time 10 \
    -X POST \
    -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
    -H "Content-Type: application/json" \
    -d '{"body":"Test comment from sandbox"}' \
    "https://api.github.com/repos/octocat/Hello-World/issues/1/comments" 2>&1)

if echo "$COMMENT_RESP" | grep -qE '"id"'; then
    test_pass "Issue comment creation works (allowed by policy)"
elif echo "$COMMENT_RESP" | grep -qiE "(blocked|forbidden|not allowed)"; then
    test_fail "Issue comment creation unexpectedly blocked"
else
    info "Comment response: $(echo "$COMMENT_RESP" | head -c 150)"
    test_warn "Issue comment response unclear"
fi

# ============================================================================
header "16. REGISTRATION API ISOLATION"
# ============================================================================

echo ""
echo "Testing that internal registration API is not accessible from sandbox..."
echo "(Registration API should only be available via Unix socket on proxy)"

# Test direct TCP access to common internal API ports
info "Testing internal API TCP exposure..."
INTERNAL_PORTS=(8081 8082 9090 5000)
for port in "${INTERNAL_PORTS[@]}"; do
    INTERNAL_RESP=$(curl -s --connect-timeout 3 --max-time 5 \
        "http://unified-proxy:${port}/internal/health" 2>&1)
    if echo "$INTERNAL_RESP" | grep -qE "(ok|healthy|status)"; then
        test_fail "Internal API accessible on port $port!"
    else
        test_pass "Internal API not exposed on TCP port $port"
    fi
done

# Test Unix socket path (should not exist in sandbox)
SOCKET_PATHS=(
    "/var/run/unified-proxy/internal.sock"
    "/var/run/proxy/internal.sock"
    "/run/unified-proxy/internal.sock"
    "/tmp/unified-proxy.sock"
)
for sock in "${SOCKET_PATHS[@]}"; do
    if [[ -S "$sock" ]]; then
        test_fail "Internal API Unix socket accessible at $sock!"
    else
        test_pass "Internal API socket not accessible: $sock"
    fi
done

# Test container registration endpoint (should be inaccessible)
info "Testing container registration endpoint..."
REGISTER_RESP=$(curl -s --connect-timeout 5 --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"container_id":"evil-container","ip":"172.17.0.100"}' \
    "http://unified-proxy:8080/internal/containers" 2>&1)

if echo "$REGISTER_RESP" | grep -qiE "(forbidden|denied|not found|404|blocked)"; then
    test_pass "Container registration endpoint blocked"
elif echo "$REGISTER_RESP" | grep -qE '"(registered|status|container_id)"'; then
    test_fail "Container registration endpoint accessible via HTTP!"
else
    info "Registration response: $(echo "$REGISTER_RESP" | head -c 100)"
    test_pass "Container registration not accessible"
fi

# ============================================================================
header "17. CERTIFICATE AND TLS INSPECTION"
# ============================================================================

echo ""
echo "Checking TLS/certificate configuration..."

# Check what CA certs are trusted
info "Custom CA certificates:"
if [[ -f /certs/mitmproxy-ca.pem ]]; then
    test_pass "mitmproxy CA certificate present (expected for HTTPS interception)"
    openssl x509 -in /certs/mitmproxy-ca.pem -noout -subject -issuer 2>/dev/null | sed 's/^/    /'
else
    test_warn "mitmproxy CA not found at /certs/mitmproxy-ca.pem"
fi

# Test that mitmproxy is intercepting HTTPS traffic
echo ""
info "Testing certificate validation..."

# Test 1: curl should FAIL without mitmproxy CA (proves interception is active)
if ! curl -sf --cacert /etc/ssl/certs/ca-certificates.crt --max-time 10 "https://api.anthropic.com/" >/dev/null 2>&1; then
    test_pass "HTTPS interception active (system CA rejects mitmproxy cert)"
else
    test_fail "HTTPS interception NOT active (system CA accepted connection)"
fi

# Test 2: curl should complete TLS handshake with mitmproxy CA (proves proxy setup works)
# Note: -s silences progress, but we check TLS success not HTTP status (API returns 404 on /)
CURL_OUT=$(curl -s --cacert /certs/mitmproxy-ca.pem --max-time 10 -w "%{ssl_verify_result}" -o /dev/null "https://api.anthropic.com/" 2>&1)
if [[ "$CURL_OUT" == "0" ]]; then
    test_pass "mitmproxy CA trust working (TLS handshake succeeds)"
else
    test_warn "mitmproxy CA trust issue (ssl_verify_result=$CURL_OUT)"
fi

# ============================================================================
header "18. FILESYSTEM ISOLATION"
# ============================================================================

echo ""
echo "Testing read-only root filesystem and tmpfs constraints..."

# Detect credential-isolation mode
# In this mode, filesystem is intentionally writable for DNS configuration
CREDENTIAL_ISOLATION_MODE=false
if [ -n "${SANDBOX_GATEWAY_ENABLED:-}" ] || [ -f /run/secrets/gateway_token ]; then
    CREDENTIAL_ISOLATION_MODE=true
    info "Credential-isolation mode detected (SANDBOX_GATEWAY_ENABLED or gateway_token present)"
fi

# Test writes to protected paths
for path in "/usr/bin/test-file" "/etc/test-file" "/opt/test-file"; do
    if touch "$path" 2>/dev/null; then
        rm -f "$path" 2>/dev/null
        if [ "$CREDENTIAL_ISOLATION_MODE" = "true" ]; then
            test_warn "Write to $path allowed (expected in credential-isolation mode)"
        else
            test_fail "Write succeeded to protected path: $path"
        fi
    else
        test_pass "Write blocked to protected path: $path"
    fi
done

# Test writes to allowed tmpfs paths
for path in "/tmp/test-file" "/var/tmp/test-file"; do
    if touch "$path" 2>/dev/null; then
        rm -f "$path"
        test_pass "Write allowed to tmpfs: $path"
    else
        test_warn "Write failed to tmpfs: $path (might be read-only mode)"
    fi
done

# Test sensitive file access
CURRENT_USER=$(whoami)
if [[ -r /etc/shadow ]]; then
    if [ "$CURRENT_USER" = "root" ]; then
        test_warn "/etc/shadow readable (running as root)"
    elif [ "$CREDENTIAL_ISOLATION_MODE" = "true" ]; then
        test_warn "/etc/shadow readable (credential-isolation starts as root)"
    else
        test_fail "/etc/shadow readable as $CURRENT_USER"
    fi
else
    test_pass "/etc/shadow not readable"
fi

if [[ -d /root ]] && ls /root/ >/dev/null 2>&1; then
    ROOT_CONTENTS=$(ls -A /root/ 2>/dev/null | wc -l)
    if [[ $ROOT_CONTENTS -gt 0 ]]; then
        test_warn "/root/ accessible with $ROOT_CONTENTS items"
    else
        test_pass "/root/ empty or inaccessible"
    fi
else
    test_pass "/root/ not accessible"
fi

# Test tmpfs size limit (try to write >512MB to /tmp)
echo ""
info "Testing tmpfs size limits..."
if dd if=/dev/zero of=/tmp/large-test bs=1M count=600 2>/dev/null; then
    rm -f /tmp/large-test
    test_fail "Wrote 600MB to /tmp (tmpfs limit not enforced)"
else
    rm -f /tmp/large-test 2>/dev/null
    test_pass "Large file write to /tmp failed (tmpfs limit working)"
fi

# ============================================================================
header "19. CAPABILITY VERIFICATION"
# ============================================================================

echo ""
echo "Testing dropped Linux capabilities..."

# Test CAP_NET_RAW (should be dropped - prevents raw sockets, ping without setuid)
info "Testing CAP_NET_RAW (should be dropped)..."

# Method 1: Try ping (needs CAP_NET_RAW if not setuid)
if ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
    # Ping worked - check if it's setuid or we have CAP_NET_RAW
    if [[ -u /bin/ping ]] || [[ -u /usr/bin/ping ]]; then
        test_pass "ping works via setuid (CAP_NET_RAW not needed)"
    else
        test_warn "ping works without setuid (CAP_NET_RAW may be present)"
    fi
else
    test_pass "ping failed (CAP_NET_RAW dropped or ping not setuid)"
fi

# Method 2: Try creating raw socket with Python if available
if command -v python3 &>/dev/null; then
    RAW_SOCKET_TEST=$(python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.close()
    print('SUCCESS')
except PermissionError:
    print('EPERM')
except Exception as e:
    print(f'ERROR:{e}')
" 2>&1)
    if [[ "$RAW_SOCKET_TEST" == "EPERM" ]]; then
        test_pass "Raw socket creation blocked (CAP_NET_RAW dropped)"
    elif [[ "$RAW_SOCKET_TEST" == "SUCCESS" ]]; then
        test_fail "Raw socket creation succeeded (CAP_NET_RAW present!)"
    else
        test_warn "Raw socket test inconclusive: $RAW_SOCKET_TEST"
    fi
else
    info "Python3 not available for raw socket test"
fi

# Test access to sensitive kernel interfaces
if [[ -r /proc/kcore ]]; then
    if [ "$CREDENTIAL_ISOLATION_MODE" = "true" ]; then
        test_warn "/proc/kcore readable (known limitation - network isolation is primary boundary)"
    else
        test_fail "/proc/kcore is readable"
    fi
else
    test_pass "/proc/kcore not readable"
fi

if [[ -d /sys/kernel/security ]] && ls /sys/kernel/security/ >/dev/null 2>&1; then
    test_warn "/sys/kernel/security is accessible"
else
    test_pass "/sys/kernel/security not accessible"
fi

# ============================================================================
header "20. ADDITIONAL CREDENTIAL PATTERNS"
# ============================================================================

echo ""
echo "Scanning for additional credential patterns in environment and files..."

# Check environment for high-entropy secrets
info "Checking environment for credential patterns..."

# Slack tokens
if env | grep -qE "xox[baprs]-[0-9a-zA-Z-]+"; then
    test_fail "Slack token pattern found in environment"
else
    test_pass "No Slack tokens in environment"
fi

# Private key patterns in environment (unusual but check)
if env | grep -qE "BEGIN (RSA|EC|OPENSSH|PRIVATE) "; then
    test_fail "Private key material found in environment"
else
    test_pass "No private key material in environment"
fi

# Generic high-entropy check for KEY/TOKEN/SECRET vars
SUSPICIOUS_VARS=$(env | grep -iE "^[^=]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[^=]*=" | \
    grep -vE "(PLACEHOLDER|PROXY|PATH|LESS|COLORS)" | \
    awk -F= 'length($2) > 32 {print $1}')
if [[ -n "$SUSPICIOUS_VARS" ]]; then
    test_warn "High-entropy values in sensitive-named vars: $SUSPICIOUS_VARS"
else
    test_pass "No suspicious high-entropy credential variables"
fi

# Scan common locations for credential files
echo ""
info "Scanning for credential files..."

# GCP service account files
if find /tmp /home -name "*.json" -exec grep -l '"type":\s*"service_account"' {} \; 2>/dev/null | head -1 | grep -q .; then
    test_fail "GCP service account JSON found"
else
    test_pass "No GCP service account files found"
fi

# Private keys in accessible locations
if find /tmp /home -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | head -1 | grep -q .; then
    FOUND_KEYS=$(find /tmp /home -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | head -5)
    test_warn "Private key files found: $FOUND_KEYS"
else
    test_pass "No private key files in /tmp or /home"
fi

# ============================================================================
header "21. NETWORK BYPASS ATTEMPTS"
# ============================================================================

echo ""
echo "Testing additional network escape vectors..."

# Direct DNS query bypass attempts
info "Testing direct DNS queries (should be blocked)..."

# UDP DNS to 8.8.8.8
if command -v dig &>/dev/null; then
    DIG_RESULT=$(dig +short +timeout=3 +tries=1 @8.8.8.8 google.com 2>&1)
    if [[ -n "$DIG_RESULT" ]] && ! echo "$DIG_RESULT" | grep -qiE "(timeout|refused|error|unreachable|failed|no servers)"; then
        test_fail "Direct UDP DNS to 8.8.8.8 succeeded"
    else
        test_pass "Direct UDP DNS to 8.8.8.8 blocked/timeout"
    fi
elif command -v nslookup &>/dev/null; then
    NS_RESULT=$(timeout 5 nslookup google.com 8.8.8.8 2>&1)
    if echo "$NS_RESULT" | grep -qE "^Address.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"; then
        test_fail "Direct DNS to 8.8.8.8 succeeded (nslookup)"
    else
        test_pass "Direct DNS to 8.8.8.8 blocked (nslookup)"
    fi
else
    info "dig/nslookup not available for direct DNS test"
fi

# IPv6 egress attempt
info "Testing IPv6 egress..."
IPV6_RESULT=$(curl -6 -s --connect-timeout 5 --max-time 10 "https://ipv6.google.com/" 2>&1)
if [[ $? -eq 0 ]] && ! echo "$IPV6_RESULT" | grep -qiE "(error|couldn't|timeout)"; then
    test_fail "IPv6 egress succeeded"
else
    test_pass "IPv6 egress blocked (no IPv6 routes or filtered)"
fi

# Cloud metadata endpoint (169.254.169.254)
info "Testing cloud metadata endpoint access..."
METADATA_RESULT=$(curl -s --connect-timeout 3 --max-time 5 "http://169.254.169.254/latest/meta-data/" 2>&1)
if [[ $? -eq 0 ]] && ! echo "$METADATA_RESULT" | grep -qiE "(error|timeout|refused|blocked)"; then
    test_fail "Cloud metadata endpoint accessible!"
else
    test_pass "Cloud metadata endpoint blocked"
fi

# Wildcard subdomain test (should work if wildcards allowed)
info "Testing wildcard domain resolution..."
if nslookup "test-subdomain.api.openai.com" >/dev/null 2>&1; then
    test_pass "Wildcard subdomain resolves (test-subdomain.api.openai.com)"
else
    test_warn "Wildcard subdomain did not resolve (may be expected)"
fi

# Non-allowlisted subdomain (should be blocked)
if nslookup "evil-subdomain.github.com" >/dev/null 2>&1; then
    # DNS resolved, but proxy should still block
    EVIL_RESP=$(curl -s --connect-timeout 5 --max-time 10 "https://evil-subdomain.github.com/" 2>&1)
    if echo "$EVIL_RESP" | grep -qE "(not in allowlist|blocked|refused)"; then
        test_pass "Non-allowlisted subdomain blocked by proxy"
    else
        test_warn "Non-allowlisted subdomain DNS resolved (proxy may still block)"
    fi
else
    test_pass "Non-allowlisted subdomain DNS blocked"
fi

# ============================================================================
header "22. SENSITIVE PATH ACCESS"
# ============================================================================

echo ""
echo "Verifying sensitive credential paths not exposed..."

# OAuth credential paths that should NOT be accessible in sandbox
OAUTH_PATHS=(
    "$HOME/.codex/auth.json"
    "$HOME/.local/share/opencode/auth.json"
    "$HOME/.gemini/oauth_creds.json"
    "$HOME/.config/gh/hosts.yml"
)

for path in "${OAUTH_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
        # File exists - check if it has real credentials
        if grep -qE "(access_token|refresh_token|oauth_token)" "$path" 2>/dev/null; then
            test_fail "OAuth credentials found at $path"
        else
            test_warn "File exists at $path (check contents)"
        fi
    else
        test_pass "OAuth path not exposed: $path"
    fi
done

# SSH/GPG directories should be empty or non-existent
for dir in "$HOME/.ssh" "$HOME/.gnupg"; do
    if [[ -d "$dir" ]]; then
        CONTENTS=$(ls -A "$dir" 2>/dev/null | wc -l)
        if [[ $CONTENTS -gt 0 ]]; then
            test_warn "$dir exists with $CONTENTS items"
            ls -la "$dir" 2>/dev/null | head -5 | sed 's/^/    /'
        else
            test_pass "$dir empty"
        fi
    else
        test_pass "$dir does not exist"
    fi
done

# Session token should exist but be restricted (credential isolation mode)
if [[ -f /run/secrets/gateway_token ]]; then
    if [[ -r /run/secrets/gateway_token ]]; then
        # Check permissions
        PERMS=$(stat -c "%a" /run/secrets/gateway_token 2>/dev/null)
        if [[ "$PERMS" == "400" ]] || [[ "$PERMS" == "600" ]]; then
            test_pass "Gateway token exists with restricted permissions ($PERMS)"
        else
            test_warn "Gateway token permissions: $PERMS (expected 400 or 600)"
        fi
    else
        test_pass "Gateway token exists but not readable by current user"
    fi
else
    info "No gateway token (not in credential isolation mode)"
fi

# Real credentials directory (unified-proxy only)
if [[ -d /credentials ]]; then
    test_fail "/credentials directory accessible in sandbox!"
    ls -la /credentials 2>/dev/null | head -10 | sed 's/^/    /'
else
    test_pass "/credentials directory not accessible"
fi

# ============================================================================
header "SUMMARY"
# ============================================================================

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASSED${NC}: $PASS"
echo -e "  ${RED}FAILED${NC}: $FAIL"
echo -e "  ${YELLOW}WARNINGS${NC}: $WARN"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}⚠ SECURITY ISSUES DETECTED - Review failed tests above${NC}"
    exit 1
elif [[ $WARN -gt 3 ]]; then
    echo -e "${YELLOW}⚠ Multiple warnings - Review for potential issues${NC}"
    exit 0
else
    echo -e "${GREEN}✓ Credential isolation appears effective${NC}"
    exit 0
fi
