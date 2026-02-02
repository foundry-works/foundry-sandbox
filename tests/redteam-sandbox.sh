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
    "/credentials"                           # Real OAuth tokens (api-proxy only)
    "/credentials/codex/auth.json"           # Codex OAuth (api-proxy only)
    "/credentials/gemini/oauth_creds.json"   # Gemini OAuth (api-proxy only)
    "/credentials/opencode/auth.json"        # OpenCode OAuth (api-proxy only)
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
header "4b. PROXY-LAYER EGRESS FILTERING"
# ============================================================================

echo ""
echo "Testing proxy-layer hostname allowlist (defense in depth)..."
echo "(Even if DNS resolves, proxy should block non-allowlisted hosts)"

# Test exfiltration targets - should be blocked by proxy
EXFIL_TARGETS=("pastebin.com" "httpbin.org" "webhook.site" "evil.com")
for target in "${EXFIL_TARGETS[@]}"; do
    RESPONSE=$(curl -s --connect-timeout 5 --max-time 10 "https://$target/" 2>&1)
    if echo "$RESPONSE" | grep -q "Hostname not in allowlist"; then
        test_pass "Proxy blocked exfiltration to: $target"
    elif echo "$RESPONSE" | grep -iq "error\|timeout\|refused"; then
        test_pass "Connection to $target failed (blocked)"
    else
        test_fail "Exfiltration to $target may have succeeded"
        info "Response: $(echo "$RESPONSE" | head -c 100)"
    fi
done

# ============================================================================
header "5. CREDENTIAL INJECTION VERIFICATION"
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
header "6. GIT SECURITY TESTS"
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
header "7. CONTAINER ESCAPE / LATERAL MOVEMENT"
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
if ping -c 1 -W 2 gateway >/dev/null 2>&1; then
    test_warn "Can ping gateway container (expected for health checks)"
else
    test_pass "Cannot ping gateway container"
fi

if ping -c 1 -W 2 api-proxy >/dev/null 2>&1; then
    test_warn "Can ping api-proxy container (expected for proxy)"
else
    test_pass "Cannot ping api-proxy container"
fi

# ============================================================================
header "8. PROCESS AND MOUNT INSPECTION"
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
header "9. GITHUB API FILTER TESTS"
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
header "10. CERTIFICATE AND TLS INSPECTION"
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

# Check if we can make requests without the proxy CA
echo ""
info "Testing certificate validation..."
if curl -s --cacert /etc/ssl/certs/ca-certificates.crt --max-time 10 "https://api.anthropic.com/" 2>&1 | grep -q "certificate"; then
    test_pass "Certificate validation working (mitmproxy intercepting)"
else
    test_warn "Certificate test inconclusive"
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
