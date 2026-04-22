#!/bin/bash
# Module: 08-credential-injection
# Description: Verify sbx-native credential injection (proxy-level, not in-VM)

run_tests() {
    header "8. CREDENTIAL INJECTION VERIFICATION"

    echo ""
    echo "Testing that credentials are injected at the proxy level, not inside the VM..."

    # Built-in providers: API keys must NOT be in the environment
    # sbx injects these at the network proxy, so the VM never sees the real key.
    info "Checking built-in provider keys are NOT in environment..."
    if env | grep -qE "^ANTHROPIC_API_KEY=sk-"; then
        test_fail "Real ANTHROPIC_API_KEY exposed in environment (sbx should inject at proxy)"
    else
        test_pass "ANTHROPIC_API_KEY not in environment (proxy-managed)"
    fi

    if env | grep -qE "^OPENAI_API_KEY=sk-"; then
        test_fail "Real OPENAI_API_KEY exposed in environment (sbx should inject at proxy)"
    else
        test_pass "OPENAI_API_KEY not in environment (proxy-managed)"
    fi

    if env | grep -qE "^GITHUB_TOKEN=gh[ps]_" || env | grep -qE "^GH_TOKEN=gh[ps]_"; then
        test_fail "Real GITHUB_TOKEN/GH_TOKEN exposed in environment (sbx should inject at proxy)"
    else
        test_pass "GITHUB_TOKEN/GH_TOKEN not in environment (proxy-managed)"
    fi

    # User-services: env vars should point to proxy URLs, not real keys
    info "Checking user-service env vars point to proxy URLs..."
    USER_SERVICE_VARS=$(env | grep -E "^(TAVILY|PERPLEXITY|SEMANTIC_SCHOLAR).*=" 2>/dev/null || true)
    if [[ -n "$USER_SERVICE_VARS" ]]; then
        echo "$USER_SERVICE_VARS" | while IFS= read -r line; do
            VAR_NAME="${line%%=*}"
            VAR_VALUE="${line#*=}"
            if echo "$VAR_VALUE" | grep -qE "^https?://.*:8083/proxy/"; then
                test_pass "$VAR_NAME points to user-services proxy URL"
            elif echo "$VAR_VALUE" | grep -qE "^(sk-|pk_|tvly-|pplx-)"; then
                test_fail "$VAR_NAME contains a real API key (should be proxy URL)"
            else
                test_warn "$VAR_NAME has unexpected value: ${VAR_VALUE:0:40}..."
            fi
        done
    else
        test_pass "No user-service env vars set (or not configured)"
    fi

    # HMAC secret must exist for git-wrapper and proxy-sign authentication
    info "Checking HMAC secret exists for git safety authentication..."
    if [[ -f /run/foundry/hmac-secret ]]; then
        HMAC_SIZE=$(wc -c < /run/foundry/hmac-secret 2>/dev/null || echo "0")
        if [[ "$HMAC_SIZE" -gt 0 ]]; then
            test_pass "HMAC secret present on tmpfs (${HMAC_SIZE} bytes)"
        else
            test_fail "HMAC secret file exists but is empty"
        fi
    elif [[ -f /var/lib/foundry/hmac-secret ]]; then
        HMAC_SIZE=$(wc -c < /var/lib/foundry/hmac-secret 2>/dev/null || echo "0")
        if [[ "$HMAC_SIZE" -gt 0 ]]; then
            test_pass "HMAC secret present on persistent storage (${HMAC_SIZE} bytes)"
        else
            test_fail "HMAC secret file exists but is empty"
        fi
    else
        test_fail "HMAC secret not found at /run/foundry/hmac-secret or /var/lib/foundry/hmac-secret"
    fi

    # Git safety environment must be configured
    info "Checking git safety environment variables..."
    if [[ -n "${GIT_API_HOST:-}" ]] && [[ -n "${GIT_API_PORT:-}" ]]; then
        test_pass "Git safety server configured (${GIT_API_HOST}:${GIT_API_PORT})"
    else
        test_fail "Git safety environment variables missing (GIT_API_HOST/GIT_API_PORT)"
    fi

    if [[ -n "${SANDBOX_ID:-}" ]]; then
        test_pass "SANDBOX_ID set (${SANDBOX_ID})"
    else
        test_fail "SANDBOX_ID not set"
    fi

    # /proc/1/environ should not contain real credentials
    info "Checking /proc/1/environ for credential leaks..."
    if [[ -r /proc/1/environ ]]; then
        if cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -qE "(sk-ant|ghp_|ghs_|sk-[^a])"; then
            test_fail "Real credentials visible in /proc/1/environ"
        else
            test_pass "/proc/1/environ does not contain real credentials"
        fi
    else
        test_pass "/proc/1/environ not readable"
    fi
}
