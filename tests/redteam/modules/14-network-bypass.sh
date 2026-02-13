#!/bin/bash
# Module: 14-network-bypass
# Description: Network bypass attempts and sensitive path access

run_tests() {
    # ---- Section 21: Network Bypass Attempts ----
    header "21. NETWORK BYPASS ATTEMPTS"

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

    # ---- Section 22: Sensitive Path Access ----
    header "22. SENSITIVE PATH ACCESS"

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
                # Distinguish proxy stubs (placeholders) from real OAuth credentials.
                # In credential isolation mode, stub files intentionally contain
                # access_token/refresh_token fields with CREDENTIAL_PROXY_PLACEHOLDER values.
                if grep -qE "CREDENTIAL_PROXY_PLACEHOLDER|PROXY_PLACEHOLDER" "$path" 2>/dev/null; then
                    test_pass "Proxy stub at $path (placeholder credentials only)"
                else
                    test_fail "OAuth credentials found at $path"
                fi
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
}
