#!/bin/bash
# Module: 03-dns-filtering
# Description: DNS filtering verification

run_tests() {
    header "3. DNS FILTERING TESTS"

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
}
