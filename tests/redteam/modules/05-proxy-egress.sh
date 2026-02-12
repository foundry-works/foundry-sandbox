#!/bin/bash
# Module: 05-proxy-egress
# Description: Proxy-layer egress filtering

run_tests() {
    header "5. PROXY-LAYER EGRESS FILTERING"

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
}
