#!/bin/bash
# Module: 04-network-isolation
# Description: Network isolation and proxy bypass testing

run_tests() {
    header "4. NETWORK ISOLATION TESTS"

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
}
