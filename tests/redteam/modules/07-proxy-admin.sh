#!/bin/bash
# Module: 07-proxy-admin
# Description: Proxy admin UI exposure check

run_tests() {
    header "7. PROXY ADMIN UI EXPOSURE"

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
}
