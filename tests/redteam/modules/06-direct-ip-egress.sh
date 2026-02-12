#!/bin/bash
# Module: 06-direct-ip-egress
# Description: Direct IP egress without proxy

run_tests() {
    header "6. DIRECT IP EGRESS (NO PROXY)"

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
}
