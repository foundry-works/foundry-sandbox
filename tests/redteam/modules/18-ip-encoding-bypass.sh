#!/bin/bash
# Module: 18-ip-encoding-bypass
# Description: IP encoding bypass attempts via proxy
# Tests that direct-IP requests in various encodings are blocked by the proxy,
# preventing DNS filtering bypass.

# Helper: assert an IP-encoded request is blocked.
# Accepts HTTP 403 (actively blocked) or 000 (connection refused/timeout).
# Fails on HTTP 200-299 (request reached upstream).
_assert_ip_blocked() {
    local label="$1"
    local url="$2"

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>&1)

    if [[ "$http_code" == "403" ]]; then
        test_pass "$label blocked (HTTP 403)"
    elif [[ "$http_code" == "000" ]]; then
        # 000 = curl couldn't connect at all (timeout, refused, DNS failure).
        # This is an acceptable block — the request never reached upstream.
        test_pass "$label blocked (connection refused/timeout)"
    elif [[ "$http_code" =~ ^2 ]]; then
        # 2xx means the request reached an upstream — definite bypass.
        test_fail "$label NOT blocked — got HTTP $http_code (request reached upstream)"
    else
        # Other codes (4xx auth errors, 5xx proxy errors) are ambiguous but
        # not a bypass.  Warn so the operator can investigate.
        test_warn "$label returned HTTP $http_code (not a bypass, but review)"
    fi
}

run_tests() {
    header "18. IP ENCODING BYPASS PREVENTION"

    echo ""
    echo "Testing that IP-encoded URLs are blocked by the proxy..."

    # All requests go through the proxy. The policy engine should reject
    # any request where the host is an IP literal, regardless of encoding.

    # --- Dotted decimal ---
    info "Testing dotted decimal IP (1.2.3.4)..."
    _assert_ip_blocked "Dotted decimal IP (1.2.3.4)" "http://1.2.3.4/"

    info "Testing dotted decimal IP (127.0.0.1)..."
    _assert_ip_blocked "Dotted decimal IP (127.0.0.1)" "http://127.0.0.1/"

    # --- Octal encoding ---
    info "Testing octal-encoded IP (0177.0.0.1 = 127.0.0.1)..."
    _assert_ip_blocked "Octal IP (0177.0.0.1)" "http://0177.0.0.1/"

    # --- Hex encoding ---
    info "Testing hex-encoded IP (0x7f000001 = 127.0.0.1)..."
    _assert_ip_blocked "Hex IP (0x7f000001)" "http://0x7f000001/"

    # --- Integer encoding ---
    info "Testing integer-encoded IP (2130706433 = 127.0.0.1)..."
    _assert_ip_blocked "Integer IP (2130706433)" "http://2130706433/"

    # --- Mixed encoding ---
    info "Testing mixed-encoding IP (0x7f.0.0.01)..."
    _assert_ip_blocked "Mixed IP (0x7f.0.0.01)" "http://0x7f.0.0.01/"

    # --- IPv6 brackets ---
    info "Testing IPv6 bracket notation ([::1])..."
    _assert_ip_blocked "IPv6 bracket ([::1])" "http://[::1]/"

    # --- Normal domain still works ---
    info "Testing that normal domain requests still pass..."
    # Use a domain that should be in the allowlist
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://api.github.com/rate_limit" 2>&1)
    if [[ "$RESP" =~ ^(200|301|304)$ ]]; then
        test_pass "Normal domain (api.github.com) still accessible (HTTP $RESP)"
    elif [[ "$RESP" == "401" ]]; then
        # 401 = reached GitHub but no auth — proxy forwarded correctly
        test_pass "Normal domain (api.github.com) reachable (HTTP 401 — auth required)"
    elif [[ "$RESP" == "403" ]]; then
        test_warn "Normal domain (api.github.com) returned 403 (may be rate limited)"
    else
        test_warn "Normal domain (api.github.com) returned HTTP $RESP (may be expected in test environment)"
    fi
}
