#!/bin/bash
# Module: 18-ip-encoding-bypass
# Description: IP encoding bypass attempts via proxy
# Tests that direct-IP requests in various encodings are blocked by the proxy,
# preventing DNS filtering bypass.

run_tests() {
    header "18. IP ENCODING BYPASS PREVENTION"

    echo ""
    echo "Testing that IP-encoded URLs are blocked by the proxy..."

    # All requests go through the proxy. The policy engine should reject
    # any request where the host is an IP literal, regardless of encoding.

    # --- Dotted decimal ---
    info "Testing dotted decimal IP (1.2.3.4)..."
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://1.2.3.4/" 2>&1)
    if [[ "$RESP" == "403" ]]; then
        test_pass "Dotted decimal IP (1.2.3.4) blocked (403)"
    elif [[ "$RESP" == "000" ]]; then
        test_pass "Dotted decimal IP (1.2.3.4) blocked (connection refused/timeout)"
    else
        test_fail "Dotted decimal IP (1.2.3.4) not blocked (HTTP $RESP)"
    fi

    info "Testing dotted decimal IP (127.0.0.1)..."
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://127.0.0.1/" 2>&1)
    if [[ "$RESP" == "403" ]]; then
        test_pass "Dotted decimal IP (127.0.0.1) blocked (403)"
    elif [[ "$RESP" == "000" ]]; then
        test_pass "Dotted decimal IP (127.0.0.1) blocked (connection refused/timeout)"
    else
        test_fail "Dotted decimal IP (127.0.0.1) not blocked (HTTP $RESP)"
    fi

    # --- Octal encoding ---
    info "Testing octal-encoded IP (0177.0.0.1 = 127.0.0.1)..."
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://0177.0.0.1/" 2>&1)
    if [[ "$RESP" == "403" ]]; then
        test_pass "Octal IP (0177.0.0.1) blocked (403)"
    elif [[ "$RESP" == "000" ]]; then
        test_pass "Octal IP (0177.0.0.1) blocked (connection refused/timeout)"
    else
        test_fail "Octal IP (0177.0.0.1) not blocked (HTTP $RESP)"
    fi

    # --- Hex encoding ---
    info "Testing hex-encoded IP (0x7f000001 = 127.0.0.1)..."
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://0x7f000001/" 2>&1)
    if [[ "$RESP" == "403" ]]; then
        test_pass "Hex IP (0x7f000001) blocked (403)"
    elif [[ "$RESP" == "000" ]]; then
        test_pass "Hex IP (0x7f000001) blocked (connection refused/timeout)"
    else
        test_fail "Hex IP (0x7f000001) not blocked (HTTP $RESP)"
    fi

    # --- Integer encoding ---
    info "Testing integer-encoded IP (2130706433 = 127.0.0.1)..."
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://2130706433/" 2>&1)
    if [[ "$RESP" == "403" ]]; then
        test_pass "Integer IP (2130706433) blocked (403)"
    elif [[ "$RESP" == "000" ]]; then
        test_pass "Integer IP (2130706433) blocked (connection refused/timeout)"
    else
        test_fail "Integer IP (2130706433) not blocked (HTTP $RESP)"
    fi

    # --- Mixed encoding ---
    info "Testing mixed-encoding IP (0x7f.0.0.01)..."
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://0x7f.0.0.01/" 2>&1)
    if [[ "$RESP" == "403" ]]; then
        test_pass "Mixed IP (0x7f.0.0.01) blocked (403)"
    elif [[ "$RESP" == "000" ]]; then
        test_pass "Mixed IP (0x7f.0.0.01) blocked (connection refused/timeout)"
    else
        test_fail "Mixed IP (0x7f.0.0.01) not blocked (HTTP $RESP)"
    fi

    # --- IPv6 brackets ---
    info "Testing IPv6 bracket notation ([::1])..."
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "http://[::1]/" 2>&1)
    if [[ "$RESP" == "403" ]]; then
        test_pass "IPv6 bracket ([::1]) blocked (403)"
    elif [[ "$RESP" == "000" ]]; then
        test_pass "IPv6 bracket ([::1]) blocked (connection refused/timeout)"
    else
        test_fail "IPv6 bracket ([::1]) not blocked (HTTP $RESP)"
    fi

    # --- Normal domain still works ---
    info "Testing that normal domain requests still pass..."
    # Use a domain that should be in the allowlist
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://api.github.com/rate_limit" 2>&1)
    if [[ "$RESP" == "200" ]] || [[ "$RESP" == "304" ]] || [[ "$RESP" == "401" ]]; then
        test_pass "Normal domain (api.github.com) still accessible (HTTP $RESP)"
    elif [[ "$RESP" == "403" ]]; then
        test_warn "Normal domain (api.github.com) returned 403 (may be rate limited or auth required)"
    else
        test_warn "Normal domain (api.github.com) returned HTTP $RESP (may be expected in test environment)"
    fi
}
