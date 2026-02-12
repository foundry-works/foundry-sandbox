#!/bin/bash
# Module: 16-readonly-fs
# Description: Read-only filesystem and CA trust verification

run_tests() {
    header "24. READ-ONLY FILESYSTEM & CA TRUST"

    echo ""
    echo "Testing read-only filesystem and CA trust configuration..."
    echo "(Credential isolation mode should have read-only root FS with combined CA bundle)"

    # Test 1: Root filesystem should be read-only
    info "Testing root filesystem is read-only..."
    TOUCH_OUTPUT=$(touch /usr/bin/test-readonly-probe 2>&1)
    TOUCH_EXIT=$?
    if [[ $TOUCH_EXIT -ne 0 ]] && echo "$TOUCH_OUTPUT" | grep -qiE "(read-only|read only|permission denied)"; then
        test_pass "Root filesystem is read-only"
        rm -f /usr/bin/test-readonly-probe 2>/dev/null
    elif [[ $TOUCH_EXIT -eq 0 ]]; then
        rm -f /usr/bin/test-readonly-probe 2>/dev/null
        test_fail "Root filesystem is writable (should be read-only)"
    else
        info "Touch output: $TOUCH_OUTPUT"
        test_warn "Root filesystem write test inconclusive"
    fi

    # Test 2: Combined CA bundle exists
    info "Testing combined CA bundle exists..."
    if [[ -f /certs/ca-certificates.crt ]]; then
        test_pass "Combined CA bundle exists at /certs/ca-certificates.crt"
    else
        test_warn "Combined CA bundle not found (may not be in credential isolation mode)"
    fi

    # Test 3: SANDBOX_CA_MODE is set to combined
    info "Testing SANDBOX_CA_MODE environment variable..."
    if [[ "${SANDBOX_CA_MODE:-}" = "combined" ]]; then
        test_pass "SANDBOX_CA_MODE=combined is set"
    else
        test_warn "SANDBOX_CA_MODE not set to combined (may not be in credential isolation mode)"
    fi

    # Test 4: CA trust works (curl HTTPS through proxy)
    info "Testing CA trust via HTTPS request..."
    CURL_HTTPS_RESP=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        "https://api.github.com/" 2>&1)
    if [[ "$CURL_HTTPS_RESP" =~ ^(200|301|302|403|404|429) ]]; then
        test_pass "HTTPS request succeeded through proxy (HTTP $CURL_HTTPS_RESP)"
    elif [[ "$CURL_HTTPS_RESP" =~ ^(000|60|77) ]]; then
        test_fail "HTTPS request failed - CA trust issue (code: $CURL_HTTPS_RESP)"
    else
        info "HTTPS response code: $CURL_HTTPS_RESP"
        test_warn "HTTPS response unclear - verify CA trust manually"
    fi

    # Test 5: Git over HTTPS works
    info "Testing git over HTTPS..."
    GIT_LS_RESP=$(git ls-remote --exit-code https://github.com/octocat/Hello-World.git HEAD 2>&1)
    GIT_LS_EXIT=$?
    if [[ $GIT_LS_EXIT -eq 0 ]] || [[ $GIT_LS_EXIT -eq 2 ]]; then
        test_pass "Git HTTPS works through proxy"
    elif echo "$GIT_LS_RESP" | grep -qiE "(SSL|certificate|CA)"; then
        test_fail "Git HTTPS failed due to CA trust issue"
    else
        info "Git ls-remote exit: $GIT_LS_EXIT, output: $(echo "$GIT_LS_RESP" | head -c 200)"
        test_warn "Git HTTPS response unclear - verify manually"
    fi

    # Test 6: tmpfs is writable (expected - /tmp should always work)
    info "Testing tmpfs writability (/tmp)..."
    if touch /tmp/test-tmpfs-probe && rm -f /tmp/test-tmpfs-probe; then
        test_pass "tmpfs (/tmp) is writable"
    else
        test_fail "tmpfs (/tmp) is not writable"
    fi

    # Test 7: Home directory is writable (expected - /home is tmpfs)
    info "Testing home directory writability..."
    if touch ~/test-home-probe && rm -f ~/test-home-probe; then
        test_pass "Home directory is writable"
    else
        test_fail "Home directory is not writable"
    fi
}
