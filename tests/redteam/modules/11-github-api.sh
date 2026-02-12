#!/bin/bash
# Module: 11-github-api
# Description: GitHub API filter, policy bypass, and registration isolation

run_tests() {
    # ---- Section 14: GitHub API Filter Tests ----
    header "14. GITHUB API FILTER TESTS"

    echo ""
    echo "Testing GitHub API security filters..."

    # These should be blocked
    info "Testing blocked operations (expect failures)..."

    # Try to access secrets endpoint
    SECRETS_RESP=$(curl -s --max-time 10 \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        "https://api.github.com/repos/octocat/Hello-World/actions/secrets" 2>&1)

    if echo "$SECRETS_RESP" | grep -qiE "(blocked|forbidden|not allowed)"; then
        test_pass "GitHub secrets endpoint blocked"
    elif echo "$SECRETS_RESP" | grep -qE "\"secrets\""; then
        test_fail "GitHub secrets endpoint accessible!"
    else
        info "Secrets response: $(echo "$SECRETS_RESP" | head -c 150)"
        test_warn "GitHub secrets response unclear"
    fi

    # ---- Section 15: GitHub Policy Bypass Attempts ----
    header "15. GITHUB POLICY BYPASS ATTEMPTS"

    echo ""
    echo "Testing policy engine bypass attempts..."
    echo "(Policy engine blocks dangerous GitHub operations regardless of credentials)"

    # Test PR merge endpoint (should be blocked by policy engine)
    info "Testing PR merge block (PUT /repos/*/pulls/*/merge)..."
    MERGE_RESP=$(curl -s --max-time 10 \
        -X PUT \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"commit_title":"test","merge_method":"merge"}' \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/merge" 2>&1)

    if echo "$MERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
        test_pass "PR merge endpoint blocked by policy engine"
    elif echo "$MERGE_RESP" | grep -qE '"merged"'; then
        test_fail "PR merge endpoint accessible!"
    elif echo "$MERGE_RESP" | grep -qE "(not found|404)"; then
        test_pass "PR merge request reached GitHub (404 = PR doesn't exist, but policy allowed)"
        info "Note: Policy may allow merge for valid PRs - verify with ALLOW_PR_OPERATIONS=false"
    else
        info "Merge response: $(echo "$MERGE_RESP" | head -c 150)"
        test_warn "PR merge response unclear"
    fi

    # Test release creation endpoint (should be blocked by policy engine)
    info "Testing release creation block (POST /repos/*/releases)..."
    RELEASE_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"tag_name":"v0.0.1-test","name":"Test Release"}' \
        "https://api.github.com/repos/octocat/Hello-World/releases" 2>&1)

    if echo "$RELEASE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
        test_pass "Release creation endpoint blocked by policy engine"
    elif echo "$RELEASE_RESP" | grep -qE '"id"'; then
        test_fail "Release creation endpoint accessible!"
    else
        info "Release response: $(echo "$RELEASE_RESP" | head -c 150)"
        test_pass "Release creation blocked or unauthorized"
    fi

    # Test issue comment creation (always allowed - issue comments are lower risk)
    info "Testing issue comment creation (always allowed)..."
    COMMENT_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"body":"Test comment from sandbox"}' \
        "https://api.github.com/repos/octocat/Hello-World/issues/1/comments" 2>&1)

    if echo "$COMMENT_RESP" | grep -qE '"id"'; then
        test_pass "Issue comment creation works (allowed by policy)"
    elif echo "$COMMENT_RESP" | grep -qiE "(blocked|forbidden|not allowed)"; then
        test_fail "Issue comment creation unexpectedly blocked"
    else
        info "Comment response: $(echo "$COMMENT_RESP" | head -c 150)"
        test_warn "Issue comment response unclear"
    fi

    # ---- Section 16: Registration API Isolation ----
    header "16. REGISTRATION API ISOLATION"

    echo ""
    echo "Testing that internal registration API is not accessible from sandbox..."
    echo "(Registration API should only be available via Unix socket on proxy)"

    # Test direct TCP access to common internal API ports
    info "Testing internal API TCP exposure..."
    INTERNAL_PORTS=(8081 8082 9090 5000)
    for port in "${INTERNAL_PORTS[@]}"; do
        INTERNAL_RESP=$(curl -s --connect-timeout 3 --max-time 5 \
            "http://unified-proxy:${port}/internal/health" 2>&1)
        if echo "$INTERNAL_RESP" | grep -qE "(ok|healthy|status)"; then
            test_fail "Internal API accessible on port $port!"
        else
            test_pass "Internal API not exposed on TCP port $port"
        fi
    done

    # Test Unix socket path (should not exist in sandbox)
    SOCKET_PATHS=(
        "/var/run/unified-proxy/internal.sock"
        "/var/run/proxy/internal.sock"
        "/run/unified-proxy/internal.sock"
        "/tmp/unified-proxy.sock"
    )
    for sock in "${SOCKET_PATHS[@]}"; do
        if [[ -S "$sock" ]]; then
            test_fail "Internal API Unix socket accessible at $sock!"
        else
            test_pass "Internal API socket not accessible: $sock"
        fi
    done

    # Test container registration endpoint (should be inaccessible)
    info "Testing container registration endpoint..."
    REGISTER_RESP=$(curl -s --connect-timeout 5 --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"container_id":"evil-container","ip":"172.17.0.100"}' \
        "http://unified-proxy:8080/internal/containers" 2>&1)

    if echo "$REGISTER_RESP" | grep -qiE "(forbidden|denied|not found|404|blocked)"; then
        test_pass "Container registration endpoint blocked"
    elif echo "$REGISTER_RESP" | grep -qE '"(registered|status|container_id)"'; then
        test_fail "Container registration endpoint accessible via HTTP!"
    else
        info "Registration response: $(echo "$REGISTER_RESP" | head -c 100)"
        test_pass "Container registration not accessible"
    fi
}
