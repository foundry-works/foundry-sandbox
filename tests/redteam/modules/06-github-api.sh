#!/bin/bash
# Module: 06-github-api
# Description: GitHub API deep policy, policy bypass, and service isolation (sbx-compatible)

run_tests() {
    # ---- Section 14: GitHub API Filter Tests ----
    header "14. GITHUB API FILTER TESTS"

    echo ""
    echo "Testing GitHub API security filters..."

    if ! deep_policy_available; then
        test_fail "Deep-policy proxy signing unavailable (need GIT_API_HOST, GIT_API_PORT, and proxy-sign)"
        return
    fi
    info "Routing signed requests through git-safety proxy"

    # These should be blocked
    info "Testing blocked operations (expect failures)..."

    # Try to access secrets endpoint
    assert_deep_policy_blocked \
        "GitHub secrets endpoint" \
        GET \
        "/deep-policy/github/repos/octocat/Hello-World/actions/secrets"

    # ---- Section 15: GitHub Policy Bypass Attempts ----
    header "15. GITHUB POLICY BYPASS ATTEMPTS"

    echo ""
    echo "Testing policy engine bypass attempts..."
    echo "(Policy engine blocks dangerous GitHub operations regardless of credentials)"

    # Test PR merge endpoint (should be blocked by policy engine)
    info "Testing PR merge block (PUT /repos/*/pulls/*/merge)..."
    assert_deep_policy_blocked \
        "PR merge endpoint" \
        PUT \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/merge" \
        '{"commit_title":"test","merge_method":"merge"}'

    # Test release deletion endpoint (should be blocked by policy engine)
    info "Testing release deletion block (DELETE /repos/*/releases/*)..."
    assert_deep_policy_blocked \
        "Release deletion endpoint" \
        DELETE \
        "/deep-policy/github/repos/octocat/Hello-World/releases/123"

    # Test issue comment creation (always allowed - issue comments are lower risk)
    info "Testing issue comment creation (always allowed)..."
    assert_deep_policy_allowed \
        "Issue comment creation" \
        POST \
        "/deep-policy/github/repos/octocat/Hello-World/issues/1/comments" \
        '{"body":"Test comment from sandbox"}'

    # ---- Section 16: Registration API Isolation ----
    header "16. REGISTRATION API ISOLATION"

    echo ""
    echo "Testing that internal registration API is not accessible from sandbox..."
    echo "(Service endpoints should not be accessible from inside sandbox)"

    # Test direct TCP access to common internal API ports
    info "Testing internal API TCP exposure..."
    INTERNAL_PORTS=(8081 8082 9090 5000)
    for port in "${INTERNAL_PORTS[@]}"; do
        INTERNAL_RESP=$(curl -s --connect-timeout 3 --max-time 5 \
            "http://127.0.0.1:${port}/internal/health" 2>&1)
        if echo "$INTERNAL_RESP" | grep -qE "(ok|healthy|status)"; then
            test_fail "Internal API accessible on port $port!"
        else
            test_pass "Internal API not exposed on TCP port $port"
        fi
    done

    # Test Unix socket path (should not exist in sandbox)
    SOCKET_PATHS=(
        "/var/run/foundry/git-safety.sock"
        "/var/run/foundry/internal.sock"
        "/run/foundry/git-safety.sock"
        "/tmp/foundry-git-safety.sock"
    )
    for sock in "${SOCKET_PATHS[@]}"; do
        if [[ -S "$sock" ]]; then
            test_fail "Internal API Unix socket accessible at $sock!"
        else
            test_pass "Internal API socket not accessible: $sock"
        fi
    done

    # Test git-safety registration endpoint (should be inaccessible from inside sandbox)
    info "Testing git-safety registration endpoint isolation..."
    REGISTER_RESP=$(curl -s --connect-timeout 5 --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"container_id":"evil-container","ip":"172.17.0.100"}' \
        "http://127.0.0.1:8083/internal/containers" 2>&1)

    if echo "$REGISTER_RESP" | grep -qiE "(forbidden|denied|not found|404|blocked)"; then
        test_pass "Git-safety registration endpoint blocked"
    elif echo "$REGISTER_RESP" | grep -qE '"(registered|status|container_id)"'; then
        test_fail "Git-safety registration endpoint accessible via HTTP!"
    else
        info "Registration response: $(echo "$REGISTER_RESP" | head -c 100)"
        test_pass "Git-safety registration endpoint not accessible"
    fi
}
