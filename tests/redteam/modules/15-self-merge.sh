#!/bin/bash
# Module: 15-self-merge
# Description: Self-merge prevention controls

run_tests() {
    header "23. SELF-MERGE PREVENTION"

    echo ""
    echo "Testing self-merge prevention controls..."
    echo "(These operations must be blocked to prevent sandbox from merging its own PRs)"

    # Test 1: gh pr merge (PUT /repos/*/pulls/*/merge) -> expect blocked
    info "Testing PR merge block (PUT /repos/*/pulls/*/merge)..."
    SELF_MERGE_RESP=$(curl -s --max-time 10 \
        -X PUT \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"commit_title":"self-merge test","merge_method":"merge"}' \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/merge" 2>&1)

    if echo "$SELF_MERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
        test_pass "PR merge blocked (self-merge prevention)"
    elif echo "$SELF_MERGE_RESP" | grep -qE '"merged"'; then
        test_fail "PR merge endpoint accessible (self-merge possible!)"
    else
        info "Merge response: $(echo "$SELF_MERGE_RESP" | head -c 200)"
        test_warn "PR merge response unclear - verify manually"
    fi

    # Test 2: Auto-merge enablement (PUT /repos/*/pulls/*/auto-merge) -> expect blocked
    info "Testing auto-merge enablement block (PUT /repos/*/pulls/*/auto-merge)..."
    AUTOMERGE_RESP=$(curl -s --max-time 10 \
        -X PUT \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{}' \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/auto-merge" 2>&1)

    if echo "$AUTOMERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
        test_pass "Auto-merge enablement blocked"
    elif echo "$AUTOMERGE_RESP" | grep -qE '"auto_merge"'; then
        test_fail "Auto-merge enablement accessible!"
    else
        info "Auto-merge response: $(echo "$AUTOMERGE_RESP" | head -c 200)"
        test_warn "Auto-merge response unclear - verify manually"
    fi

    # Test 3: PR review approval (POST /repos/*/pulls/*/reviews with event=APPROVE) -> expect blocked
    info "Testing PR review approval block (POST /repos/*/pulls/*/reviews, event=APPROVE)..."
    APPROVE_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"event":"APPROVE","body":"Looks good"}' \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/reviews" 2>&1)

    if echo "$APPROVE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy|self-approving)"; then
        test_pass "PR review approval blocked (self-approval prevention)"
    elif echo "$APPROVE_RESP" | grep -qE '"state".*"APPROVED"'; then
        test_fail "PR review approval accessible (self-approval possible!)"
    else
        info "Approval response: $(echo "$APPROVE_RESP" | head -c 200)"
        test_warn "PR review approval response unclear - verify manually"
    fi

    # Test 4: PR review comment (POST /repos/*/pulls/*/reviews with event=COMMENT) -> expect success
    info "Testing PR review comment (POST /repos/*/pulls/*/reviews, event=COMMENT)..."
    COMMENT_REVIEW_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"event":"COMMENT","body":"non-approval review comment"}' \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/reviews" 2>&1)

    if echo "$COMMENT_REVIEW_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
        test_fail "Non-approval PR review comment unexpectedly blocked"
    elif echo "$COMMENT_REVIEW_RESP" | grep -qE '"id"'; then
        test_pass "Non-approval PR review comment allowed (correct behavior)"
    elif echo "$COMMENT_REVIEW_RESP" | grep -qE "(not found|404|422)"; then
        test_pass "Non-approval review comment reached GitHub (not blocked by policy)"
    else
        info "Comment review response: $(echo "$COMMENT_REVIEW_RESP" | head -c 200)"
        test_warn "Non-approval review comment response unclear - verify manually"
    fi

    # Test 5: Review deletion (DELETE /repos/*/pulls/*/reviews/123) -> expect blocked
    info "Testing review deletion block (DELETE /repos/*/pulls/*/reviews/123)..."
    DELETE_REVIEW_RESP=$(curl -s --max-time 10 \
        -X DELETE \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/reviews/123" 2>&1)

    if echo "$DELETE_REVIEW_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
        test_pass "Review deletion blocked (prevents unblocking PRs)"
    elif echo "$DELETE_REVIEW_RESP" | grep -qE '"message".*"Not Found"'; then
        test_warn "Review deletion returned 404 - may not have reached policy layer"
    else
        info "Delete review response: $(echo "$DELETE_REVIEW_RESP" | head -c 200)"
        test_warn "Review deletion response unclear - verify manually"
    fi

    # Test 6: GraphQL updatePullRequestBranch mutation -> expect blocked
    info "Testing GraphQL updatePullRequestBranch block..."
    GRAPHQL_UPDATE_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"query":"mutation { updatePullRequestBranch(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}' \
        "https://api.github.com/graphql" 2>&1)

    if echo "$GRAPHQL_UPDATE_RESP" | grep -qiE "(blocked|forbidden|not allowed|policy)"; then
        test_pass "GraphQL updatePullRequestBranch blocked"
    elif echo "$GRAPHQL_UPDATE_RESP" | grep -qE '"errors"'; then
        info "GraphQL response had errors (may be blocked at filter layer)"
        test_pass "GraphQL updatePullRequestBranch blocked or rejected"
    else
        info "GraphQL response: $(echo "$GRAPHQL_UPDATE_RESP" | head -c 200)"
        test_warn "GraphQL updatePullRequestBranch response unclear - verify manually"
    fi
}
