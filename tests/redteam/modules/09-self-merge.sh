#!/bin/bash
# Module: 09-self-merge
# Description: Self-merge prevention controls

run_tests() {
    header "23. SELF-MERGE PREVENTION"

    echo ""
    echo "Testing self-merge prevention controls..."
    echo "(These operations must be blocked to prevent sandbox from merging its own PRs)"

    if ! deep_policy_available; then
        test_fail "Deep-policy proxy signing unavailable (need GIT_API_HOST, GIT_API_PORT, and proxy-sign)"
        return
    fi
    info "Routing signed requests through git-safety proxy"

    # Test 1: gh pr merge (PUT /repos/*/pulls/*/merge) -> expect blocked
    info "Testing PR merge block (PUT /repos/*/pulls/*/merge)..."
    assert_deep_policy_blocked \
        "PR merge" \
        PUT \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/merge" \
        '{"commit_title":"self-merge test","merge_method":"merge"}'

    # Test 2: Auto-merge enablement (PUT /repos/*/pulls/*/auto-merge) -> expect blocked
    info "Testing auto-merge enablement block (PUT /repos/*/pulls/*/auto-merge)..."
    assert_deep_policy_blocked \
        "Auto-merge enablement" \
        PUT \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/auto-merge" \
        '{}'

    # Test 3: PR review approval (POST /repos/*/pulls/*/reviews with event=APPROVE) -> expect blocked
    info "Testing PR review approval block (POST /repos/*/pulls/*/reviews, event=APPROVE)..."
    assert_deep_policy_blocked \
        "PR review approval" \
        POST \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/reviews" \
        '{"event":"APPROVE","body":"Looks good"}'

    # Test 4: PR review comment (POST /repos/*/pulls/*/reviews with event=COMMENT) -> expect success
    info "Testing PR review comment (POST /repos/*/pulls/*/reviews, event=COMMENT)..."
    assert_deep_policy_allowed \
        "Non-approval PR review comment" \
        POST \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/reviews" \
        '{"event":"COMMENT","body":"non-approval review comment"}'

    # Test 5: Review deletion (DELETE /repos/*/pulls/*/reviews/123) -> expect blocked
    info "Testing review deletion block (DELETE /repos/*/pulls/*/reviews/123)..."
    assert_deep_policy_blocked \
        "Review deletion" \
        DELETE \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/reviews/123"

    # Test 6: GraphQL updatePullRequestBranch mutation -> expect blocked
    info "Testing GraphQL updatePullRequestBranch block..."
    assert_deep_policy_blocked \
        "GraphQL updatePullRequestBranch" \
        POST \
        "/deep-policy/github/graphql" \
        '{"query":"mutation { updatePullRequestBranch(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}'
}
