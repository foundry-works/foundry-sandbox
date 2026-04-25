#!/bin/bash
# Module: 12-merge-early-exit
# Description: Early-exit merge blocking validation
# Tests that merge operations are blocked at the earliest possible point
# in the policy engine, before identity verification or domain matching.
# This is defense-in-depth on top of the deep-policy sidecar fallback.

# Helper: assert a merge request is blocked after HMAC authentication.
_assert_merge_blocked() {
    assert_deep_policy_blocked "$@"
}

run_tests() {
    header "19. EARLY-EXIT MERGE BLOCKING"

    echo ""
    echo "Testing that merge operations are blocked at foundry-git-safety early-exit..."
    echo "(These are blocked before identity or domain checks for defense-in-depth)"

    if ! deep_policy_available; then
        test_fail "Deep-policy proxy signing unavailable (need GIT_API_HOST, GIT_API_PORT, and proxy-sign)"
        return
    fi
    info "Routing signed requests through git-safety proxy"

    # Test 1: REST PR merge endpoint (PUT /repos/*/pulls/*/merge)
    info "Testing REST PR merge block (PUT /repos/*/pulls/*/merge)..."
    _assert_merge_blocked \
        "REST PR merge" \
        PUT \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/merge" \
        '{"commit_title":"test merge","merge_method":"merge"}'

    # Test 2: REST auto-merge endpoint (PUT /repos/*/pulls/*/auto-merge)
    info "Testing REST auto-merge block (PUT /repos/*/pulls/*/auto-merge)..."
    _assert_merge_blocked \
        "REST auto-merge" \
        PUT \
        "/deep-policy/github/repos/octocat/Hello-World/pulls/1/auto-merge" \
        '{}'

    # Test 3: GraphQL mergePullRequest mutation
    info "Testing GraphQL mergePullRequest mutation block..."
    _assert_merge_blocked \
        "GraphQL mergePullRequest" \
        POST \
        "/deep-policy/github/graphql" \
        '{"query":"mutation { mergePullRequest(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}'

    # Test 4: GraphQL enablePullRequestAutoMerge mutation
    info "Testing GraphQL enablePullRequestAutoMerge mutation block..."
    _assert_merge_blocked \
        "GraphQL enablePullRequestAutoMerge" \
        POST \
        "/deep-policy/github/graphql" \
        '{"query":"mutation { enablePullRequestAutoMerge(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}'

    # Test 5: /merges path should NOT be caught by early-exit
    # (it's a lower-severity endpoint handled by the Step 3 blocklist)
    info "Testing that /merges path is NOT caught by early-exit..."
    MERGES_HEADERS=$(mktemp)
    MERGES_RESP=$(deep_policy_request \
        POST \
        "/deep-policy/github/repos/octocat/Hello-World/merges" \
        '{"base":"main","head":"feature","commit_message":"test"}' \
        "$MERGES_HEADERS" 2>&1)
    MERGES_EXIT=$?
    MERGES_CODE=$(http_response_code "$MERGES_RESP")
    MERGES_BODY=$(http_response_body "$MERGES_RESP")

    # /merges should be blocked by Step 3 or later, but NOT by the merge_block policy type.
    # We verify it's still blocked (not passed through) — the blocking stage is tested
    # in unit tests, not here.
    if [[ $MERGES_EXIT -ne 0 ]]; then
        test_fail "/merges request failed before policy: $(printf '%s' "$MERGES_RESP" | head -c 200)"
    elif deep_policy_response_blocked "$MERGES_CODE" "$MERGES_HEADERS" "$MERGES_BODY"; then
        test_pass "/merges endpoint blocked (HTTP $MERGES_CODE — by later policy stage)"
    else
        test_fail "/merges endpoint NOT blocked — got HTTP $MERGES_CODE"
    fi
    rm -f "$MERGES_HEADERS"

    # Test 6: Non-merge GitHub API request should pass through
    info "Testing that non-merge GitHub API requests pass through..."
    assert_deep_policy_allowed \
        "Non-merge GitHub API request" \
        GET \
        "/deep-policy/github/repos/octocat/Hello-World/pulls"
}
