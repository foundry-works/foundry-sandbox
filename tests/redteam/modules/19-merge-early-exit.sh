#!/bin/bash
# Module: 19-merge-early-exit
# Description: Early-exit merge blocking validation
# Tests that merge operations are blocked at the earliest possible point
# in the policy engine, before identity verification or domain matching.
# This is defense-in-depth on top of the existing Step 3 GitHub blocklist.

run_tests() {
    header "19. EARLY-EXIT MERGE BLOCKING"

    echo ""
    echo "Testing that merge operations are blocked at early-exit (Step E)..."
    echo "(These are blocked before identity or domain checks for defense-in-depth)"

    # Test 1: REST PR merge endpoint (PUT /repos/*/pulls/*/merge)
    info "Testing REST PR merge block (PUT /repos/*/pulls/*/merge)..."
    MERGE_RESP=$(curl -s --max-time 10 \
        -X PUT \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"commit_title":"test merge","merge_method":"merge"}' \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/merge" 2>&1)

    if echo "$MERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy)"; then
        test_pass "REST PR merge blocked by early-exit"
    else
        info "Merge response: $(echo "$MERGE_RESP" | head -c 200)"
        test_fail "REST PR merge not blocked by early-exit"
    fi

    # Test 2: REST auto-merge endpoint (PUT /repos/*/pulls/*/auto-merge)
    info "Testing REST auto-merge block (PUT /repos/*/pulls/*/auto-merge)..."
    AUTOMERGE_RESP=$(curl -s --max-time 10 \
        -X PUT \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{}' \
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/auto-merge" 2>&1)

    if echo "$AUTOMERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy)"; then
        test_pass "REST auto-merge blocked by early-exit"
    else
        info "Auto-merge response: $(echo "$AUTOMERGE_RESP" | head -c 200)"
        test_fail "REST auto-merge not blocked by early-exit"
    fi

    # Test 3: GraphQL mergePullRequest mutation
    info "Testing GraphQL mergePullRequest mutation block..."
    GQL_MERGE_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"query":"mutation { mergePullRequest(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}' \
        "https://api.github.com/graphql" 2>&1)

    if echo "$GQL_MERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy)"; then
        test_pass "GraphQL mergePullRequest blocked by early-exit"
    else
        info "GraphQL merge response: $(echo "$GQL_MERGE_RESP" | head -c 200)"
        test_fail "GraphQL mergePullRequest not blocked by early-exit"
    fi

    # Test 4: GraphQL enablePullRequestAutoMerge mutation
    info "Testing GraphQL enablePullRequestAutoMerge mutation block..."
    GQL_AUTOMERGE_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"query":"mutation { enablePullRequestAutoMerge(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}' \
        "https://api.github.com/graphql" 2>&1)

    if echo "$GQL_AUTOMERGE_RESP" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy)"; then
        test_pass "GraphQL enablePullRequestAutoMerge blocked by early-exit"
    else
        info "GraphQL auto-merge response: $(echo "$GQL_AUTOMERGE_RESP" | head -c 200)"
        test_fail "GraphQL enablePullRequestAutoMerge not blocked by early-exit"
    fi

    # Test 5: /merges path should NOT be caught by early-exit
    # (it's a lower-severity endpoint handled by the Step 3 blocklist)
    info "Testing that /merges path is NOT caught by early-exit..."
    MERGES_RESP=$(curl -s --max-time 10 \
        -X POST \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "Content-Type: application/json" \
        -d '{"base":"main","head":"feature","commit_message":"test"}' \
        "https://api.github.com/repos/octocat/Hello-World/merges" 2>&1)

    # /merges should be blocked by Step 3 or later, but NOT by the merge_block policy type.
    # We can't distinguish the blocking stage from curl, so just verify it doesn't pass through.
    if echo "$MERGES_RESP" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy|not found|404)"; then
        test_pass "/merges endpoint handled (not by early-exit, by later policy)"
    else
        info "/merges response: $(echo "$MERGES_RESP" | head -c 200)"
        test_warn "/merges response unclear - verify it's blocked by Step 3"
    fi

    # Test 6: Non-merge GitHub API request should pass through
    info "Testing that non-merge GitHub API requests pass through..."
    LIST_RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
        "https://api.github.com/repos/octocat/Hello-World/pulls" 2>&1)

    if [[ "$LIST_RESP" == "200" ]] || [[ "$LIST_RESP" == "301" ]] || [[ "$LIST_RESP" == "404" ]]; then
        test_pass "Non-merge GitHub API request passes through (HTTP $LIST_RESP)"
    elif [[ "$LIST_RESP" == "403" ]]; then
        # Could be auth failure, not merge block — check if it mentions merge
        DETAIL_RESP=$(curl -s --max-time 10 \
            -H "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER" \
            "https://api.github.com/repos/octocat/Hello-World/pulls" 2>&1)
        if echo "$DETAIL_RESP" | grep -qiE "merge"; then
            test_fail "Non-merge request incorrectly blocked by merge policy"
        else
            test_pass "Non-merge GitHub API request reaches GitHub (403 is auth, not merge block)"
        fi
    else
        info "List PRs response: HTTP $LIST_RESP"
        test_warn "Non-merge request response unclear - verify manually"
    fi
}
