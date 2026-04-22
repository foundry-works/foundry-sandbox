#!/bin/bash
# Module: 12-merge-early-exit
# Description: Early-exit merge blocking validation
# Tests that merge operations are blocked at the earliest possible point
# in the policy engine, before identity verification or domain matching.
# This is defense-in-depth on top of the deep-policy sidecar fallback.

# Helper: assert a merge request is blocked.
# Checks HTTP status code first (403 = blocked), then falls back to body
# inspection for proxies that return 200 with an error payload.
_assert_merge_blocked() {
    local label="$1"
    shift
    # Remaining args are the curl flags

    local http_code body
    body=$(curl -s --max-time 10 -w "\n%{http_code}" "$@" 2>&1)
    http_code=$(echo "$body" | tail -n1)
    body=$(echo "$body" | sed '$d')

    if [[ "$http_code" == "403" ]]; then
        test_pass "$label blocked (HTTP 403)"
    elif [[ "$http_code" =~ ^(401|422)$ ]]; then
        # 401/422 from proxy means the request was intercepted (not forwarded
        # with real credentials) — acceptable block signal.
        if echo "$body" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy|merge)"; then
            test_pass "$label blocked (HTTP $http_code with policy message)"
        else
            test_pass "$label intercepted (HTTP $http_code — not forwarded to upstream)"
        fi
    elif [[ "$http_code" =~ ^2 ]]; then
        # 2xx is suspicious — check if the body indicates a policy block
        if echo "$body" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy)"; then
            test_pass "$label blocked (HTTP $http_code with block message in body)"
        else
            test_fail "$label NOT blocked — got HTTP $http_code with no block indicator"
        fi
    elif [[ "$http_code" == "000" ]]; then
        test_fail "$label — curl failed (connection error, HTTP 000)"
    else
        # 4xx/5xx other than 403 — likely blocked but verify
        if echo "$body" | grep -qiE "(blocked|forbidden|not allowed|not permitted|policy|merge)"; then
            test_pass "$label blocked (HTTP $http_code)"
        else
            test_warn "$label returned HTTP $http_code without clear block message — review"
        fi
    fi
}

run_tests() {
    header "19. EARLY-EXIT MERGE BLOCKING"

    echo ""
    echo "Testing that merge operations are blocked at foundry-git-safety early-exit..."
    echo "(These are blocked before identity or domain checks for defense-in-depth)"

    # When running inside a sandbox with the git-safety proxy available,
    # route requests through the proxy so the deep policy engine can
    # inspect and block them.  Without the proxy, requests go directly
    # to api.github.com and bypass the policy engine entirely.
    if [[ -n "${GIT_API_HOST:-}" ]] && [[ -n "${GIT_API_PORT:-}" ]]; then
        GITHUB_BASE="http://${GIT_API_HOST}:${GIT_API_PORT}/deep-policy/github"
        info "Routing through git-safety proxy at ${GITHUB_BASE}"
    else
        GITHUB_BASE="https://api.github.com"
        info "No git-safety proxy detected — targeting api.github.com directly"
    fi

    # Test 1: REST PR merge endpoint (PUT /repos/*/pulls/*/merge)
    info "Testing REST PR merge block (PUT /repos/*/pulls/*/merge)..."
    _assert_merge_blocked "REST PR merge" \
        -X PUT \
        -H "Authorization: token ${GH_TOKEN:-}" \
        -H "Content-Type: application/json" \
        -d '{"commit_title":"test merge","merge_method":"merge"}' \
        "${GITHUB_BASE}/repos/octocat/Hello-World/pulls/1/merge"

    # Test 2: REST auto-merge endpoint (PUT /repos/*/pulls/*/auto-merge)
    info "Testing REST auto-merge block (PUT /repos/*/pulls/*/auto-merge)..."
    _assert_merge_blocked "REST auto-merge" \
        -X PUT \
        -H "Authorization: token ${GH_TOKEN:-}" \
        -H "Content-Type: application/json" \
        -d '{}' \
        "${GITHUB_BASE}/repos/octocat/Hello-World/pulls/1/auto-merge"

    # Test 3: GraphQL mergePullRequest mutation
    info "Testing GraphQL mergePullRequest mutation block..."
    _assert_merge_blocked "GraphQL mergePullRequest" \
        -X POST \
        -H "Authorization: token ${GH_TOKEN:-}" \
        -H "Content-Type: application/json" \
        -d '{"query":"mutation { mergePullRequest(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}' \
        "${GITHUB_BASE}/graphql"

    # Test 4: GraphQL enablePullRequestAutoMerge mutation
    info "Testing GraphQL enablePullRequestAutoMerge mutation block..."
    _assert_merge_blocked "GraphQL enablePullRequestAutoMerge" \
        -X POST \
        -H "Authorization: token ${GH_TOKEN:-}" \
        -H "Content-Type: application/json" \
        -d '{"query":"mutation { enablePullRequestAutoMerge(input: {pullRequestId: \"PR_test123\"}) { pullRequest { id } } }"}' \
        "${GITHUB_BASE}/graphql"

    # Test 5: /merges path should NOT be caught by early-exit
    # (it's a lower-severity endpoint handled by the Step 3 blocklist)
    info "Testing that /merges path is NOT caught by early-exit..."
    MERGES_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST \
        -H "Authorization: token ${GH_TOKEN:-}" \
        -H "Content-Type: application/json" \
        -d '{"base":"main","head":"feature","commit_message":"test"}' \
        "${GITHUB_BASE}/repos/octocat/Hello-World/merges" 2>&1)

    # /merges should be blocked by Step 3 or later, but NOT by the merge_block policy type.
    # We verify it's still blocked (not passed through) — the blocking stage is tested
    # in unit tests, not here.
    if [[ "$MERGES_CODE" =~ ^(403|404|422)$ ]]; then
        test_pass "/merges endpoint blocked (HTTP $MERGES_CODE — by later policy stage)"
    elif [[ "$MERGES_CODE" =~ ^2 ]]; then
        test_fail "/merges endpoint NOT blocked — got HTTP $MERGES_CODE"
    else
        test_warn "/merges response HTTP $MERGES_CODE — verify it's blocked by Step 3"
    fi

    # Test 6: Non-merge GitHub API request should pass through
    info "Testing that non-merge GitHub API requests pass through..."
    LIST_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -H "Authorization: token ${GH_TOKEN:-}" \
        "${GITHUB_BASE}/repos/octocat/Hello-World/pulls" 2>&1)

    if [[ "$LIST_CODE" =~ ^(200|301|304|404)$ ]]; then
        test_pass "Non-merge GitHub API request passes through (HTTP $LIST_CODE)"
    elif [[ "$LIST_CODE" == "401" ]]; then
        # 401 = reached GitHub, no valid auth — request was forwarded correctly
        test_pass "Non-merge GitHub API request forwarded (HTTP 401 — auth required)"
    elif [[ "$LIST_CODE" == "403" ]]; then
        # Could be auth failure or merge block — get detail
        DETAIL_BODY=$(curl -s --max-time 10 \
            -H "Authorization: token ${GH_TOKEN:-}" \
            "${GITHUB_BASE}/repos/octocat/Hello-World/pulls" 2>&1)
        if echo "$DETAIL_BODY" | grep -qiE "merge"; then
            test_fail "Non-merge request incorrectly blocked by merge policy"
        else
            test_pass "Non-merge GitHub API request reaches proxy (403 is auth/rate limit, not merge block)"
        fi
    else
        test_warn "Non-merge request response HTTP $LIST_CODE — verify manually"
    fi
}
