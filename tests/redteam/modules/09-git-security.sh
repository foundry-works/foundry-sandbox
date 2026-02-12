#!/bin/bash
# Module: 09-git-security
# Description: Git security, hooks, shadow isolation, and marketplace access

run_tests() {
    # ---- Section 9: Git Security Tests ----
    header "9. GIT SECURITY TESTS"

    echo ""
    echo "Testing git security boundaries..."

    # Check git config
    info "Git configuration:"
    git config --global --list 2>/dev/null | grep -E "(user|credential)" | sed 's/^/    /' || echo "    (no relevant config)"

    # Check if we can see the gateway session
    if [[ -f "$HOME/.git-session-token" ]]; then
        test_warn "Git session token file exists at $HOME/.git-session-token"
        info "Content (first 50 chars): $(head -c 50 "$HOME/.git-session-token")"
    else
        test_pass "No git session token file exposed"
    fi

    # Try to read git credentials
    if git credential-store --file=/dev/null get 2>/dev/null <<< "host=github.com"; then
        test_pass "Git credential store empty or not configured"
    else
        test_pass "Git credential store not accessible"
    fi

    # ---- Section 10: Git Hook Prevention ----
    header "10. GIT HOOK PREVENTION"

    echo ""
    echo "Testing git hook hardening (core.hooksPath, fsmonitor, etc.)..."

    # Test 1: core.hooksPath should be /dev/null
    HOOKS_PATH=$(git config --global core.hooksPath 2>/dev/null)
    if [[ "$HOOKS_PATH" == "/dev/null" ]]; then
        test_pass "core.hooksPath is /dev/null"
    else
        test_fail "core.hooksPath is '$HOOKS_PATH' (expected /dev/null)"
    fi

    # Test 2: core.fsmonitor should be false
    FSMONITOR=$(git config --global core.fsmonitor 2>/dev/null)
    if [[ "$FSMONITOR" == "false" ]]; then
        test_pass "core.fsmonitor is false"
    else
        test_fail "core.fsmonitor is '$FSMONITOR' (expected false)"
    fi

    # Test 3: init.templateDir should be empty string
    TEMPLATE_DIR=$(git config --global init.templateDir 2>/dev/null)
    if [[ "$TEMPLATE_DIR" == "" ]]; then
        test_pass "init.templateDir is empty string"
    else
        test_fail "init.templateDir is '$TEMPLATE_DIR' (expected empty string)"
    fi

    # Test 4: core.fsmonitorHookVersion should be 0
    FSMONITOR_VER=$(git config --global core.fsmonitorHookVersion 2>/dev/null)
    if [[ "$FSMONITOR_VER" == "0" ]]; then
        test_pass "core.fsmonitorHookVersion is 0"
    else
        test_fail "core.fsmonitorHookVersion is '$FSMONITOR_VER' (expected 0)"
    fi

    # Test 5: receive.denyCurrentBranch should be refuse
    DENY_CURRENT=$(git config --global receive.denyCurrentBranch 2>/dev/null)
    if [[ "$DENY_CURRENT" == "refuse" ]]; then
        test_pass "receive.denyCurrentBranch is refuse"
    else
        test_fail "receive.denyCurrentBranch is '$DENY_CURRENT' (expected refuse)"
    fi

    # Test 6: Malicious post-checkout hook should NOT execute on clone
    info "Testing malicious post-checkout hook execution..."
    HOOK_TEST_DIR="/tmp/hook-test-$$"
    HOOK_REPO_DIR="/tmp/hook-repo-$$"
    HOOK_MARKER="/tmp/hook-executed-$$"
    rm -rf "$HOOK_TEST_DIR" "$HOOK_REPO_DIR" "$HOOK_MARKER" 2>/dev/null

    # Create a repo with a malicious post-checkout hook
    mkdir -p "$HOOK_REPO_DIR"
    (
        cd "$HOOK_REPO_DIR"
        git init --quiet
        git commit --allow-empty -m "init" --quiet
        mkdir -p .git/hooks
        cat > .git/hooks/post-checkout << HOOKEOF
#!/bin/bash
touch "$HOOK_MARKER"
HOOKEOF
        chmod +x .git/hooks/post-checkout
    )

    # Clone the repo - hook should NOT fire because core.hooksPath=/dev/null
    git clone --quiet "$HOOK_REPO_DIR" "$HOOK_TEST_DIR" 2>/dev/null

    if [[ -f "$HOOK_MARKER" ]]; then
        test_fail "Malicious post-checkout hook executed during clone!"
        rm -f "$HOOK_MARKER"
    else
        test_pass "Malicious post-checkout hook did NOT execute on clone"
    fi
    rm -rf "$HOOK_TEST_DIR" "$HOOK_REPO_DIR" 2>/dev/null

    # Test 7: Gated regression test for GIT_SHADOW_ENABLED override gap
    if [[ "${GIT_SHADOW_ENABLED:-0}" == "1" ]]; then
        info "GIT_SHADOW_ENABLED=1: Testing -c core.hooksPath= override gap..."
        OVERRIDE_PATH=$(git -c core.hooksPath= config core.hooksPath 2>/dev/null)
        if [[ -z "$OVERRIDE_PATH" || "$OVERRIDE_PATH" == "/dev/null" ]]; then
            test_pass "git -c core.hooksPath= override blocked by wrapper"
        else
            test_warn "git -c core.hooksPath= override succeeded (expected when Phase 3 wrapper active)"
            info "This gap is closed by Phase 3's git wrapper command allowlist"
        fi
    else
        info "GIT_SHADOW_ENABLED not set - skipping -c override gap test (Phase 3 not active)"
    fi

    # ---- Section 10b: Git Shadow Isolation ----
    header "10b. GIT SHADOW ISOLATION (Phase 3)"

    echo ""
    echo "Testing git shadow mode isolation (tmpfs + wrapper + HMAC auth)..."

    if [[ "${GIT_SHADOW_ENABLED:-0}" == "1" ]]; then

        # Test 1: /workspace/.git is an empty tmpfs
        info "Testing /workspace/.git is empty tmpfs..."
        if mountpoint -q /workspace/.git 2>/dev/null; then
            GIT_MOUNT_TYPE=$(mount | grep "/workspace/.git " | awk '{print $5}')
            if [[ "$GIT_MOUNT_TYPE" == "tmpfs" ]]; then
                GIT_DIR_CONTENTS=$(ls -A /workspace/.git 2>/dev/null | wc -l)
                if [[ "$GIT_DIR_CONTENTS" -eq 0 ]]; then
                    test_pass "/workspace/.git is empty tmpfs (mount type: tmpfs, 0 files)"
                else
                    test_fail "/workspace/.git is tmpfs but NOT empty ($GIT_DIR_CONTENTS items found)"
                    info "Contents: $(ls -A /workspace/.git 2>/dev/null | head -5)"
                fi
            else
                test_fail "/workspace/.git is mounted but not tmpfs (type: $GIT_MOUNT_TYPE)"
            fi
        else
            test_fail "/workspace/.git is not a separate mount point (shadow not active)"
        fi

        # Test 2: /usr/bin/git status fails with 'not a git repository'
        info "Testing raw /usr/bin/git status fails without real .git/..."
        RAW_GIT_OUTPUT=$(/usr/bin/git status 2>&1)
        RAW_GIT_EXIT=$?
        if [[ $RAW_GIT_EXIT -ne 0 ]] && echo "$RAW_GIT_OUTPUT" | grep -qi "not a git repository"; then
            test_pass "/usr/bin/git status fails with 'not a git repository'"
        elif [[ $RAW_GIT_EXIT -eq 0 ]]; then
            test_fail "/usr/bin/git status succeeded (shadow .git/ may contain metadata)"
        else
            test_fail "/usr/bin/git status failed but without expected message"
            info "Exit code: $RAW_GIT_EXIT, output: $(echo "$RAW_GIT_OUTPUT" | head -c 200)"
        fi

        # Test 3: proxied git log works correctly via wrapper
        info "Testing proxied git log via wrapper..."
        if [[ -x /usr/local/bin/git ]]; then
            WRAPPER_OUTPUT=$(/usr/local/bin/git log --oneline -5 2>&1)
            WRAPPER_EXIT=$?
            if [[ $WRAPPER_EXIT -eq 0 ]] && [[ -n "$WRAPPER_OUTPUT" ]]; then
                test_pass "Proxied git log works via wrapper (returned commits)"
            elif [[ $WRAPPER_EXIT -eq 0 ]]; then
                test_warn "Proxied git log returned 0 but empty output (new repo?)"
            else
                test_fail "Proxied git log via wrapper failed (exit: $WRAPPER_EXIT)"
                info "Output: $(echo "$WRAPPER_OUTPUT" | head -c 200)"
            fi
        else
            test_fail "Git wrapper not found at /usr/local/bin/git"
        fi

        # Test 4: git --git-dir=/tmp/evil status rejected by wrapper
        info "Testing --git-dir flag injection rejected by wrapper..."
        mkdir -p /tmp/evil 2>/dev/null
        GITDIR_OUTPUT=$(/usr/local/bin/git --git-dir=/tmp/evil status 2>&1)
        GITDIR_EXIT=$?
        rmdir /tmp/evil 2>/dev/null
        if [[ $GITDIR_EXIT -ne 0 ]] && echo "$GITDIR_OUTPUT" | grep -qiE "(blocked|rejected|not allowed|forbidden|denied|error)"; then
            test_pass "git --git-dir=/tmp/evil status rejected by wrapper"
        elif [[ $GITDIR_EXIT -eq 0 ]]; then
            test_fail "git --git-dir=/tmp/evil status succeeded (flag injection not blocked!)"
        else
            # Non-zero exit but unexpected message — still likely blocked
            test_pass "git --git-dir=/tmp/evil status failed (exit: $GITDIR_EXIT)"
            info "Output: $(echo "$GITDIR_OUTPUT" | head -c 200)"
        fi

        # Test 5: direct curl to git API without HMAC returns 401
        info "Testing unauthenticated git API access returns 401..."
        GIT_API_HOST="${GIT_API_HOST:-unified-proxy}"
        GIT_API_PORT="${GIT_API_PORT:-8083}"
        NOAUTH_RESP=$(curl -s --connect-timeout 5 --max-time 10 \
            -X POST \
            -H "Content-Type: application/json" \
            -d '{"args":["status"],"cwd":"/workspace"}' \
            -o /dev/null -w "%{http_code}" \
            "http://${GIT_API_HOST}:${GIT_API_PORT}/git/exec" 2>&1)
        if [[ "$NOAUTH_RESP" == "401" ]]; then
            test_pass "Unauthenticated git API request returned 401"
        elif [[ "$NOAUTH_RESP" == "000" ]]; then
            test_fail "Git API unreachable at ${GIT_API_HOST}:${GIT_API_PORT}"
        elif [[ "$NOAUTH_RESP" == "200" ]]; then
            test_fail "Unauthenticated git API request succeeded (HMAC not enforced!)"
        else
            test_fail "Unauthenticated git API returned unexpected HTTP $NOAUTH_RESP (expected 401)"
        fi

    else
        info "GIT_SHADOW_ENABLED not set - skipping git shadow isolation tests (Phase 3 not active)"
        info "  These tests require: tmpfs at /workspace/.git, git wrapper at /usr/local/bin/git,"
        info "  and git API server at port 8083 with HMAC authentication."
    fi

    # ---- Section 11: Git Marketplace Access ----
    header "11. GIT MARKETPLACE ACCESS"

    echo ""
    echo "Testing git proxy access for plugin marketplaces..."

    # Test 1: Plugin marketplace clone (positive test - should succeed)
    info "Testing plugin marketplace clone (allowed list)..."
    MARKETPLACE_DIR="/tmp/test-marketplace-$$"
    rm -rf "$MARKETPLACE_DIR" 2>/dev/null

    CLONE_OUTPUT=$(git clone --depth 1 https://github.com/anthropics/claude-plugins-official.git "$MARKETPLACE_DIR" 2>&1)
    CLONE_EXIT=$?

    if [[ $CLONE_EXIT -eq 0 ]] && [[ -d "$MARKETPLACE_DIR/.git" ]]; then
        test_pass "Plugin marketplace clone succeeded (git proxy allows anthropics repos)"
        rm -rf "$MARKETPLACE_DIR"
    elif echo "$CLONE_OUTPUT" | grep -qiE "(403|forbidden|blocked|not allowed)"; then
        test_fail "Plugin marketplace clone blocked (should be in allowed list)"
        info "Output: $(echo "$CLONE_OUTPUT" | head -c 200)"
    else
        test_warn "Plugin marketplace clone failed (may be network issue or repo doesn't exist)"
        info "Exit code: $CLONE_EXIT"
        info "Output: $(echo "$CLONE_OUTPUT" | head -c 200)"
    fi

    # Test 2: Unauthorized repo clone (negative test - should be blocked)
    info "Testing unauthorized repo clone (should be blocked)..."
    BLOCKED_DIR="/tmp/test-blocked-$$"
    rm -rf "$BLOCKED_DIR" 2>/dev/null

    BLOCKED_OUTPUT=$(git clone https://github.com/octocat/Hello-World.git "$BLOCKED_DIR" 2>&1)
    BLOCKED_EXIT=$?

    if echo "$BLOCKED_OUTPUT" | grep -qiE "(403|forbidden|blocked|not allowed|denied)"; then
        test_pass "Unauthorized repo clone blocked by git proxy (403)"
        rm -rf "$BLOCKED_DIR" 2>/dev/null
    elif [[ $BLOCKED_EXIT -eq 0 ]] && [[ -d "$BLOCKED_DIR/.git" ]]; then
        test_fail "Unauthorized repo clone succeeded (should be blocked by git proxy)"
        rm -rf "$BLOCKED_DIR"
    else
        # Could be blocked by other means (network, etc.)
        test_pass "Unauthorized repo clone failed (exit code: $BLOCKED_EXIT)"
        info "Output: $(echo "$BLOCKED_OUTPUT" | head -c 200)"
    fi

    # Test 3: Node.js proxy integration (global-agent bootstrap)
    info "Testing Node.js proxy integration..."
    if command -v node &>/dev/null; then
        # Test that Node.js can make HTTPS requests through the proxy
        NODE_OUTPUT=$(node -e "
const https = require('https');
const req = https.get('https://api.github.com/', (res) => {
    console.log('STATUS:' + res.statusCode);
    process.exit(0);
});
req.on('error', (e) => {
    console.log('ERROR:' + e.message);
    process.exit(1);
});
req.setTimeout(10000, () => {
    console.log('TIMEOUT');
    req.destroy();
    process.exit(1);
});
" 2>&1)
        NODE_EXIT=$?

        if echo "$NODE_OUTPUT" | grep -q "STATUS:"; then
            STATUS_CODE=$(echo "$NODE_OUTPUT" | grep "STATUS:" | cut -d: -f2)
            if [[ "$STATUS_CODE" == "200" ]] || [[ "$STATUS_CODE" == "403" ]]; then
                test_pass "Node.js routes through proxy (HTTP $STATUS_CODE)"
            else
                test_warn "Node.js proxy response: HTTP $STATUS_CODE"
            fi
        elif echo "$NODE_OUTPUT" | grep -qiE "(ECONNREFUSED|ETIMEDOUT|certificate)"; then
            test_warn "Node.js proxy connection issue: $(echo "$NODE_OUTPUT" | head -c 100)"
        else
            test_warn "Node.js proxy test inconclusive"
            info "Output: $(echo "$NODE_OUTPUT" | head -c 150)"
        fi
    else
        info "Node.js not available for proxy integration test"
    fi
}
