#!/bin/bash
# Module: 10-readonly-fs
# Description: Read-only filesystem verification (sbx microVM)

run_tests() {
    header "24. READ-ONLY FILESYSTEM"

    echo ""
    echo "Testing read-only filesystem and writable paths..."

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

    # Test 2: tmpfs is writable (expected — /tmp should always work)
    info "Testing tmpfs writability (/tmp)..."
    if touch /tmp/test-tmpfs-probe && rm -f /tmp/test-tmpfs-probe; then
        test_pass "tmpfs (/tmp) is writable"
    else
        test_fail "tmpfs (/tmp) is not writable"
    fi

    # Test 3: Home directory is writable (expected — /home is tmpfs-backed)
    info "Testing home directory writability..."
    if touch ~/test-home-probe && rm -f ~/test-home-probe; then
        test_pass "Home directory is writable"
    else
        test_fail "Home directory is not writable"
    fi

    # Test 4: Workspace mount — cast sandboxes mount the repo at the original
    # host path, not /workspace. Check for either convention.
    info "Testing workspace mount..."
    if [[ -d /workspace ]]; then
        if touch /workspace/.readonly-fs-probe 2>/dev/null && rm -f /workspace/.readonly-fs-probe; then
            test_pass "/workspace is writable"
        else
            test_warn "/workspace exists but is not writable (read-only mount?)"
        fi
    elif mount | grep -q "type virtiofs\|type bind"; then
        test_pass "Repo mounted via virtiofs (cast layout)"
    else
        test_warn "/workspace directory not found and no repo mount detected"
    fi

    # Test 5: Git wrapper is present at /usr/local/bin/git
    info "Testing git wrapper installation..."
    if [[ -f /usr/local/bin/git ]]; then
        test_pass "Git wrapper present at /usr/local/bin/git"
    else
        test_fail "Git wrapper missing from /usr/local/bin/git"
    fi

    # Test 6: HMAC secret is available for git authentication
    info "Testing HMAC secret availability..."
    if [[ -f /run/foundry/hmac-secret ]] || [[ -f /var/lib/foundry/hmac-secret ]]; then
        test_pass "HMAC secret file present"
    else
        test_fail "HMAC secret file not found"
    fi

    # Test 7: Git over HTTPS works through the sbx proxy
    info "Testing git over HTTPS..."
    GIT_LS_RESP=$(git ls-remote --exit-code https://github.com/octocat/Hello-World.git HEAD 2>&1)
    GIT_LS_EXIT=$?
    if [[ $GIT_LS_EXIT -eq 0 ]]; then
        test_pass "Git HTTPS works through sbx proxy"
    elif [[ $GIT_LS_EXIT -eq 2 ]]; then
        test_pass "Git HTTPS works (ls-remote returned 2 — repo access OK)"
    elif echo "$GIT_LS_RESP" | grep -qiE "(SSL|certificate|CA)"; then
        test_fail "Git HTTPS failed due to TLS/CA issue"
    else
        info "Git ls-remote exit: $GIT_LS_EXIT, output: $(echo "$GIT_LS_RESP" | head -c 200)"
        test_warn "Git HTTPS response unclear — verify manually"
    fi
}
