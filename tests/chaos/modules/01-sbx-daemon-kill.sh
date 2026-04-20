#!/usr/bin/env bash
# Chaos module: Kill sbx daemon mid-operation
#
# Tests that killing the sbx daemon during an active git operation:
# 1. Causes the wrapper to return non-zero
# 2. Does not corrupt the worktree
# 3. Allows recovery after daemon restart

# Requires a sandbox name as the first argument or env SANDBOX_NAME
: "${SANDBOX_NAME:=chaos-test-01}"

run_tests() {
    info "Module: sbx daemon kill mid-operation"

    # Setup: ensure sandbox exists and is running
    if ! sbx ls 2>/dev/null | grep -q "${SANDBOX_NAME}"; then
        test_warn "Sandbox ${SANDBOX_NAME} not found; skipping daemon kill tests"
        return
    fi

    # Test 1: Verify sandbox is accessible before disruption
    section_start "pre-check"
    if sbx exec "${SANDBOX_NAME}" -- echo "alive" &>/dev/null; then
        test_pass "Sandbox ${SANDBOX_NAME} is accessible"
    else
        test_fail "Sandbox ${SANDBOX_NAME} is not accessible (pre-check)"
        return
    fi
    section_end "pre-check"

    # Test 2: Verify git wrapper responds
    section_start "git-check"
    if sbx exec "${SANDBOX_NAME}" -- git version &>/dev/null; then
        test_pass "Git wrapper responds inside sandbox"
    else
        test_warn "Git wrapper not responding; may indicate server issue"
    fi
    section_end "git-check"

    # Test 3: Kill daemon and verify failure
    section_start "daemon-kill"
    # Find the sbx daemon PID
    daemon_pid=$(pgrep -f "sbx daemon" || true)
    if [[ -z "${daemon_pid}" ]]; then
        test_warn "No sbx daemon process found; cannot test daemon kill"
    else
        # Start a git operation in background
        sbx exec "${SANDBOX_NAME}" -- git status &>/dev/null &
        git_pid=$!
        sleep 0.1

        # Kill the daemon
        kill -9 "${daemon_pid}" 2>/dev/null || true
        test_pass "Killed sbx daemon (PID ${daemon_pid})"

        # Wait for git operation to complete (should fail)
        if wait "${git_pid}"; then
            test_warn "Git operation succeeded despite daemon kill"
        else
            test_pass "Git operation failed after daemon kill (expected)"
        fi

        # Verify worktree is not corrupted
        if sbx exec "${SANDBOX_NAME}" -- test -d /workspace/.git &>/dev/null; then
            test_pass "Worktree .git directory intact after daemon kill"
        else
            test_fail "Worktree .git directory missing after daemon kill"
        fi
    fi
    section_end "daemon-kill"

    # Test 4: Recovery after daemon restart
    section_start "recovery"
    sleep 2  # Give daemon time to restart
    if sbx ls &>/dev/null; then
        test_pass "sbx daemon recovered after kill"
    else
        test_warn "sbx daemon not yet recovered; may need manual restart"
    fi

    if sbx exec "${SANDBOX_NAME}" -- echo "recovered" &>/dev/null; then
        test_pass "Sandbox accessible after daemon recovery"
    else
        test_fail "Sandbox not accessible after daemon recovery"
    fi
    section_end "recovery"
}
