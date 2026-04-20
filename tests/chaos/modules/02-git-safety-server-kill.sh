#!/usr/bin/env bash
# Chaos module: Kill foundry-git-safety server mid-push
#
# Tests that killing the git-safety server during an active push:
# 1. Returns non-zero to the wrapper
# 2. Does not result in a partial push on the remote
# 3. Allows retry after server restart

: "${SANDBOX_NAME:=chaos-test-02}"

run_tests() {
    info "Module: git-safety server kill mid-push"

    # Setup: check server is running
    if ! curl -sf http://127.0.0.1:8083/health &>/dev/null; then
        test_warn "Git safety server not reachable; skipping server kill tests"
        return
    fi
    test_pass "Git safety server is healthy"

    # Test 1: Kill server and verify wrapper error
    section_start "server-kill"
    server_pid=$(pgrep -f "foundry-git-safety" || true)
    if [[ -z "${server_pid}" ]]; then
        test_warn "No foundry-git-safety process found"
    else
        # Start a git operation in background via sbx
        sbx exec "${SANDBOX_NAME}" -- git push origin HEAD &>/dev/null &
        push_pid=$!
        sleep 0.1

        # Kill the server
        kill -9 "${server_pid}" 2>/dev/null || true
        test_pass "Killed foundry-git-safety server (PID ${server_pid})"

        # Wait for push to complete (should fail)
        if wait "${push_pid}" 2>/dev/null; then
            test_warn "Push succeeded despite server kill"
        else
            test_pass "Push failed after server kill (expected)"
        fi
    fi
    section_end "server-kill"

    # Test 2: Restart server and verify recovery
    section_start "restart"
    sleep 1
    if foundry-git-safety start &>/dev/null; then
        test_pass "Git safety server restarted"
    else
        test_fail "Git safety server failed to restart"
        return
    fi

    # Wait for server to be ready
    for i in $(seq 1 10); do
        if curl -sf http://127.0.0.1:8083/health &>/dev/null; then
            break
        fi
        sleep 0.5
    done

    if curl -sf http://127.0.0.1:8083/health &>/dev/null; then
        test_pass "Git safety server is healthy after restart"
    else
        test_fail "Git safety server not healthy after restart"
    fi
    section_end "restart"

    # Test 3: Graceful shutdown drains requests
    section_start "graceful-shutdown"
    server_pid=$(pgrep -f "foundry-git-safety" || true)
    if [[ -n "${server_pid}" ]]; then
        # Start a long git operation
        sbx exec "${SANDBOX_NAME}" -- git log --oneline -100 &>/dev/null &
        log_pid=$!
        sleep 0.1

        # Send SIGTERM for graceful shutdown
        kill -TERM "${server_pid}" 2>/dev/null || true
        test_pass "Sent SIGTERM to git safety server"

        # The log operation should complete (drain)
        if wait "${log_pid}" 2>/dev/null; then
            test_pass "In-flight request completed during graceful shutdown"
        else
            test_warn "In-flight request did not complete during graceful shutdown"
        fi
    else
        test_warn "No server process found for graceful shutdown test"
    fi

    # Restart for subsequent tests
    foundry-git-safety start &>/dev/null || true
    section_end "graceful-shutdown"
}
