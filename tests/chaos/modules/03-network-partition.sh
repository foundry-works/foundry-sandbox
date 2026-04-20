#!/usr/bin/env bash
# Chaos module: Simulate network partition between VM and host
#
# Tests that network disruption between sandbox and git-safety server:
# 1. Causes the wrapper to timeout (not hang)
# 2. Resolves after connectivity is restored
# 3. Produces clear error messages

: "${SANDBOX_NAME:=chaos-test-03}"

run_tests() {
    info "Module: network partition simulation"

    if ! sbx ls 2>/dev/null | grep -q "${SANDBOX_NAME}"; then
        test_warn "Sandbox ${SANDBOX_NAME} not found; skipping network partition tests"
        return
    fi

    # Test 1: Wrapper timeout on unreachable server
    section_start "timeout"
    # Block traffic to git safety port from the sandbox's perspective
    # Using sbx policy to deny access to the host
    sbx policy deny network host.docker.internal &>/dev/null || true

    # Measure wrapper response time
    start_time=$(date +%s%N)
    sbx exec "${SANDBOX_NAME}" -- git status &>/dev/null
    exit_code=$?
    end_time=$(date +%s%N)
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))

    if [[ ${exit_code} -ne 0 ]]; then
        test_pass "Wrapper returned non-zero during partition (exit ${exit_code})"
    else
        test_warn "Wrapper succeeded during network partition"
    fi

    # Wrapper should timeout within 30s (--max-time 30 in wrapper.sh)
    if [[ ${elapsed_ms} -lt 35000 ]]; then
        test_pass "Wrapper timed out within expected window (${elapsed_ms}ms)"
    else
        test_fail "Wrapper took too long to timeout (${elapsed_ms}ms > 35000ms)"
    fi
    section_end "timeout"

    # Test 2: Restore connectivity
    section_start "restore"
    sbx policy allow network host.docker.internal &>/dev/null || true
    sleep 1

    if sbx exec "${SANDBOX_NAME}" -- git status &>/dev/null; then
        test_pass "Git operations resume after partition restore"
    else
        test_fail "Git operations do not resume after partition restore"
    fi
    section_end "restore"

    # Test 3: DNS failure produces clear error
    section_start "dns-failure"
    # Override the proxy to point to nonexistent host
    sbx exec "${SANDBOX_NAME}" -e SBX_PROXY=http://nonexistent.invalid:3128 -- \
        git status &>/dev/null
    exit_code=$?

    if [[ ${exit_code} -ne 0 ]]; then
        test_pass "DNS failure returns non-zero exit code"
    else
        test_warn "DNS failure returned exit code 0"
    fi
    section_end "dns-failure"
}
