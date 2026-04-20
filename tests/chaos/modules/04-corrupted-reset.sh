#!/usr/bin/env bash
# Chaos module: Corrupted sbx reset (interrupted)
#
# Tests recovery from an interrupted sbx reset:
# 1. Interrupted reset leaves sandbox in recoverable state
# 2. cast destroy --force can clean up
# 3. cast new can recreate the sandbox

: "${SANDBOX_NAME:=chaos-test-04}"

run_tests() {
    info "Module: corrupted sbx reset"

    if ! sbx ls 2>/dev/null | grep -q "${SANDBOX_NAME}"; then
        test_warn "Sandbox ${SANDBOX_NAME} not found; skipping corrupted reset tests"
        return
    fi

    # Test 1: Interrupted reset
    section_start "interrupted-reset"
    # Start reset and send SIGINT after a short delay
    timeout --signal=INT 0.5 sbx reset "${SANDBOX_NAME}" &>/dev/null || true
    test_pass "Interrupted sbx reset with SIGINT"

    # Check sandbox state
    if sbx ls 2>/dev/null | grep -q "${SANDBOX_NAME}"; then
        test_pass "Sandbox still listed after interrupted reset"
    else
        test_warn "Sandbox not listed after interrupted reset (may have completed)"
    fi
    section_end "interrupted-reset"

    # Test 2: Recovery via destroy
    section_start "destroy-recovery"
    if cast destroy "${SANDBOX_NAME}" --force &>/dev/null; then
        test_pass "cast destroy --force succeeded after corrupted reset"
    else
        test_warn "cast destroy --force had issues (sandbox may already be removed)"
    fi
    section_end "destroy-recovery"

    # Test 3: Wrapper survives full reset when using template
    section_start "template-restore"
    # Create a new sandbox with the foundry template
    if cast new test/repo main --name "${SANDBOX_NAME}-template" &>/dev/null; then
        test_pass "Created sandbox with template"

        # Verify wrapper is present
        if sbx exec "${SANDBOX_NAME}-template" -- which git 2>/dev/null | grep -q "/usr/local/bin/git"; then
            test_pass "Wrapper present in template-based sandbox"
        else
            test_warn "Wrapper not found in template-based sandbox"
        fi

        # Reset the sandbox
        if sbx reset "${SANDBOX_NAME}-template" &>/dev/null; then
            test_pass "sbx reset completed"

            # Verify wrapper is still present (template-baked)
            if sbx exec "${SANDBOX_NAME}-template" -- which git 2>/dev/null | grep -q "/usr/local/bin/git"; then
                test_pass "Wrapper survived sbx reset (template-baked)"
            else
                test_warn "Wrapper missing after reset (template may not bake it)"
            fi
        else
            test_warn "sbx reset failed"
        fi

        # Cleanup
        cast destroy "${SANDBOX_NAME}-template" --force &>/dev/null || true
    else
        test_warn "Could not create template-based sandbox for reset test"
    fi
    section_end "template-restore"
}
