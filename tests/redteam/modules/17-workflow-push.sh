#!/bin/bash
# Module: 17-workflow-push
# Description: Workflow push blocking verification

run_tests() {
    header "25. WORKFLOW PUSH BLOCKING"

    echo ""
    echo "Testing that pushes modifying .github/workflows/ are blocked..."
    echo "(Requires git shadow mode and push access to test repo)"

    if [[ "${GIT_SHADOW_ENABLED:-0}" == "1" ]]; then

        WORKFLOW_TEST_BRANCH="sandbox/redteam-workflow-test-$$"
        WORKFLOW_TEST_DIR="/tmp/workflow-push-test-$$"
        rm -rf "$WORKFLOW_TEST_DIR" 2>/dev/null

        # Get current repo info from git remote
        REMOTE_URL=$(git remote get-url origin 2>/dev/null || true)
        if [[ -n "$REMOTE_URL" ]]; then

            # Set up a temporary clone for the test
            mkdir -p "$WORKFLOW_TEST_DIR"
            cd "$WORKFLOW_TEST_DIR"
            git init --quiet
            git remote add origin "$REMOTE_URL"
            git fetch --depth=1 origin HEAD --quiet 2>/dev/null
            git checkout -b "$WORKFLOW_TEST_BRANCH" FETCH_HEAD --quiet 2>/dev/null

            # Test 1: Push with .github/workflows/ file should be BLOCKED
            info "Creating commit with .github/workflows/merge.yml..."
            mkdir -p .github/workflows
            cat > .github/workflows/merge.yml << 'WFEOF'
name: Auto-merge
on: pull_request
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
WFEOF
            git add .github/workflows/merge.yml
            git commit --quiet -m "redteam: add auto-merge workflow"

            info "Attempting push with workflow file (should be blocked)..."
            WORKFLOW_PUSH_OUTPUT=$(git push origin "$WORKFLOW_TEST_BRANCH" 2>&1)
            WORKFLOW_PUSH_EXIT=$?

            if [[ $WORKFLOW_PUSH_EXIT -ne 0 ]]; then
                test_pass "Push with .github/workflows/ file was blocked (exit: $WORKFLOW_PUSH_EXIT)"

                # Verify error message is generic (does not reveal restricted path)
                if echo "$WORKFLOW_PUSH_OUTPUT" | grep -qiE "\.github/(workflows|actions)"; then
                    test_fail "Error message reveals restricted path pattern"
                    info "Output: $(echo "$WORKFLOW_PUSH_OUTPUT" | head -c 300)"
                else
                    test_pass "Error message is generic (does not reveal restricted path)"
                fi
            else
                test_fail "Push with .github/workflows/ file SUCCEEDED (should be blocked!)"
                # Note: Branch cleanup via DELETE /git/refs/ is also blocked by the
                # proxy's git ref mutation policy. Log the orphan for manual cleanup.
                info "Orphan branch '${WORKFLOW_TEST_BRANCH}' may remain on remote (cleanup blocked by policy)"
            fi

            # Test 2: Normal code push should still work after workflow block
            info "Testing normal code push still works..."
            git reset --hard HEAD~1 --quiet 2>/dev/null
            echo "# redteam test" > src_redteam_test.txt
            git add src_redteam_test.txt
            git commit --quiet -m "redteam: normal code push test"

            NORMAL_PUSH_OUTPUT=$(git push origin "$WORKFLOW_TEST_BRANCH" 2>&1)
            NORMAL_PUSH_EXIT=$?

            if [[ $NORMAL_PUSH_EXIT -eq 0 ]]; then
                test_pass "Normal code push succeeded after workflow block"
                # Note: Branch cleanup via DELETE /git/refs/ is blocked by the
                # proxy's git ref mutation policy. Log the orphan for manual cleanup.
                info "Orphan branch '${WORKFLOW_TEST_BRANCH}' may remain on remote (cleanup blocked by policy)"
            else
                test_fail "Normal code push failed after workflow block (exit: $NORMAL_PUSH_EXIT)"
                info "Output: $(echo "$NORMAL_PUSH_OUTPUT" | head -c 300)"
            fi

            # Return to workspace
            cd /workspace
            rm -rf "$WORKFLOW_TEST_DIR" 2>/dev/null

        else
            info "No git remote configured - skipping workflow push blocking test"
        fi

    else
        info "GIT_SHADOW_ENABLED not set - skipping workflow push blocking tests"
        info "  These tests require git shadow mode with push access to a test repo."
    fi
}
