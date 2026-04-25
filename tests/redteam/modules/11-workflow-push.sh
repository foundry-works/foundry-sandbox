#!/bin/bash
# Module: 11-workflow-push
# Description: Workflow push blocking verification

run_tests() {
    header "25. WORKFLOW PUSH BLOCKING"

    echo ""
    echo "Testing that pushes modifying .github/workflows/ are blocked..."
    echo "(Requires git shadow mode and push access to test repo)"

    if [[ "${GIT_SHADOW_ENABLED:-0}" == "1" ]]; then

        ORIG_DIR="$PWD"
        WORKSPACE_ROOT=$(foundry_workspace_dir)

        cd "$WORKSPACE_ROOT" || {
            test_fail "Unable to enter workspace at $WORKSPACE_ROOT"
            return
        }

        if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            test_fail "Workspace is not a git worktree: $WORKSPACE_ROOT"
            cd "$ORIG_DIR" || true
            return
        fi

        BASE_REF=$(git rev-parse --verify HEAD 2>/dev/null)
        if [[ -z "$BASE_REF" ]]; then
            test_fail "Unable to resolve current HEAD for workflow push test"
            cd "$ORIG_DIR" || true
            return
        fi

        SANDBOX_PUSH_BRANCH=$(git branch --show-current 2>/dev/null || true)
        if [[ -z "$SANDBOX_PUSH_BRANCH" ]]; then
            test_fail "Unable to resolve current sandbox branch for workflow push test"
            cd "$ORIG_DIR" || true
            return
        fi

        if ! git diff --cached --quiet 2>/dev/null; then
            test_warn "Index has staged changes or git diff failed; skipping workflow push test"
            cd "$ORIG_DIR" || true
            return
        fi

        WORKFLOW_PATH=".github/workflows/redteam-$$.yml"
        NORMAL_PATH="redteam-normal-$$.txt"
        GITHUB_DIR_PREEXISTED=false
        WORKFLOW_DIR_PREEXISTED=false
        [[ -d .github ]] && GITHUB_DIR_PREEXISTED=true
        [[ -d .github/workflows ]] && WORKFLOW_DIR_PREEXISTED=true

        _workflow_push_cleanup() {
            /usr/bin/git reset --mixed "$BASE_REF" --quiet 2>/dev/null \
                || git reset --mixed "$BASE_REF" --quiet 2>/dev/null \
                || true
            rm -f "$WORKFLOW_PATH" "$NORMAL_PATH" 2>/dev/null || true
            if [[ "$WORKFLOW_DIR_PREEXISTED" == "false" ]]; then
                rmdir .github/workflows 2>/dev/null || true
            fi
            if [[ "$GITHUB_DIR_PREEXISTED" == "false" ]]; then
                rmdir .github 2>/dev/null || true
            fi
        }

        _workflow_transport_unavailable() {
            printf '%s' "$1" | grep -qiE "(cannot run ssh|unable to fork|permission denied \(publickey\)|could not resolve hostname|could not read Username|authentication failed|repository not found)"
        }

        # Get current repo info from git remote. This must run in the workspace
        # so the git wrapper, not raw /usr/bin/git, handles the request.
        REMOTE_URL=$(git remote get-url origin 2>/dev/null || true)
        if [[ -n "$REMOTE_URL" ]]; then

            # Test 1: Push with .github/workflows/ file should be BLOCKED
            info "Creating commit with $WORKFLOW_PATH..."
            mkdir -p .github/workflows
            cat > "$WORKFLOW_PATH" << 'WFEOF'
name: Auto-merge
on: pull_request
jobs:
  merge:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
WFEOF
            git add "$WORKFLOW_PATH"
            WORKFLOW_COMMIT_OUTPUT=$(git -c user.email=redteam@example.invalid \
                -c user.name="Redteam Test" \
                commit --quiet -m "redteam: add auto-merge workflow" 2>&1)
            WORKFLOW_COMMIT_EXIT=$?
            if [[ $WORKFLOW_COMMIT_EXIT -eq 0 ]]; then
                info "Attempting push with workflow file (should be blocked)..."
                WORKFLOW_PUSH_OUTPUT=$(git push --dry-run origin "HEAD:$SANDBOX_PUSH_BRANCH" 2>&1)
                WORKFLOW_PUSH_EXIT=$?

                if _workflow_transport_unavailable "$WORKFLOW_PUSH_OUTPUT"; then
                    test_warn "Git push transport unavailable; skipping live workflow push assertions"
                    info "Output: $(echo "$WORKFLOW_PUSH_OUTPUT" | head -c 300)"
                    _workflow_push_cleanup
                    cd "$ORIG_DIR" || true
                    return
                fi

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
                fi
            else
                if echo "$WORKFLOW_COMMIT_OUTPUT" | grep -qiE "(blocked|not allowed|denied|restricted)"; then
                    test_pass "Workflow file change blocked before push by git safety"
                    info "Commit was denied before push; push-time validation remains covered by unit tests"
                else
                    test_fail "Failed to create workflow-file test commit"
                    info "Output: $(echo "$WORKFLOW_COMMIT_OUTPUT" | head -c 300)"
                    _workflow_push_cleanup
                    cd "$ORIG_DIR" || true
                    return
                fi
            fi

            # Test 2: Normal code push should still work after workflow block
            info "Testing normal code push still works..."
            _workflow_push_cleanup
            echo "# redteam test" > "$NORMAL_PATH"
            git add "$NORMAL_PATH"
            if git -c user.email=redteam@example.invalid \
                -c user.name="Redteam Test" \
                commit --quiet -m "redteam: normal code push test"; then
                NORMAL_PUSH_OUTPUT=$(git push --dry-run origin "HEAD:$SANDBOX_PUSH_BRANCH" 2>&1)
                NORMAL_PUSH_EXIT=$?

                if [[ $NORMAL_PUSH_EXIT -eq 0 ]]; then
                    test_pass "Normal code push succeeded after workflow block"
                elif _workflow_transport_unavailable "$NORMAL_PUSH_OUTPUT"; then
                    test_warn "Git push transport unavailable; skipping normal push assertion"
                    info "Output: $(echo "$NORMAL_PUSH_OUTPUT" | head -c 300)"
                elif echo "$NORMAL_PUSH_OUTPUT" | grep -qi "Push modifies blocked files" \
                    && ! echo "$NORMAL_PUSH_OUTPUT" | grep -q "$NORMAL_PATH"; then
                    test_warn "Normal push range already contains blocked baseline files; skipping normal push assertion"
                    info "Output: $(echo "$NORMAL_PUSH_OUTPUT" | head -c 300)"
                else
                    test_fail "Normal code push failed after workflow block (exit: $NORMAL_PUSH_EXIT)"
                    info "Output: $(echo "$NORMAL_PUSH_OUTPUT" | head -c 300)"
                fi
            else
                test_fail "Failed to create normal-code test commit"
            fi

            # Return to workspace
            _workflow_push_cleanup
            cd "$ORIG_DIR" || true

        else
            info "No git remote configured - skipping workflow push blocking test"
            _workflow_push_cleanup
            cd "$ORIG_DIR" || true
        fi

    else
        info "GIT_SHADOW_ENABLED not set - skipping workflow push blocking tests"
        info "  These tests require git shadow mode with push access to a test repo."
    fi
}
