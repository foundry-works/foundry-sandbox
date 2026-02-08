# Phase 5: Branch Cleanup on Destroy/Prune

## 5A. Add `cleanup_sandbox_branch()` helper

**File:** `lib/git_worktree.sh`

```bash
cleanup_sandbox_branch() {
    local branch="${1:-}"
    local repo_url="${2:-}"
    if [ -z "$branch" ] || [ -z "$repo_url" ]; then
        return 0
    fi

    local bare_path
    bare_path=$(repo_to_path "$repo_url")
    [ -d "$bare_path" ] || return 0

    # Don't delete well-known branches
    case "$branch" in
        main|master|develop|production) return 0 ;;
    esac
    case "$branch" in
        release/*|hotfix/*) return 0 ;;
    esac

    # Don't delete if another worktree still uses this branch
    # Use grep -xF for exact line match -- -F for fixed strings (branch may
    # contain regex metacharacters like "user/feature+fix"), -x for full-line
    # match (prevents "foo" matching "foobar")
    if git -C "$bare_path" worktree list --porcelain 2>/dev/null \
        | grep -qxF "branch refs/heads/$branch"; then
        return 0
    fi

    if git -C "$bare_path" branch -D "$branch" 2>/dev/null; then
        log_info "Cleaned up sandbox branch '$branch' from bare repo"
    fi
}
```

(`repo_to_path` exists in `lib/utils.sh` lines 102-112.)

## 5B. Call cleanup from destroy

**File:** `commands/destroy.sh` — **after** the worktree removal block (line 64), add:

```bash
# Clean up sandbox branch from bare repo (after worktree removal so the
# worktree-in-use check in cleanup_sandbox_branch doesn't find our own
# worktree and skip deletion)
load_sandbox_metadata "$name" 2>/dev/null || true
cleanup_sandbox_branch "${SANDBOX_BRANCH:-}" "${SANDBOX_REPO_URL:-}"
```

**Ordering note:** `cleanup_sandbox_branch()` checks `git worktree list` to verify no other worktree uses the branch before deleting it. If called *before* worktree removal, it would find the sandbox's own worktree and skip the deletion. The call must come *after* `remove_worktree` / worktree cleanup.

## 5C. Call cleanup from prune

**File:** `commands/prune.sh`

In the orphaned configs loop (**after** `remove_path "$config_dir"` at line 39). Load metadata *before* removing config (since metadata is in the config dir), but clean up the branch *after*. Clear variables at the top of each iteration to prevent stale values from a previous iteration leaking through when `load_sandbox_metadata` fails:

```bash
# Clear stale metadata from previous iteration
SANDBOX_BRANCH="" SANDBOX_REPO_URL=""
# Load metadata before config removal
load_sandbox_metadata "$name" 2>/dev/null || true
local _prune_branch="${SANDBOX_BRANCH:-}"
local _prune_repo="${SANDBOX_REPO_URL:-}"
```

Then after `remove_path "$config_dir"`:

```bash
cleanup_sandbox_branch "$_prune_branch" "$_prune_repo"
```

In the no-container loop (**after** `remove_worktree "$worktree_dir"` at line 65). Same variable clearing to prevent cross-iteration leaks:

```bash
# Clear stale metadata from previous iteration
SANDBOX_BRANCH="" SANDBOX_REPO_URL=""
load_sandbox_metadata "$name" 2>/dev/null || true
# Worktree is already removed above, so the in-use check will pass
cleanup_sandbox_branch "${SANDBOX_BRANCH:-}" "${SANDBOX_REPO_URL:-}"
```

**Limitation:** If the metadata file is already gone (common for orphaned sandboxes), `SANDBOX_BRANCH` won't be populated and cleanup silently no-ops. Orphaned branches from corrupted sandboxes accumulate until manual cleanup. This is the safe default — we don't want to guess which branches to delete.

## Verification

- Destroy a sandbox, verify its branch is removed from the bare repo
- Prune orphans, verify their branches are cleaned up
