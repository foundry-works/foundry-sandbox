# Phase 4: Server-Side Fetch Locking

## 4A. Per-repo file lock for fetch operations

**File:** `unified-proxy/git_operations.py`

### Bare repo resolver and lock context manager

```python
import fcntl
import time
from contextlib import contextmanager

def _resolve_bare_repo_path(repo_root: str) -> Optional[str]:
    """Resolve the bare repo path from a worktree's .git pointer.

    Follows the gitdir -> commondir chain:
      /git-workspace/.git  ->  "gitdir: /path/to/worktrees/sandbox-1"
      /path/to/worktrees/sandbox-1/commondir  ->  "../.."  (the bare repo)

    Works for all sandboxes regardless of metadata contents, since
    the .git file and commondir are always present in worktree setups.
    """
    git_file = os.path.join(repo_root, ".git")
    if not os.path.isfile(git_file):
        return None
    try:
        content = open(git_file).read().strip()
        if not content.startswith("gitdir:"):
            return None
        gitdir = content.split("gitdir:", 1)[1].strip()
        commondir_file = os.path.join(gitdir, "commondir")
        if not os.path.isfile(commondir_file):
            return None
        commondir = open(commondir_file).read().strip()
        if os.path.isabs(commondir):
            return commondir
        return os.path.normpath(os.path.join(gitdir, commondir))
    except (IOError, OSError):
        return None


@contextmanager
def _fetch_lock(bare_repo_dir: str, timeout: float = 30.0):
    """Context manager: per-repo file lock to serialize fetch operations.

    Yields True if the lock was acquired, raises TimeoutError on timeout.
    Guarantees fd is closed on exit (even if the caller raises).
    """
    lock_path = os.path.join(bare_repo_dir, ".foundry-fetch.lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_WRONLY, 0o644)
    deadline = time.monotonic() + timeout
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Concurrent fetch in progress")
                time.sleep(1.0)
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
```

**Lock path note:** The lock file is placed in the **bare repo directory**, not the worktree. Git ignores unknown files in bare repos (no working tree means no `git status` pollution), so this is harmless.

**Bare repo resolution:** `_resolve_bare_repo_path()` resolves the bare repo by following the worktree's `.git` file -> gitdir -> `commondir` chain. This works for all sandboxes without requiring `bare_repo_path` in metadata. The existing `metadata.get("bare_repo_path")` usage in `check_push_protected_branches()` (line 1023) is a pre-existing gap — `bare_repo_path` was never populated in metadata. Phase 7C closes this by switching push protection to `_resolve_bare_repo_path(repo_root)`.

**Sleep interval:** Set to 1.0s. Fetches take seconds; polling faster just wastes CPU. The 30s timeout is generous enough to absorb this.

### Wiring into `execute_git()`

In `execute_git()`, extract subcommand and wrap the subprocess call. Insert after the existing validation block and before the subprocess call (line ~1230):

```python
# Extract subcommand for fetch locking
subcommand = _get_subcommand(request.args)

# Serialize fetch and pull operations per bare repo
_FETCH_CMDS = {"fetch", "pull"}
bare_repo = _resolve_bare_repo_path(repo_root) if repo_root else None

if subcommand in _FETCH_CMDS and not bare_repo:
    audit_log(event="fetch_lock_unavailable",
              action=subcommand,
              decision="deny", command_args=request.args,
              reason="Unable to resolve bare repo path",
              matched_rule="fetch_lock", request_id=req_id)
    return None, ValidationError(
        "Cannot run fetch/pull: unable to resolve repository lock scope"
    )
elif subcommand in _FETCH_CMDS and bare_repo:
    try:
        with _fetch_lock(bare_repo):
            result = subprocess.run(cmd, ...)
    except TimeoutError:
        audit_log(event="fetch_lock_timeout",
                  action=subcommand,
                  decision="deny", command_args=request.args,
                  reason="Concurrent fetch in progress",
                  matched_rule="fetch_lock", request_id=req_id)
        return None, ValidationError(
            "Concurrent fetch in progress, try again later"
        )
else:
    result = subprocess.run(cmd, ...)
```

**Fallback behavior:** If `_resolve_bare_repo_path()` returns `None` for `fetch`/`pull`, fail closed by default and emit `fetch_lock_unavailable` audit logs. Add optional override (`FOUNDRY_ALLOW_UNLOCKED_FETCH=1`) for break-glass operation, but keep telemetry mandatory.

## Verification

- Run concurrent fetches from two sandbox proxies — no lock contention errors
- `git pull` is serialized
- `_resolve_bare_repo_path()` correctly follows `.git` -> gitdir -> commondir
- If lock scope cannot be resolved, fetch/pull is denied and `fetch_lock_unavailable` audit event is emitted
- Optional break-glass override allows operation only when explicitly set
