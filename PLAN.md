# Fix Shared Bare Repo Issues

## Context

Multiple sandboxes sharing the same git repository use a single bare repo at `~/.sandboxes/repos/{host}/{repo}.git`, each with its own worktree. This creates correctness bugs, cross-sandbox information leaks, and maintenance issues:

1. `repositoryformatversion=0` with `extensions.worktreeConfig=true` violates git spec
2. Docker Desktop VirtioFS caches stale inodes after `git config` atomic renames
3. `core.bare=true` (shared) conflicts with `core.worktree` (per-worktree) when extensions become visible
4. Any sandbox can read/diff/cherry-pick other sandboxes' branches
5. Any sandbox can delete other sandboxes' stale branches
6. `git branch -a` lists every sandbox's branch (namespace pollution)
7. Concurrent `git fetch` from multiple proxies causes lock contention
8. Destroyed sandboxes leave branches accumulating in the bare repo

---

## Phase 1: Correctness Bugs

### 1A. Bump `repositoryformatversion` to 1

**File:** `lib/git_worktree.sh` — `configure_sparse_checkout()`, after line 14

After setting `extensions.worktreeConfig=true`, bump version if < 1:

```bash
local current_version
current_version=$(git -C "$bare_path" config --get core.repositoryformatversion 2>/dev/null || echo "0")
if [ "$current_version" -lt 1 ] 2>/dev/null; then
    git -C "$bare_path" config core.repositoryformatversion 1
fi
```

### 1B. VirtioFS cache refresh in proxy

**File:** `lib/container_config.sh` — `fix_proxy_worktree_paths()` (already partially done)

After the existing `ls "$BARE_DIR"` cache refresh (line 2075), also explicitly read the config file to force inode refresh:

```bash
cat "$BARE_DIR/config" >/dev/null 2>&1 || true
```

Also defensively ensure `extensions.worktreeConfig` is set inside the proxy (handles case where host-side set was lost to VirtioFS):

```bash
git config --file "$BARE_DIR/config" extensions.worktreeConfig true 2>/dev/null || true
```

And bump `repositoryformatversion` inside the proxy too (idempotent):

```bash
local current_ver
current_ver=$(git config --file "$BARE_DIR/config" --get core.repositoryformatversion 2>/dev/null || echo 0)
if [ "$current_ver" -lt 1 ] 2>/dev/null; then
    git config --file "$BARE_DIR/config" core.repositoryformatversion 1
fi
```

**Ordering note:** The host-side `configure_sparse_checkout()` runs during `sandbox new` before the container starts. The proxy-side heredoc in `fix_proxy_worktree_paths()` runs on container startup. No concurrent write race exists — the proxy writes are purely defensive against VirtioFS losing the host-side writes.

### 1C. `core.bare` conflict — already fixed

`core.bare=false` is already set in `fix_proxy_worktree_paths()` at line 2079. No additional changes needed.

---

## Phase 2: Pass Sandbox Branch to Proxy Metadata

### 2A. Add `sandbox_branch` to registration metadata

**File:** `commands/new.sh` lines 1184-1188

```bash
metadata_json=$(jq -n \
    --arg repo "$repo_spec" \
    --arg allow_pr "$allow_pr" \
    --arg sandbox_branch "$branch" \
    '{repo: $repo, allow_pr: ($allow_pr == "true"), sandbox_branch: $sandbox_branch}')
```

(`$branch` is in scope — set at lines 837-843, possibly modified at line 988.)

**File:** `commands/start.sh` lines 166-170

```bash
metadata_json=$(jq -n \
    --arg repo "$repo_spec" \
    --arg allow_pr "${SANDBOX_ALLOW_PR:-0}" \
    --arg sandbox_branch "${SANDBOX_BRANCH:-}" \
    '{repo: $repo, allow_pr: ($allow_pr == "1"), sandbox_branch: $sandbox_branch}')
```

(`$SANDBOX_BRANCH` is loaded via `load_sandbox_metadata` at line 23.)

No changes needed to `git_api.py` or `registry.py` — the metadata dict flows through as opaque JSON via `registry.register()` → SQLite → `ContainerConfig.from_row()`.

**Legacy sandboxes:** Sandboxes created before this change will have no `sandbox_branch` in metadata. Phase 3 handles this gracefully — `validate_branch_isolation()` returns `None` (no isolation) when `sandbox_branch` is empty. This is an accepted limitation; legacy sandboxes must be re-created to get isolation.

---

## Phase 3: Cross-Sandbox Branch Isolation

### 3A. Add subcommand extraction helper, constants, and validators

**File:** `unified-proxy/git_operations.py`

Add `_get_subcommand()` helper (reuse the parsing pattern from `validate_command()` at lines 507-540):

```python
def _get_subcommand(args: List[str]) -> Optional[str]:
    """Extract the git subcommand from args, skipping global flags and -c options."""
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "-c" and idx + 1 < len(args):
            idx += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            idx += 1
            continue
        if not arg.startswith("-"):
            return arg
        idx += 1
    return None


def _get_subcommand_args(args: List[str]) -> Tuple[Optional[str], List[str]]:
    """Extract the git subcommand and its args from the full arg list."""
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "-c" and idx + 1 < len(args):
            idx += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            idx += 1
            continue
        if not arg.startswith("-"):
            return arg, args[idx + 1:]
        idx += 1
    return None, []
```

Add new constants:

```python
# Branches always accessible regardless of sandbox isolation
WELL_KNOWN_BRANCHES: FrozenSet[str] = frozenset({
    "main", "master", "develop", "production",
})

WELL_KNOWN_BRANCH_PREFIXES: Tuple[str, ...] = (
    "release/", "hotfix/",
)

# Commands that take ref arguments subject to isolation
_REF_READING_CMDS: FrozenSet[str] = frozenset({
    "log", "show", "diff", "blame", "cherry-pick", "merge",
    "rebase", "rev-list", "diff-tree",
})
```

Add `_is_allowed_ref()` helper:

```python
import re

def _is_allowed_ref(ref: str, sandbox_branch: str) -> bool:
    """Check if a ref is accessible to this sandbox.

    Allows: relative refs, well-known branches, own sandbox branch,
    remote tracking refs for allowed branches, tags, SHA hashes.
    Blocks: other sandboxes' branch names (local or remote).
    """
    # Relative refs (HEAD~2, @{upstream})
    if ref.startswith("HEAD") or "@{" in ref:
        return True

    # Range operators — check each side recursively
    for sep in ("...", ".."):
        if sep in ref:
            parts = ref.split(sep)
            return all(
                _is_allowed_ref(p.lstrip("^"), sandbox_branch)
                for p in parts if p
            )

    # Tags are always allowed
    if ref.startswith("refs/tags/") or ref.startswith("tags/"):
        return True

    # Remote tracking refs — apply same isolation to the branch name part
    if ref.startswith("refs/remotes/"):
        # refs/remotes/origin/branch-name → extract branch-name
        parts = ref.split("/", 3)  # ['refs', 'remotes', 'origin', 'branch-name']
        if len(parts) >= 4:
            return _is_allowed_branch_name(parts[3], sandbox_branch)
        return True
    if ref.startswith("origin/"):
        bare_ref = ref.removeprefix("origin/")
        return _is_allowed_branch_name(bare_ref, sandbox_branch)

    # Strip refs/heads/ prefix for comparison
    bare_ref = ref.removeprefix("refs/heads/")
    return _is_allowed_branch_name(bare_ref, sandbox_branch)


def _is_allowed_branch_name(name: str, sandbox_branch: str) -> bool:
    """Check if a bare branch name (no refs/heads/ prefix) is allowed."""
    # Well-known branches
    if name in WELL_KNOWN_BRANCHES:
        return True
    if any(name.startswith(p) for p in WELL_KNOWN_BRANCH_PREFIXES):
        return True
    # Own sandbox branch
    if name == sandbox_branch:
        return True
    # SHA hashes — require 12+ hex chars to avoid matching branch names
    # like "deadbeef" (full SHAs are 40 chars; 12 is git's default abbrev)
    if len(name) >= 12 and re.fullmatch(r'[0-9a-f]+', name):
        return True
    # Everything else is potentially another sandbox's branch
    return False
```

**Key changes from v1:**
- Remote tracking refs (`origin/*`, `refs/remotes/*`) are now filtered through the same isolation logic instead of being unconditionally allowed. This closes the bypass where sandbox A could `git log origin/sandbox-B-branch`.
- SHA minimum length raised from 7 to 12 to avoid false positives on hex-like branch names (e.g., `deadbeef`, `cafebabe`). Git's default abbreviated SHA is 12+ chars.
- Removed the fragile file-path heuristic (`"." in ref and "/" in ref`). Pathspecs are handled by `--` detection in the caller instead.
- Tags remain unconditionally allowed (accepted low risk — tagging requires write access).
- Extracted `_is_allowed_branch_name()` to share logic between local and remote ref checks.

Add `validate_branch_isolation()`:

```python
def validate_branch_isolation(
    args: List[str],
    metadata: Optional[dict] = None,
) -> Optional[ValidationError]:
    """Block access to other sandboxes' branches."""
    if not metadata:
        return None
    sandbox_branch = metadata.get("sandbox_branch", "")
    if not sandbox_branch:
        return None

    subcommand, subcommand_args = _get_subcommand_args(args)
    if subcommand is None:
        return None

    # Branch deletion guard
    if subcommand == "branch":
        if any(a in ("-d", "-D", "--delete") for a in subcommand_args):
            for arg in subcommand_args:
                if arg.startswith("-"):
                    continue
                if not _is_allowed_ref(arg, sandbox_branch):
                    return ValidationError(
                        f"Cannot delete branch '{arg}': belongs to another sandbox"
                    )
        return None  # branch listing handled by output filtering (3C)

    # Checkout/switch to another sandbox's branch
    if subcommand in ("checkout", "switch"):
        # Only check the first non-flag arg (the branch target)
        for arg in subcommand_args:
            if arg == "--":
                break  # Pathspecs after --
            if arg.startswith("-"):
                continue
            if not _is_allowed_ref(arg, sandbox_branch):
                return ValidationError(
                    f"Cannot checkout branch '{arg}': belongs to another sandbox"
                )
            break  # Only check the first positional (the target ref)
        return None

    # Ref-reading commands
    if subcommand not in _REF_READING_CMDS:
        return None

    for arg in subcommand_args:
        if arg.startswith("-"):
            continue
        if arg == "--":
            break  # Everything after -- is pathspecs, not refs
        if not _is_allowed_ref(arg, sandbox_branch):
            return ValidationError(
                f"Access denied: ref '{arg}' belongs to another sandbox"
            )
    return None
```

**Changes from v1:**
- Uses `_get_subcommand_args()` helper instead of inline parsing.
- Added `checkout`/`switch` to isolation (sandbox A shouldn't be able to switch to sandbox B's branch).

### 3B. Wire isolation into `execute_git()`

**File:** `unified-proxy/git_operations.py` — in `execute_git()`, after path args validation (line 1193), before push check (line 1195):

```python
# Check branch isolation
err = validate_branch_isolation(request.args, metadata)
if err:
    audit_log(event="branch_isolation_blocked",
              action=" ".join(request.args[:3]),
              decision="deny", command_args=request.args, reason=err.reason,
              matched_rule="branch_isolation", request_id=req_id)
    return None, err
```

### 3C. Output filtering for branch listing

**File:** `unified-proxy/git_operations.py` — in `execute_git()`, after path translation (line 1278), before constructing the response (line 1280):

```python
# Post-process branch listing output for isolation
if metadata and metadata.get("sandbox_branch"):
    stdout_str = _filter_branch_listing(
        request.args, stdout_str, metadata["sandbox_branch"]
    )
```

Add `_filter_branch_listing()`:

```python
_BRANCH_LINE_RE = re.compile(r'^([* ] +)(.+)$')
_REMOTE_BRANCH_LINE_RE = re.compile(r'^( +)(remotes/\S+)(.*)$')

def _filter_branch_listing(
    args: List[str], stdout: str, sandbox_branch: str,
) -> str:
    """Filter branch listing output to hide other sandboxes' branches."""
    subcommand = _get_subcommand(args)
    if subcommand != "branch":
        return stdout

    lines = stdout.split("\n")
    filtered = []
    for line in lines:
        if not line.strip():
            filtered.append(line)
            continue

        # Try matching "* branch" or "  branch" format (local branches)
        m = _BRANCH_LINE_RE.match(line)
        if m:
            branch_name = m.group(2).strip()
            # Handle "branch -> origin/branch" symref format
            if " -> " in branch_name:
                branch_name = branch_name.split(" -> ")[0]
            if _is_allowed_ref(branch_name, sandbox_branch):
                filtered.append(line)
            continue

        # Try matching remote branch format "  remotes/origin/branch"
        m = _REMOTE_BRANCH_LINE_RE.match(line)
        if m:
            ref = m.group(2).strip()
            if _is_allowed_ref(ref, sandbox_branch):
                filtered.append(line)
            continue

        # Unrecognized format — keep it (safe default)
        filtered.append(line)

    return "\n".join(filtered)
```

**Changes from v1:**
- Uses regex for branch name parsing instead of fragile `lstrip("* ")`.
- Handles remote branch format (`remotes/origin/foo`) separately.
- Handles `branch -> origin/branch` symref format.
- Dropped `for-each-ref` filtering — over-engineered for now; `git branch` covers the primary use case. Can add later if needed.
- Unrecognized lines are kept (fail-open for display, since isolation is enforced at the command level in 3A/3B).

---

## Phase 4: Server-Side Fetch Locking

### 4A. Per-repo file lock for fetch operations

**File:** `unified-proxy/git_operations.py`

Add lock class:

```python
import fcntl
import time

class _RepoFetchLock:
    """Per-repo file lock to serialize fetch operations."""

    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout

    def acquire(self, bare_repo_dir: str) -> Optional[int]:
        """Acquire exclusive lock on the bare repo. Returns fd or None on timeout."""
        lock_path = os.path.join(bare_repo_dir, ".foundry-fetch.lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_WRONLY, 0o644)
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    return None
                time.sleep(1.0)

    def release(self, fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

_fetch_lock = _RepoFetchLock()
```

**Lock path note:** The lock must be placed in the **bare repo directory**, not the worktree. The bare repo path is available via `metadata.get("bare_repo_path")` (already used in `check_push_protected_branches()` at line 1023-1025). If not available in metadata, fall back to resolving it from the worktree's `.git/commondir` file.

**Sleep interval:** Set to 1.0s (up from 0.5s). Fetches take seconds; polling faster just wastes CPU. The 30s timeout is generous enough to absorb this.

In `execute_git()`, extract subcommand and wrap the subprocess call. Insert after the existing validation block and before the subprocess call (line ~1230):

```python
# Extract subcommand for fetch locking
subcommand = _get_subcommand(request.args)

# Serialize fetch and pull operations per bare repo
_FETCH_CMDS = {"fetch", "pull"}
fetch_fd = None
if subcommand in _FETCH_CMDS:
    bare_repo = metadata.get("bare_repo_path") if metadata else None
    if bare_repo:
        fetch_fd = _fetch_lock.acquire(bare_repo)
        if fetch_fd is None:
            audit_log(event="fetch_lock_timeout",
                      action=subcommand,
                      decision="deny", command_args=request.args,
                      reason="Concurrent fetch in progress",
                      matched_rule="fetch_lock", request_id=req_id)
            return None, ValidationError(
                "Concurrent fetch in progress, try again later"
            )

try:
    result = subprocess.run(cmd, ...)
finally:
    if fetch_fd is not None:
        _fetch_lock.release(fetch_fd)
```

**Changes from v1:**
- Lock path uses `bare_repo_path` from metadata (not `resolved_cwd`, which points to the worktree).
- `git pull` is included in serialization (pull includes an implicit fetch).
- Uses `_get_subcommand()` helper for parsing.
- Sleep increased to 1.0s.

---

## Phase 5: Branch Cleanup on Destroy/Prune

### 5A. Add `cleanup_sandbox_branch()` helper

**File:** `lib/git_worktree.sh`

```bash
cleanup_sandbox_branch() {
    local name="$1"
    if [ -z "${SANDBOX_BRANCH:-}" ] || [ -z "${SANDBOX_REPO_URL:-}" ]; then
        return 0
    fi

    local bare_path
    bare_path=$(repo_to_path "$SANDBOX_REPO_URL")
    [ -d "$bare_path" ] || return 0

    # Don't delete well-known branches
    case "$SANDBOX_BRANCH" in
        main|master|develop|production) return 0 ;;
    esac
    case "$SANDBOX_BRANCH" in
        release/*|hotfix/*) return 0 ;;
    esac

    # Don't delete if another worktree still uses this branch
    if git -C "$bare_path" worktree list --porcelain 2>/dev/null \
        | grep -q "branch refs/heads/$SANDBOX_BRANCH"; then
        return 0
    fi

    git -C "$bare_path" branch -D "$SANDBOX_BRANCH" 2>/dev/null || true
}
```

(`repo_to_path` exists in `lib/utils.sh` lines 102-112.)

### 5B. Call cleanup from destroy

**File:** `commands/destroy.sh` — before the worktree removal block (line 64), add:

```bash
# Clean up sandbox branch from bare repo
load_sandbox_metadata "$name" 2>/dev/null || true
cleanup_sandbox_branch "$name"
```

### 5C. Call cleanup from prune

**File:** `commands/prune.sh`

In the orphaned configs loop (before `remove_path "$config_dir"` at line 39):

```bash
load_sandbox_metadata "$name" 2>/dev/null || true
cleanup_sandbox_branch "$name"
```

In the no-container loop (before `remove_worktree "$worktree_dir"` at line 65):

```bash
load_sandbox_metadata "$name" 2>/dev/null || true
cleanup_sandbox_branch "$name"
```

**Limitation:** If the metadata file is already gone (common for orphaned sandboxes), `SANDBOX_BRANCH` won't be populated and cleanup silently no-ops. Orphaned branches from corrupted sandboxes accumulate until manual cleanup. This is the safe default — we don't want to guess which branches to delete.

---

## Phase 6: Unit Tests

### 6A. Test `_is_allowed_ref` and `_is_allowed_branch_name`

**File:** `unified-proxy/test_git_operations.py` (or existing test file)

```python
import pytest
from git_operations import _is_allowed_ref, _is_allowed_branch_name

class TestIsAllowedRef:
    """Unit tests for branch isolation ref checking."""

    def test_head_relative(self):
        assert _is_allowed_ref("HEAD~2", "my-branch")
        assert _is_allowed_ref("HEAD", "my-branch")
        assert _is_allowed_ref("HEAD^", "my-branch")

    def test_upstream_ref(self):
        assert _is_allowed_ref("@{upstream}", "my-branch")
        assert _is_allowed_ref("branch@{1}", "my-branch")

    def test_own_branch(self):
        assert _is_allowed_ref("my-branch", "my-branch")
        assert _is_allowed_ref("refs/heads/my-branch", "my-branch")

    def test_well_known_branches(self):
        assert _is_allowed_ref("main", "my-branch")
        assert _is_allowed_ref("master", "my-branch")
        assert _is_allowed_ref("develop", "my-branch")
        assert _is_allowed_ref("release/1.0", "my-branch")
        assert _is_allowed_ref("hotfix/urgent", "my-branch")

    def test_other_sandbox_blocked(self):
        assert not _is_allowed_ref("other-sandbox-branch", "my-branch")
        assert not _is_allowed_ref("refs/heads/other-sandbox", "my-branch")

    def test_remote_other_sandbox_blocked(self):
        """Remote tracking refs for other sandboxes should be blocked."""
        assert not _is_allowed_ref("origin/other-sandbox", "my-branch")
        assert not _is_allowed_ref("refs/remotes/origin/other-sandbox", "my-branch")

    def test_remote_well_known_allowed(self):
        assert _is_allowed_ref("origin/main", "my-branch")
        assert _is_allowed_ref("refs/remotes/origin/main", "my-branch")
        assert _is_allowed_ref("origin/my-branch", "my-branch")

    def test_tags_allowed(self):
        assert _is_allowed_ref("refs/tags/v1.0", "my-branch")
        assert _is_allowed_ref("tags/v1.0", "my-branch")

    def test_sha_hashes(self):
        # 12+ hex chars → allowed (SHA)
        assert _is_allowed_ref("abcdef123456", "my-branch")
        assert _is_allowed_ref("a" * 40, "my-branch")
        # Short hex strings → blocked (could be branch names)
        assert not _is_allowed_ref("deadbeef", "my-branch")
        assert not _is_allowed_ref("cafebabe", "my-branch")

    def test_range_operators(self):
        assert _is_allowed_ref("main..my-branch", "my-branch")
        assert _is_allowed_ref("main...my-branch", "my-branch")
        assert not _is_allowed_ref("main..other-sandbox", "my-branch")

    def test_range_with_caret(self):
        assert _is_allowed_ref("^main..my-branch", "my-branch")


class TestValidateBranchIsolation:
    """Unit tests for the full isolation validator."""

    def test_no_metadata_allows_all(self):
        from git_operations import validate_branch_isolation
        assert validate_branch_isolation(["log", "anything"], None) is None

    def test_no_sandbox_branch_allows_all(self):
        from git_operations import validate_branch_isolation
        assert validate_branch_isolation(
            ["log", "anything"], {"sandbox_branch": ""}
        ) is None

    def test_blocks_other_branch_in_log(self):
        from git_operations import validate_branch_isolation
        err = validate_branch_isolation(
            ["log", "other-sandbox"], {"sandbox_branch": "my-branch"}
        )
        assert err is not None
        assert "other-sandbox" in err.reason

    def test_allows_own_branch(self):
        from git_operations import validate_branch_isolation
        assert validate_branch_isolation(
            ["log", "my-branch"], {"sandbox_branch": "my-branch"}
        ) is None

    def test_pathspecs_after_double_dash(self):
        from git_operations import validate_branch_isolation
        # Args after -- are pathspecs, not refs — should not be checked
        assert validate_branch_isolation(
            ["log", "--", "other-sandbox"], {"sandbox_branch": "my-branch"}
        ) is None

    def test_blocks_branch_deletion(self):
        from git_operations import validate_branch_isolation
        err = validate_branch_isolation(
            ["branch", "-D", "other-sandbox"], {"sandbox_branch": "my-branch"}
        )
        assert err is not None

    def test_blocks_checkout_other_branch(self):
        from git_operations import validate_branch_isolation
        err = validate_branch_isolation(
            ["checkout", "other-sandbox"], {"sandbox_branch": "my-branch"}
        )
        assert err is not None
```

---

## Files Modified Summary

| File | Changes |
|------|---------|
| `lib/git_worktree.sh` | Bump repoformatversion (1A), add `cleanup_sandbox_branch()` (5A) |
| `lib/container_config.sh` | VirtioFS cache refresh + defensive extensions set (1B) |
| `commands/new.sh` | Add `sandbox_branch` to proxy metadata (2A) |
| `commands/start.sh` | Add `sandbox_branch` to proxy metadata (2A) |
| `unified-proxy/git_operations.py` | Subcommand helpers (3A), branch isolation validator (3A), ref checker (3A), output filter (3C), wiring (3B), fetch lock (4A) |
| `commands/destroy.sh` | Load metadata + branch cleanup (5B) |
| `commands/prune.sh` | Load metadata + branch cleanup (5C) |
| `unified-proxy/test_git_operations.py` | Unit tests for isolation logic (6A) |

---

## Accepted Risks and Limitations

1. **Legacy sandboxes** created before Phase 2 have no `sandbox_branch` in metadata. They get no isolation. Must be re-created.
2. **Tag bypass:** Any sandbox can access any tag. Low risk — tagging requires write access that is already separately controlled.
3. **Orphaned branch accumulation:** If metadata is lost before destroy/prune, the sandbox branch can't be cleaned up automatically. Manual `git branch -D` in the bare repo is the escape hatch.
4. **Race in cleanup:** Between `load_sandbox_metadata` and `git branch -D`, another sandbox could theoretically start using the same branch. Mitigated by the `worktree list | grep` check; residual risk is negligible in practice.

---

## Verification

1. **Correctness (Phase 1):** Create a sparse checkout sandbox, exec into proxy, verify:
   - `git config --get core.repositoryformatversion` returns `1`
   - `git config --get extensions.worktreeConfig` returns `true`
   - `git sparse-checkout list` returns patterns (no "not sparse" error)
   - `git config --get core.sparseCheckout` returns `true`

2. **Metadata (Phase 2):** Create a sandbox, check proxy registration metadata includes `sandbox_branch`

3. **Branch isolation (Phase 3):** With two sandboxes on the same repo:
   - `git branch -a` from sandbox A should NOT list sandbox B's branch
   - `git log sandbox-B-branch` should be blocked
   - `git log origin/sandbox-B-branch` should be blocked (remote ref isolation)
   - `git cherry-pick <sandbox-B-commit>` by branch name should be blocked
   - `git branch -d <sandbox-B-branch>` should be blocked
   - `git checkout sandbox-B-branch` should be blocked
   - `git log main`, `git log origin/main`, `git log HEAD~3` should all work
   - `git log <12-char-sha>` should work

4. **Fetch locking (Phase 4):** Run concurrent fetches from two sandbox proxies — no lock contention errors. Also test `git pull` is serialized.

5. **Branch cleanup (Phase 5):** Destroy a sandbox, verify its branch is removed from the bare repo. Prune orphans, verify their branches are cleaned up.

6. **Unit tests (Phase 6):** `pytest unified-proxy/test_git_operations.py` — all tests pass covering ref checking, isolation validation, edge cases (SHAs, ranges, remote refs, pathspecs).
