# Phase 7: Hardening and Leak Closure

## 7A. Direct SHA reachability enforcement

**Goal:** Close the remaining code-access gap where known SHAs bypass branch-name controls. A sandbox that learns a SHA (e.g., from CI logs, shared docs) can currently `git show <sha>` or `git cherry-pick <sha>` without restriction, because SHAs >= 12 hex chars pass `_is_allowed_ref()`.

**File:** `unified-proxy/git_operations.py`

### Allowed-ref resolver

```python
import subprocess
from functools import lru_cache

def _get_allowed_refs(bare_repo: str, sandbox_branch: str) -> List[str]:
    """Build the list of refs this sandbox is allowed to access.

    Returns fully-qualified refs (refs/heads/*, refs/remotes/origin/*).
    """
    allowed = []
    # Own branch
    allowed.append(f"refs/heads/{sandbox_branch}")
    allowed.append(f"refs/remotes/origin/{sandbox_branch}")
    # Well-known branches
    for branch in WELL_KNOWN_BRANCHES:
        allowed.append(f"refs/heads/{branch}")
        allowed.append(f"refs/remotes/origin/{branch}")
    # Well-known prefixes -- resolve by listing matching refs
    for prefix in WELL_KNOWN_BRANCH_PREFIXES:
        try:
            result = subprocess.run(
                ["git", "-C", bare_repo, "for-each-ref",
                 "--format=%(refname)", f"refs/heads/{prefix}*"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        allowed.append(line)
                        # Add remote equivalent
                        short = line.removeprefix("refs/heads/")
                        allowed.append(f"refs/remotes/origin/{short}")
        except (subprocess.TimeoutExpired, OSError):
            pass
    # All tags
    allowed.append("refs/tags/")  # prefix -- any tag is reachable
    return allowed
```

### SHA reachability checker with per-request memoization

```python
def _check_sha_reachability(
    sha: str,
    bare_repo: str,
    allowed_refs: List[str],
    _cache: dict,
) -> bool:
    """Check if a SHA is reachable from any allowed ref.

    Uses `git merge-base --is-ancestor <sha> <ref>` for branch refs.
    Tags are checked via `git tag --contains <sha>` (any tag containing
    the SHA makes it reachable, since tags are globally allowed).

    Results are memoized in `_cache` (dict keyed by SHA) for the
    duration of the request. Typical cost: 1-3 subprocess calls per
    unique SHA (early-exit on first reachable ref).
    """
    if sha in _cache:
        return _cache[sha]

    # Check tag reachability first (single call, covers all tags)
    try:
        result = subprocess.run(
            ["git", "-C", bare_repo, "tag", "--contains", sha],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            _cache[sha] = True
            return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Check branch reachability -- early-exit on first match
    for ref in allowed_refs:
        if ref.startswith("refs/tags/"):
            continue  # Already checked above
        try:
            result = subprocess.run(
                ["git", "-C", bare_repo, "merge-base", "--is-ancestor",
                 sha, ref],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                _cache[sha] = True
                return True
        except (subprocess.TimeoutExpired, OSError):
            continue

    _cache[sha] = False
    return False
```

### Validation function

```python
_SHA_RE = re.compile(r'^[0-9a-f]{12,40}$')

def validate_sha_reachability(
    args: List[str],
    repo_root: str,
    metadata: Optional[dict] = None,
) -> Optional[ValidationError]:
    """Block SHA arguments that are not reachable from allowed refs.

    Only applies to ref-reading commands. Resolves the bare repo path
    and builds the allowed ref set once per call, then checks each
    SHA-like argument.

    Performance: per-request _cache dict memoizes results. Typical
    commands have 0-2 SHA arguments. The `merge-base --is-ancestor`
    call is O(commit-graph-depth) but git's commit-graph file makes
    this fast (~1-5ms for repos with commit-graph enabled).
    """
    if not metadata or not metadata.get("sandbox_branch"):
        return None

    subcommand, subcommand_args = _get_subcommand_args(args)
    if subcommand not in _REF_READING_CMDS:
        return None

    # Collect SHA-like positional args
    sha_args = []
    for arg in subcommand_args:
        if arg == "--":
            break
        if arg.startswith("-"):
            continue
        # Strip range operators and check each side
        for sep in ("...", ".."):
            if sep in arg:
                for part in arg.split(sep):
                    part = part.lstrip("^")
                    part = _strip_rev_suffixes(part)
                    if _SHA_RE.fullmatch(part):
                        sha_args.append(part)
                break
        else:
            cleaned = _strip_rev_suffixes(arg)
            if _SHA_RE.fullmatch(cleaned):
                sha_args.append(cleaned)

    if not sha_args:
        return None

    bare_repo = _resolve_bare_repo_path(repo_root)
    if not bare_repo:
        return ValidationError(
            "Cannot verify SHA reachability: unable to resolve bare repo"
        )

    sandbox_branch = metadata["sandbox_branch"]
    allowed_refs = _get_allowed_refs(bare_repo, sandbox_branch)
    cache: dict = {}

    for sha in sha_args:
        if not _check_sha_reachability(sha, bare_repo, allowed_refs, cache):
            return ValidationError(
                f"Access denied: commit {sha[:12]} is not reachable "
                f"from allowed refs. It may belong to another sandbox."
            )
    return None
```

### Wiring into `execute_git()`

After `validate_branch_isolation()` call, before push check:

```python
# Check SHA reachability (Phase 7A)
err = validate_sha_reachability(request.args, repo_root, metadata)
if err:
    audit_log(event="sha_reachability_blocked",
              action=" ".join(request.args[:3]),
              decision="deny", command_args=request.args, reason=err.reason,
              matched_rule="sha_reachability", request_id=req_id)
    return None, err
```

### Shallow clone handling

In shallow clones, `merge-base --is-ancestor` may return false negatives (the ancestor commit is pruned). Mitigation: if the bare repo has a shallow file (`$bare_repo/shallow` exists), skip SHA reachability checks and log a warning. Shallow repos are rare in the sandbox use case (full clones are the default), and the branch-name isolation from Phase 3 still provides the primary defense.

```python
# In validate_sha_reachability, before checking:
shallow_file = os.path.join(bare_repo, "shallow")
if os.path.isfile(shallow_file):
    logger.warning("SHA reachability check skipped: shallow repository")
    return None
```

## 7B. Close known branch-name leak channels

**File:** `unified-proxy/git_operations.py`

### 7B-1. Reflog isolation

`git reflog` and `git reflog show <ref>` accept ref arguments. Add `reflog` handling to `validate_branch_isolation()`:

```python
    # --- Reflog isolation ---
    # `git reflog show <ref>` or `git reflog <ref>` accepts a ref argument.
    # The default (no args) shows HEAD's reflog, which is per-worktree and safe.
    if subcommand == "reflog":
        sub_sub = subcommand_args[0] if subcommand_args else "show"
        if sub_sub in ("show", "list", "expire", "delete"):
            ref_args = subcommand_args[1:]
        elif not sub_sub.startswith("-"):
            # `git reflog <ref>` is shorthand for `git reflog show <ref>`
            ref_args = subcommand_args
        else:
            ref_args = []
        for arg in ref_args:
            if arg.startswith("-"):
                continue
            if not _is_allowed_ref(arg, sandbox_branch):
                return ValidationError(
                    f"Cannot access reflog for '{arg}': "
                    f"belongs to another sandbox"
                )
        return None
```

Insert this block in `validate_branch_isolation()` before the ref-reading commands section.

### 7B-2. `for-each-ref --format` custom output filtering

The `_filter_ref_enum_output()` function (defined in 3C) already includes two-pass filtering that handles custom `--format` output with short refnames. Pass 1 catches `refs/heads/<name>` patterns; pass 2 checks the first whitespace-delimited token as a potential short refname (e.g., `%(refname:short)` -> `main`).

### 7B-3. `git log --source` output filtering

`git log --source` appends the ref name that led to each commit (e.g., `abc1234\trefs/heads/other-sandbox`). Add source ref redaction:

```python
_SOURCE_REF_RE = re.compile(r'\trefs/heads/(\S+)')

def _filter_log_source_refs(stdout: str, sandbox_branch: str) -> str:
    """Redact --source refs from other sandboxes in git log output.

    --source appends a tab-separated ref to each commit line:
      abc1234\trefs/heads/branch  commit message

    Replace disallowed refs with a placeholder to preserve formatting.
    """
    lines = stdout.split("\n")
    filtered = []
    for line in lines:
        m = _SOURCE_REF_RE.search(line)
        if m:
            branch_name = m.group(1)
            if not _is_allowed_branch_name(branch_name, sandbox_branch):
                line = _SOURCE_REF_RE.sub('\t[redacted]', line)
        filtered.append(line)
    return "\n".join(filtered)
```

The `_filter_ref_listing_output()` dispatch (3C) already includes source-ref filtering via `_log_has_source_flag()`. Add the helper:

```python
def _log_has_source_flag(args: List[str]) -> bool:
    _, subcommand_args = _get_subcommand_args(args)
    return "--source" in subcommand_args
```

### 7B-4. `git notes` isolation

`git notes` refs are stored under `refs/notes/`. In shared bare repos, notes are visible across sandboxes. Add `notes` handling to `validate_branch_isolation()`:

```python
    # --- Notes isolation ---
    # `git notes` commands can reference note refs and object refs.
    # Block notes operations that specify a non-allowed ref.
    if subcommand == "notes":
        _NOTES_VALUE_FLAGS = frozenset({"--ref"})
        skip_next = False
        for arg in subcommand_args:
            if skip_next:
                # --ref <notesref> -- the notesref itself is not a branch,
                # but the target objects could leak. Allow default refs/notes/*.
                skip_next = False
                continue
            if arg in _NOTES_VALUE_FLAGS:
                skip_next = True
                continue
            if arg.startswith("-"):
                continue
            # Sub-subcommands (list, add, show, etc.) are fine.
            # Object arguments (SHAs) are checked by 7A reachability.
            # Branch-name arguments should be isolation-checked.
            if arg in ("list", "add", "copy", "append", "edit",
                        "show", "merge", "remove", "prune"):
                continue
            if not _is_allowed_ref(arg, sandbox_branch):
                return ValidationError(
                    f"Cannot access notes for '{arg}': "
                    f"belongs to another sandbox"
                )
        return None
```

## 7C. Push-protection path correctness follow-up

**File:** `unified-proxy/git_operations.py`

`check_push_protected_branches()` (line ~1023) uses `metadata.get("bare_repo_path")`, which was never populated in metadata. Replace with runtime resolution:

```python
def check_push_protected_branches(
    args: List[str],
    repo_root: str,
    metadata: Optional[dict] = None,
) -> Optional[ValidationError]:
    """Check if push targets a protected branch."""
    # ... existing refspec parsing ...

    # Resolve bare repo for default-branch detection
    bare_repo = _resolve_bare_repo_path(repo_root)
    if bare_repo:
        try:
            result = subprocess.run(
                ["git", "-C", bare_repo, "symbolic-ref", "HEAD"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                default_branch = result.stdout.strip().removeprefix("refs/heads/")
                protected.add(default_branch)
        except (subprocess.TimeoutExpired, OSError):
            pass

    # ... existing protection logic ...
```

Update the function signature at the call site in `execute_git()` to pass `repo_root`:

```python
# Before (broken -- bare_repo_path not in metadata):
err = check_push_protected_branches(request.args, metadata)

# After:
err = check_push_protected_branches(request.args, repo_root, metadata)
```

### Tests

```python
class TestPushProtection:
    """Tests for push-protection bare repo resolution."""

    def test_resolves_default_branch_from_bare_repo(self, tmp_path):
        """Protected branches should include the bare repo's HEAD target."""
        # Setup: create bare repo with HEAD -> refs/heads/main
        bare = tmp_path / "repo.git"
        subprocess.run(["git", "init", "--bare", str(bare)], check=True)
        # HEAD already points to refs/heads/main by default
        result = check_push_protected_branches(
            ["push", "origin", "main"], str(tmp_path), {}
        )
        assert result is not None  # main is protected

    def test_allows_push_to_sandbox_branch(self, tmp_path):
        bare = tmp_path / "repo.git"
        subprocess.run(["git", "init", "--bare", str(bare)], check=True)
        result = check_push_protected_branches(
            ["push", "origin", "my-feature"], str(tmp_path), {}
        )
        assert result is None  # non-protected branch
```

## Verification

- `git show <sha>` / `git cherry-pick <sha>` blocked when SHA is not reachable from allowed refs
- Same commands allowed when SHA is reachable from own or well-known refs
- SHA reachability skipped gracefully for shallow repos (warning logged, not denied)
- `git reflog show other-sandbox-branch` is blocked
- `git reflog` (no args, shows HEAD) works normally
- `git for-each-ref --format='%(refname:short)'` does not leak other sandbox branch names
- `git log --source` output redacts disallowed branch names with `[redacted]`
- `git notes show <other-sandbox-ref>` is blocked
- `git push origin main` correctly resolves bare repo for default-branch protection
- `git push origin my-feature` to non-protected branch is allowed
