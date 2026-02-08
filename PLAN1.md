# PLAN 1: Self-Merge Prevention, Workflow Push Blocking, Git Hook Hardening, Read-Only FS Restoration

## Context

The comparison with the egg sandbox identified three infrastructure hardening improvements. Investigation reveals that items 2 and 3 are partially implemented — this plan closes the remaining gaps and adds the missing layer for item 4.

### Implementation Order and Dependencies

Items 2a, 2b, 3, and 4 are independent of each other. Implement in order of increasing risk: 3 → 2a → 4 → 2b, with an E2E smoke test after each. Item 3 is a two-line change (lowest risk, good warmup). Item 2a adds API patterns (moderate). Item 4 changes boot behavior (could prevent sandbox start). Item 2b adds pack inspection (highest complexity).

All changes build on top of the git policy hardening fixes on `tylerburleigh/foundry-sandbox-20260206-1024`. Check for merge conflicts with `main` before starting.

### Blast Radius

| Item | If implemented wrong | Recovery |
|------|---------------------|----------|
| 2a (self-merge API) | False positives: blocks legitimate comment-only reviews or benign API calls | Revert the pattern additions; no data loss |
| 2b (workflow push) | False positives: blocks legitimate CI config changes | Remove the restricted-paths check in git_proxy.py; no data loss |
| 3 (hook hardening) | Unlikely to break anything; adds defense-in-depth flags | Revert the two `-c` flags |
| 4 (read-only FS) | **Sandbox fails to boot** if CA bundle is missing or paths are wrong | Set `read_only: false` in compose override to restore previous behavior |

### Dual-Layer Blocking: Maintenance Contract

Items 2a and 2b add blocking rules to **both** the GitHub API Filter (`github-api-filter.py`) and the Policy Engine (`policy_engine.py`). This is intentional defense-in-depth — the API filter is the first line of defense (pattern matching on method + path), the policy engine is the second (can also inspect request bodies) — but it creates a maintenance obligation: **when a new endpoint is blocked, it must be added to both files.** Each file must include a single-line cross-reference:

```python
# github-api-filter.py:
# Defense-in-depth: also blocked in addons/policy_engine.py

# policy_engine.py:
# Defense-in-depth: also blocked in github-api-filter.py
```

**Enforceability:** A unit test (`test_dual_layer_endpoint_consistency`) makes this machine-enforced. See Item 2a testing section for details.

---

## Item 2a: Audit and Harden Self-Merge Prevention (API Layer)

### Current State (Already Strong)

Three independent layers already block PR merges:

1. **Policy Engine** (`unified-proxy/addons/policy_engine.py:450-451`) — blocks `PUT /repos/*/pulls/*/merge`
2. **GitHub API Filter** (`unified-proxy/github-api-filter.py:183,189`) — blocks REST merge endpoint + `POST /repos/*/merges`
3. **GraphQL blocking** (`unified-proxy/github-api-filter.py:148-149`) — blocks `mergePullRequest` and `reopenPullRequest` mutations

### Remaining Gaps

| Gap | Vector | Risk | Disposition |
|-----|--------|------|-------------|
| Auto-merge enablement | `PUT /repos/{owner}/{repo}/pulls/{number}/auto-merge` | Agent enables auto-merge; CI passes → merge happens without human | **Block** (this plan, Item 2a) |
| Review approval | `POST /repos/{owner}/{repo}/pulls/{number}/reviews` with `event: APPROVE` | Agent self-approves, satisfying branch protection | **Block APPROVE only** (this plan, Item 2a) |
| Update branch (REST) | `PUT /repos/{owner}/{repo}/pulls/{number}/update-branch` | Agent keeps PR up-to-date, auto-merge fires | **No action needed** — blocking auto-merge enablement neutralizes this vector. Updating a branch is benign without auto-merge. |
| Update branch (GraphQL) | `updatePullRequestBranch` mutation | Same as above, but via GraphQL | **Block** (this plan, Item 2a) — apply the same conservative approach as `addPullRequestReview`: the GraphQL mutation parser cannot inspect arguments, and this mutation performs a merge operation on the server. Block it entirely at the GraphQL level. REST equivalent is left open since auto-merge is blocked. |
| Review deletion | `DELETE /repos/{owner}/{repo}/pulls/{number}/reviews/{review_id}` | Agent deletes a blocking review to unblock merge | **Block** (this plan, Item 2a) |
| GitHub Actions trigger | Agent pushes workflow file that merges on CI pass | Indirect merge via Actions | **Block** (this plan, Item 2b) — block pushes that add/modify `.github/workflows/` files. Workflow changes are security-sensitive and should require human review regardless. |

### Changes

**File: `unified-proxy/github-api-filter.py`**

Add to `BLOCKED_PATTERNS`:
```python
# Defense-in-depth: also blocked in addons/policy_engine.py
("PUT", r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$", "auto-merge: enables automatic merge (requires human approval)"),
("DELETE", r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$", "auto-merge: disables automatic merge (requires human approval)"),
("DELETE", r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews/\d+$", "review deletion: removes review (requires human approval)"),
```

Note: PR review approval is NOT blocked at the path level because comment-only reviews and request-changes reviews are legitimate agent actions. Approval blocking is done via body inspection in the policy engine (see below).

Add to `ALWAYS_BLOCKED_GRAPHQL_MUTATIONS`:
```python
"enablePullRequestAutoMerge",
"disablePullRequestAutoMerge",
"dismissPullRequestReview",
"updatePullRequestBranch",  # Performs server-side merge; block conservatively
# addPullRequestReview: blocked entirely because the regex-based mutation parser
# cannot inspect GraphQL arguments (inline vs variables). APPROVE-only filtering
# would require a GraphQL AST parser. REST reviews are NOT blocked — body
# inspection in policy_engine.py selectively blocks only APPROVE events.
# Collateral: GraphQL comment/request-changes reviews are blocked. All major
# tools (gh, hub, Claude) use REST for reviews, so no functional impact.
"addPullRequestReview",
```

**Design decision: Block `addPullRequestReview` and `updatePullRequestBranch` entirely at the GraphQL level.** The regex-based mutation parser (`_check_graphql_mutations()` at line 331) only matches mutation names — it cannot inspect arguments (which can appear inline or in the `variables` object). Selective filtering would require a full GraphQL AST parser, which is out of scope. Review submission is available via REST with fine-grained `event` filtering. `updatePullRequestBranch` performs a server-side merge and has no legitimate sandbox use case.

**File: `unified-proxy/addons/policy_engine.py`**

Add patterns for auto-merge and review deletion:
```python
# Defense-in-depth: also blocked in github-api-filter.py
GITHUB_AUTO_MERGE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$")
GITHUB_DELETE_REVIEW_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews/\d+$")
```

Block in `_check_github_blocklist()` alongside existing merge block:
```python
# Block auto-merge enablement
if method in ("PUT", "DELETE") and GITHUB_AUTO_MERGE_PATTERN.match(path):
    return "GitHub auto-merge operations are blocked by policy"

# Block review deletion (prevents removing blocking reviews)
if method == "DELETE" and GITHUB_DELETE_REVIEW_PATTERN.match(path):
    return "Deleting pull request reviews is blocked by policy"
```

Add body inspection for PR review approval in `_check_github_body_policies()` (line 465). This follows the same pattern used for `state:closed` detection (lines 546-552):
```python
# Defense-in-depth: also blocked at GraphQL level in github-api-filter.py
GITHUB_PR_REVIEW_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$")

# In _check_github_body_policies(), add:
if method == "POST" and GITHUB_PR_REVIEW_PATTERN.match(path):
    event = parsed.get("event")
    if event is not None and str(event).upper() == "APPROVE":
        return "Self-approving pull requests is blocked by policy"
```

**File: `tests/unit/test_policy_engine.py`** (exists, 1877 lines, pytest + unittest.mock)

Add tests to existing file:
- `test_blocked_auto_merge_enable` — PUT auto-merge returns 403
- `test_blocked_auto_merge_disable` — DELETE auto-merge returns 403
- `test_blocked_pr_review_approve` — POST review with `{"event": "APPROVE"}` returns 403
- `test_allowed_pr_review_comment` — POST review with `{"event": "COMMENT"}` is allowed
- `test_allowed_pr_review_request_changes` — POST review with `{"event": "REQUEST_CHANGES"}` is allowed
- `test_blocked_pr_review_deletion` — DELETE review returns 403

**File: `tests/unit/test_github_api_filter.py`** (new file)

This file does not exist and must be created. Infrastructure needed:
- Import mitmproxy mocks from `conftest.py` (already set up in `tests/unit/conftest.py` — pre-mocks mitmproxy modules in `sys.modules`)
- Use `MockHTTPFlow` / `MockHTTPResponse` patterns from existing test files
- Use pytest fixtures for `GitHubAPIFilter` instantiation

Add tests (regression coverage for existing blocks + new blocks):
- `test_blocked_merge_rest` — PUT `/repos/.../pulls/.../merge` blocked (regression)
- `test_blocked_merge_graphql` — `mergePullRequest` mutation blocked (regression)
- `test_blocked_auto_merge_graphql` — `enablePullRequestAutoMerge` mutation blocked
- `test_blocked_disable_auto_merge_graphql` — `disablePullRequestAutoMerge` mutation blocked
- `test_blocked_add_review_graphql` — `addPullRequestReview` mutation blocked (all events)
- `test_blocked_dismiss_review_graphql` — `dismissPullRequestReview` mutation blocked
- `test_blocked_update_branch_graphql` — `updatePullRequestBranch` mutation blocked
- `test_blocked_auto_merge_rest` — PUT `/repos/.../auto-merge` blocked
- `test_blocked_delete_auto_merge_rest` — DELETE `/repos/.../auto-merge` blocked
- `test_blocked_delete_review_rest` — DELETE `/repos/.../reviews/123` blocked

**File: `tests/unit/test_dual_layer_consistency.py`** (new file)

Enforce the dual-layer blocking maintenance contract. The test defines a canonical list of security-critical operations and asserts both layers handle each one:

```python
BLOCKED_OPERATIONS = {
    "merge_pr": {
        "api_filter": ("PUT", "/repos/owner/repo/pulls/1/merge"),
        "policy_engine": ("PUT", "/repos/owner/repo/pulls/1/merge"),
    },
    "auto_merge_enable": {
        "api_filter": ("PUT", "/repos/owner/repo/pulls/1/auto-merge"),
        "policy_engine": ("PUT", "/repos/owner/repo/pulls/1/auto-merge"),
    },
    # ... one entry per operation ...
}
```

For each operation, the test sends a request through both `GitHubAPIFilter` and `PolicyEngine` and asserts both block it. Adding a new operation to this dict without implementing it in both layers causes a test failure. This is concrete and refactor-resistant — it tests behavior, not regex patterns.

**File: `tests/redteam-sandbox.sh`** (exists, 1239 lines, 22 test sections)

Add red-team tests (run inside sandbox):
- Attempt `gh pr merge` → expect 403
- Attempt `gh api -X PUT .../auto-merge` → expect 403
- Attempt `gh pr review --approve` → expect 403
- Attempt `gh pr review --comment -b "looks good"` → expect success (verifies non-approval reviews still work via REST)
- Attempt `gh api -X DELETE .../pulls/.../reviews/123` → expect 403
- Attempt GraphQL `updatePullRequestBranch` mutation → expect blocked

---

## Item 2b: Block Workflow File Pushes

### Threat

An agent can push a `.github/workflows/` file containing a workflow that merges PRs on CI pass (e.g., `gh pr merge` or a merge API call using the Actions-provided `GITHUB_TOKEN`). This bypasses all proxy-side merge blocking because the merge happens server-side on GitHub, using a different credential.

### Approach

Block pushes that add or modify files under `.github/workflows/`. The interception point is the git proxy addon (`unified-proxy/addons/git_proxy.py`), which already intercepts HTTPS push traffic to GitHub and parses pkt-line data to extract old/new SHAs for each ref being pushed.

The proxy is a pkt-line parser and HTTP forwarder — it does NOT run a local `git receive-pack`. The `request()` hook fires before the push is forwarded to GitHub. The new objects exist only in the pack data within the HTTP request body, not yet in the bare repo. Therefore, we must extract the pack data, unpack it into a temporary object store (with the bare repo as an alternate), and run `git diff-tree` to inspect which files changed.

**Why not a pre-receive hook?** The proxy architecture does not support it. A pre-receive hook requires a local `git receive-pack` step, which this proxy does not have — it parses pkt-lines and forwards the raw HTTP body. Adding local receive-pack would be a major architectural change with no benefit beyond this feature.

### Pack Data Extraction

The `_parse_git_request()` method (lines 264-296) already parses pkt-line headers using `read_pktline_prefix()` from `pktline.py`. This function reads the request body until it finds the flush packet (`0000`) that terminates the ref update list, and returns `pktline_end` — the byte offset where the header ends. Everything after `pktline_end` in the request body is pack data.

The `read_pktline_prefix()` function (pktline.py:138) already handles:
- Flush packet detection (`0000`)
- Capabilities lines interleaved with refs
- Max-bytes bounds checking (prevents memory exhaustion)
- Chunked reading from a BytesIO stream

So `pktline_end` is a reliable boundary marker — no additional protocol parsing is needed.

### Security Considerations for Untrusted Pack Data

The pack data comes from the sandbox (untrusted). Running `git unpack-objects` on adversarial input expands the attack surface on the proxy side — a memory-safety bug in git's pack parser could allow code execution on the proxy (the most privileged component). This is an **accepted risk** with the following mitigations:

1. **Timeout:** 10-second timeout on all subprocess calls (both `unpack-objects` and `diff-tree`). Guards against adversarial packs designed to hang.
2. **Isolation:** Unpack into a temporary directory, not the bare repo. The bare repo is never modified.
3. **Resource limits:** The existing push size limit (`DEFAULT_MAX_PUSH_SIZE = 100MB`, git_proxy.py:48) bounds the pack data size before it reaches this check.
4. **Fail closed:** Any error (unpack failure, diff-tree failure, timeout) blocks the push. No bypass via malformed data.
5. **Clean environment:** All git subprocesses run with a minimal environment (`PATH` + `HOME` only, plus the specific `GIT_OBJECT_DIRECTORY`/`GIT_ALTERNATE_OBJECT_DIRECTORIES` needed). The proxy's own `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CONFIG_PARAMETERS`, and other `GIT_*`/`SSH_*` vars are excluded via `_make_clean_git_env()`. This prevents (a) environment variable confusion that could cause the subprocess to operate on the wrong repository, and (b) credential leakage via `GIT_CREDENTIAL_TOKEN` or similar vars.
6. **Cleanup:** `shutil.rmtree` in `finally` block. If the proxy crashes between `mkdtemp` and `finally`, orphan dirs accumulate in `/tmp`. The container's tmpfs has a size limit and is cleaned on restart, so this is bounded.
7. **Concurrency:** The mitmproxy addon's `request()` hook runs synchronously per-connection in its default threading model. There is no concurrent execution of `_check_restricted_paths()`, so no semaphore or locking is needed. A malicious agent cannot DoS the proxy by issuing parallel pushes; they would simply queue. **Important:** This assumption depends on mitmproxy's default execution model (no `@concurrent` decorator, no `--set stream_large_bodies`). If the proxy's mitmproxy configuration is changed to enable concurrent addon execution, this code must be revisited. Add a code comment anchoring this assumption.

**Accepted risk rationale:** The alternative — parsing pack data in pure Python without invoking git — would be equally complex and untested against adversarial input, and would require reimplementing git's pack format, delta chain resolution, and tree parsing. Using git's own tooling is the pragmatic choice. This risk should be documented in `docs/security/sandbox-threats.md` under a new "Proxy-Side Attack Surface" section.

**Thin packs:** Git push sends thin packs by default — these reference delta base objects not included in the pack. `git unpack-objects` handles this because the alternates file points to the bare repo's object store, where the base objects exist. If the alternates link is broken or the bare repo is missing objects, `unpack-objects` fails and the push is blocked (fail-closed). No `git index-pack --fix-thin` is needed.

### Error Messages

Error messages returned to the sandbox are **generic** to prevent policy probing by an adversarial agent:

```python
# Good: generic
"Push blocked by security policy"

# Bad: reveals implementation details
"Push blocked: modifies '.github/workflows/ci.yml' which is in restricted path..."
```

The specific blocked path is logged server-side for debugging but not returned to the client.

### Changes

**File: `unified-proxy/addons/git_proxy.py`**

Add a restricted-paths check in the `request()` method, after the existing protected-branch checks (line 204-220). The pkt-line data is parsed in `_parse_git_request()` (lines 264-296):

```python
import subprocess
import tempfile
import shutil

# SHA-1 empty tree hash; update if GitHub adopts SHA-256 (fail-closed: wrong hash → nonzero exit → push blocked)
GIT_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf899d69f82623700"

def _make_clean_git_env(self, **extra) -> dict:
    """Build a minimal environment for git subprocesses in restricted-path checks.

    Uses only PATH (for finding the git binary) and HOME (required by git
    for config resolution). All GIT_* and SSH_* vars from the proxy's own
    environment are excluded to prevent interference (e.g., GIT_DIR,
    GIT_WORK_TREE, GIT_CONFIG_PARAMETERS could confuse the subprocess).
    """
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
    home = os.environ.get("HOME")
    if home:
        env["HOME"] = home
    env.update(extra)
    return env

def _check_restricted_paths(
    self,
    refs: List[PktLineRef],
    bare_repo_path: str,
    pack_data: bytes,
    restricted_paths: List[str],
) -> Optional[str]:
    """Block pushes that add or modify files in restricted paths.

    Because request() fires before the push is forwarded, the new objects
    exist only in the pack data (not yet in the bare repo). We unpack
    them into a temporary object store with the bare repo as an alternate
    so that both old and new SHAs resolve for git diff-tree.

    SECURITY NOTE: This runs git unpack-objects on untrusted pack data from
    the sandbox. A memory-safety bug in git's pack parser could allow code
    execution on the proxy. Mitigations: (1) pack data is bounded by
    DEFAULT_MAX_PUSH_SIZE (100MB) before reaching this point, (2) 10-second
    subprocess timeout, (3) unpack happens in an isolated temp directory,
    (4) minimal subprocess environment (no credential leakage), (5) fail-closed
    on any error. This is an accepted risk — the alternative (a full pack
    parser in Python) would be more complex and equally untested against
    adversarial input. See docs/security/sandbox-threats.md for the full
    threat model.

    Returns a generic error message if blocked, None if allowed.
    Logs the specific blocked path server-side for debugging.
    """
    if not pack_data:
        return None  # No pack data to inspect (e.g., delete-only push)

    # Normalize restricted paths defensively (strip trailing slashes)
    restricted_paths = [p.rstrip("/") for p in restricted_paths]

    tmp_dir = tempfile.mkdtemp(prefix="git-restricted-check-")
    try:
        # Initialize a proper bare repo so git commands have the structure
        # they expect (HEAD, refs/, objects/, etc.). Without this, commands
        # like diff-tree may fail with "not a git repository".
        subprocess.run(
            [GIT_BINARY, "init", "--bare", tmp_dir],
            capture_output=True,
            timeout=5,
            env=self._make_clean_git_env(),
        )

        # Point alternates at the real bare repo so old SHAs resolve
        objects_dir = os.path.join(tmp_dir, "objects")
        alt_file = os.path.join(objects_dir, "info", "alternates")
        os.makedirs(os.path.dirname(alt_file), exist_ok=True)
        with open(alt_file, "w") as f:
            f.write(os.path.join(bare_repo_path, "objects") + "\n")

        # Unpack the push's pack data into the temp object store
        result = subprocess.run(
            [GIT_BINARY, "unpack-objects"],
            input=pack_data,
            cwd=tmp_dir,
            capture_output=True,
            timeout=10,
            env=self._make_clean_git_env(GIT_OBJECT_DIRECTORY=objects_dir),
        )
        if result.returncode != 0:
            ctx.log.warn("[restricted-path] unpack-objects failed, blocking push (fail closed)")
            return "Push blocked by security policy"

        # Now diff-tree can resolve both old and new SHAs
        for ref in refs:
            if ref.is_deletion():
                continue

            old = GIT_EMPTY_TREE_SHA if ref.is_creation() else ref.old_sha

            try:
                dt_result = subprocess.run(
                    [GIT_BINARY, "diff-tree", "--name-only", "-r", old, ref.new_sha],
                    cwd=tmp_dir,
                    capture_output=True,
                    timeout=10,
                    env=self._make_clean_git_env(
                        GIT_OBJECT_DIRECTORY=objects_dir,
                        GIT_ALTERNATE_OBJECT_DIRECTORIES=os.path.join(bare_repo_path, "objects"),
                    ),
                )
                if dt_result.returncode != 0:
                    ctx.log.warn("[restricted-path] diff-tree failed, blocking push (fail closed)")
                    return "Push blocked by security policy"

                for line in dt_result.stdout.decode("utf-8", errors="replace").splitlines():
                    for restricted in restricted_paths:
                        if line == restricted or line.startswith(restricted + "/"):
                            ctx.log.info(
                                f"[restricted-path] blocked push modifying "
                                f"'{line}' (policy: '{restricted}/')"
                            )
                            return "Push blocked by security policy"
            except subprocess.TimeoutExpired:
                ctx.log.warn("[restricted-path] diff-tree timed out, blocking push (fail closed)")
                return "Push blocked by security policy"

    except subprocess.TimeoutExpired:
        ctx.log.warn("[restricted-path] unpack-objects timed out, blocking push (fail closed)")
        return "Push blocked by security policy"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return None
```

**Prerequisite: `bare_repo_path` must be populated in container metadata.**

Currently, `metadata.get("bare_repo_path")` always returns `None` — it is never set by any addon. The restricted-paths check depends on it to resolve old SHAs via alternates. Without it, the `if bare_repo_path and git_op.pack_data:` guard silently skips the check, making the entire feature a no-op.

**File: `unified-proxy/addons/container_identity.py`** (or wherever container metadata is populated)

Set `bare_repo_path` in the container metadata during container registration. The bare repo path follows a predictable convention based on the repo owner/name. Add:

```python
metadata["bare_repo_path"] = os.path.join(REPOS_BASE_DIR, owner, repo + ".git")
```

Where `REPOS_BASE_DIR` is the directory where the proxy stores bare repos (verify the actual path from the proxy's git clone/fetch logic). **If the bare repo doesn't exist yet (first push), the restricted-paths check must handle this gracefully** — see the `if bare_repo_path and os.path.isdir(bare_repo_path):` guard below.

Call this in the `request()` method alongside the existing write-operation checks:

```python
if git_op.is_write:
    # ... existing size checks, deletion checks, protected branch checks ...

    # Check for restricted file paths (e.g., .github/workflows/)
    bare_repo_path = metadata.get("bare_repo_path")
    if bare_repo_path and os.path.isdir(bare_repo_path) and git_op.pack_data:
        restricted_msg = self._check_restricted_paths(
            git_op.refs, bare_repo_path, git_op.pack_data,
            git_policies.DEFAULT_RESTRICTED_PUSH_PATHS,
        )
        if restricted_msg:
            self._deny_request(flow, restricted_msg)
            return
    elif git_op.pack_data and not bare_repo_path:
        # bare_repo_path not configured — log warning but don't block
        # This should not happen in production; indicates misconfiguration
        ctx.log.warn("[restricted-path] check skipped: bare_repo_path not in metadata")
```

Add `pack_data: bytes` field to `GitOperation` dataclass. In `_parse_git_request()`, after pkt-line parsing (line 284), extract the pack data. `pktline_end` is the byte offset returned by `read_pktline_prefix()` — it marks the end of the flush packet, so everything after it is pack data:

```python
# After line 284: refs = parse_pktline(buf[:pktline_end])
pack_data = body[pktline_end:] if pktline_end and pktline_end < len(body) else b""
```

Pass `pack_data` into the `GitOperation` constructor at line 288.

**File: `unified-proxy/git_policies.py`**

Add the restricted paths as a configurable policy (alongside existing `DEFAULT_PROTECTED_PATTERNS`):

```python
DEFAULT_RESTRICTED_PUSH_PATHS: List[str] = [
    ".github/workflows",
    ".github/actions",
]
```

Paths are stored without trailing slashes. The check uses `line == path or line.startswith(path + "/")` to match both the directory itself and any files underneath it. As a defensive measure, `_check_restricted_paths()` normalizes paths with `rstrip("/")` at runtime, so a misconfigured trailing slash in this list won't cause silent bypasses.

This allows future configurability (e.g., a sandbox owner may want to allow workflow edits for CI-focused tasks).

**File: `tests/unit/test_git_proxy.py`** (exists, 910 lines, pytest + unittest.mock)

Add tests to existing file:
- `test_blocked_push_workflow_file` — push containing `.github/workflows/ci.yml` change is blocked
- `test_blocked_push_actions_file` — push containing `.github/actions/custom/action.yml` change is blocked
- `test_allowed_push_normal_file` — push containing only `src/main.py` change is allowed
- `test_blocked_push_new_branch_with_workflow` — branch creation containing a workflow file is blocked
- `test_allowed_push_branch_deletion` — branch deletion is not inspected (no files to check)
- `test_fail_closed_on_diff_error` — if `git diff-tree` fails, push is blocked
- `test_fail_closed_on_unpack_error` — if `git unpack-objects` fails, push is blocked
- `test_temp_dir_cleanup` — temporary object store is cleaned up even on failure
- `test_error_message_is_generic` — returned error message does not contain file paths or restricted path names

**File: `tests/redteam-sandbox.sh`**

Add red-team test (run inside sandbox):
- Create a commit adding `.github/workflows/merge.yml`, attempt `git push` → expect rejection

### Design Notes

- **Object availability:** The `request()` hook fires BEFORE the push is forwarded to GitHub. The pkt-line header contains ref old/new SHAs, and the pack data follows in the same request body (after the flush packet at `pktline_end`). The old SHAs exist in the bare repo (current state), but the new SHAs are only in the pack data — they haven't been unpacked into the bare repo yet. Therefore, `git diff-tree old new` would fail if run directly against the bare repo. To resolve this, we extract the pack data from the request body, unpack it into a temporary object store that uses the bare repo as an alternate, then run `diff-tree` there. See `_check_restricted_paths()` above.
- **Flush packet boundary:** `read_pktline_prefix()` (pktline.py:138) already handles flush packet detection, capabilities parsing, and max-bytes bounding. The returned `pktline_end` is a reliable boundary — no additional protocol parsing is needed.
- **Fail closed:** If unpacking or `git diff-tree` fails or times out, the push is blocked. This prevents bypasses via malformed pack data.
- **Temp repo initialization:** The temporary directory is initialized with `git init --bare` to create a proper git repository structure (HEAD, refs/, objects/). Without this, `git diff-tree` may fail with "not a git repository." The alternates file is then written into the existing `objects/info/` directory to link the new objects with the real bare repo.
- **Empty tree SHA:** For new branch pushes (`old_sha` is all zeros), we diff against git's well-known empty tree hash (SHA-1) to enumerate all files in the new branch. Fail-closed if the hash doesn't resolve.
- **`.github/actions/` included:** Custom composite actions can also execute arbitrary code, including merge operations.
- **10-second timeout:** Each subprocess (`unpack-objects`, `diff-tree`) gets a 10-second timeout. Both should be near-instant on local data. The timeout guards against adversarial pack data.
- **Clean subprocess environment:** All git subprocesses use `_make_clean_git_env()` which provides only `PATH` and `HOME`, plus the specific `GIT_OBJECT_DIRECTORY`/`GIT_ALTERNATE_OBJECT_DIRECTORIES` needed for each call. This prevents the proxy's own git environment variables (e.g., `GIT_DIR`, `GIT_WORK_TREE`, `GIT_CREDENTIAL_TOKEN`) from leaking into or confusing the subprocess.
- **Path normalization:** Restricted paths are normalized with `rstrip("/")` at the start of the check, preventing a misconfiguration where a trailing slash in `DEFAULT_RESTRICTED_PUSH_PATHS` would cause the `startswith(restricted + "/")` check to look for a double slash and miss matches.
- **Cleanup:** The temporary directory is always removed in a `finally` block, even if the check fails. Orphan dirs from proxy crashes are bounded by tmpfs size limits and cleaned on container restart.
- **Generic error messages:** Error messages returned to the sandbox say "Push blocked by security policy" without revealing which path triggered the block or what paths are restricted. Specific details are logged server-side with `[restricted-path]` prefix for easy filtering via `docker logs <proxy-container> | grep restricted-path`.
- **Concurrency assumption anchor:** The code assumes single-threaded execution per mitmproxy's default addon model. A code comment must be added: `# THREADING: This method is not thread-safe. It relies on mitmproxy's default synchronous addon execution (no @concurrent decorator). If concurrent execution is enabled, add a threading.Lock around the entire method.`

---

## Item 3: Harden Git Hook Prevention on Proxy Side

### Current State

- **Sandbox side** (done): The sandbox-side `entrypoint.sh` sets `core.hooksPath=/dev/null` globally
- **Sandbox side** (done): `git_operations.py:333-339` blocks `-c core.hooksPath=...` and `-c core.fsmonitor=...` via CONFIG_NEVER_ALLOW
- **Proxy side** (gap): `execute_git()` at `git_operations.py:1803` builds `cmd = [GIT_BINARY] + translated_args` without injecting `-c core.hooksPath=/dev/null`. The proxy runs git on the worktree where `.git/hooks/` could contain malicious hooks from a cloned repo.

### Risk

If a malicious repository includes hooks (e.g., `post-merge`, `post-checkout`, `pre-push`), the proxy-side git execution could trigger them. The `build_clean_env()` function (line 1396) sanitizes environment variables but does NOT disable hooks via git config.

### Changes

**File: `unified-proxy/git_operations.py`**

At line 1803, where the command is built:

```python
# Current:
cmd = [GIT_BINARY] + translated_args

# Change to:
cmd = [
    GIT_BINARY,
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
] + translated_args
```

`core.hooksPath=/dev/null` disables all git hooks. `core.fsmonitor=false` disables the filesystem monitor, which can execute arbitrary commands via the `core.fsmonitor` config key — it is already in CONFIG_NEVER_ALLOW (line 339) for client-supplied args, but this ensures the proxy-side execution is also protected.

Placement before `translated_args` is safe: CONFIG_NEVER_ALLOW already blocks the client from sending either config key, so there is no last-wins override risk. The `--config` long form (used in clone options) is also covered: it is parsed by `get_subcommand_args()` and validated through the same `_validate_config_key()` path (line 625), so it cannot be used to override the injected `-c` flags.

Environment-variable-based config override is also safe: `GIT_CONFIG_PARAMETERS` is in `ENV_VARS_TO_CLEAR` (line 395), so it is explicitly cleared in the sanitized subprocess environment built by `build_clean_env()`. `GIT_CONFIG_COUNT` and `GIT_CONFIG_KEY_*`/`GIT_CONFIG_VALUE_*` are not in `ENV_ALLOWED` (the allowlist at line 413), so they are excluded from the clean env. No git config environment variable can reach the subprocess.

**File: `tests/unit/test_git_operations.py`** (exists)

Add tests:
- `test_proxy_side_hooks_disabled` — verify that `execute_git()` produces a command line containing `-c core.hooksPath=/dev/null` and `-c core.fsmonitor=false`
- `test_client_cannot_override_hooks_path` — verify that a client-supplied `--config core.hooksPath=/tmp/evil` or `-c core.hooksPath=/tmp/evil` is rejected by CONFIG_NEVER_ALLOW validation (returns a validation error, not silently overriding the injected flag)
- `test_client_cannot_override_fsmonitor` — verify that a client-supplied `-c core.fsmonitor=/tmp/evil` is rejected by CONFIG_NEVER_ALLOW validation

**File: `tests/security/test_git_policy.py`** (exists)

Add test:
- `test_hooks_disabled_in_execution` — verify hooks cannot execute during proxy-side git operations

---

## Item 4: Restore Read-Only Filesystem in Credential Isolation Mode

### Current State

`docker-compose.credential-isolation.yml:164` sets `read_only: false` to allow root writes in `entrypoint-root.sh`. The base `docker-compose.yml` sets `read_only: true` (line 13), but the credential-isolation override disables it.

Three root writes happen during boot:

| Write | File | Purpose | Works with read_only: true? |
|-------|------|---------|-----------------------------|
| 1 | `/etc/hosts` | Add unified-proxy hostname | **Yes** — Docker bind mount, writable regardless |
| 2 | `/etc/resolv.conf` | Set DNS to proxy IP | **Yes** — Docker bind mount, writable regardless |
| 3 | `/usr/local/share/ca-certificates/` + `update-ca-certificates` | Install mitmproxy CA | **No** — writes to root filesystem |

Write 3 is the only blocker. iptables (also in entrypoint-root.sh) modifies kernel netfilter state, not the filesystem.

### Existing tmpfs Mounts

The base `docker-compose.yml` already defines tmpfs mounts for all common writable paths:

- `/tmp` (512m, exec)
- `/var/tmp` (256m)
- `/run` (64m)
- `/var/cache/apt` (256m)
- `/var/lib/apt/lists` (128m)
- `/home/ubuntu` (configurable, default 2g)

These tmpfs mounts remain writable with `read_only: true`. Package installs via `apt` will fail (root FS is read-only), but `pip install --user` and `npm install` into `/home/ubuntu` will work since it's tmpfs.

### Solution: Combined CA Bundle via Shared Volume

Instead of running `update-ca-certificates` inside the sandbox, generate a combined CA bundle (system CAs + mitmproxy CA) in the proxy container and share it via the existing `mitm-certs` volume.

The proxy generates the bundle at `/etc/proxy/certs/ca-certificates.crt` (its `SHARED_CERTS_DIR`). The sandbox sees this at `/certs/ca-certificates.crt` via the volume mount `mitm-certs:/certs:ro` (compose line 141).

### Mode Detection

The sandbox-side entrypoint must distinguish between credential-isolation mode (combined bundle available, read-only FS) and legacy mode (no combined bundle, writable FS). Rather than using file-existence checks (fragile — any file at the path triggers the branch), use an explicit environment variable set in the compose file:

```yaml
# docker-compose.credential-isolation.yml
environment:
  - SANDBOX_CA_MODE=combined
```

The entrypoint checks `$SANDBOX_CA_MODE`:
- `combined` → use the combined bundle at `/certs/ca-certificates.crt`
- unset or any other value → legacy path (set env vars to mitmproxy cert, run `update-ca-certificates`)

This is explicit, auditable, and cannot be accidentally triggered.

### Changes

**File: `unified-proxy/entrypoint.sh`**

After `copy_ca_to_shared_volume()` (line 151), add a new function and call it:

```bash
# Generate combined CA bundle for sandbox containers.
# Includes system CAs + mitmproxy CA so sandboxes don't need to run
# update-ca-certificates (which requires a writable root filesystem).
generate_combined_ca_bundle() {
    local combined="${SHARED_CERTS_DIR}/ca-certificates.crt"
    local tmp="${combined}.tmp"
    # Write atomically: build in temp file, then rename.
    # Prevents sandbox from reading a partial bundle (system CAs only,
    # missing mitmproxy CA) if it starts between the two writes.
    cat /etc/ssl/certs/ca-certificates.crt > "$tmp"
    cat "${MITMPROXY_CA_CERT}" >> "$tmp"
    mv "$tmp" "$combined"
    log "Combined CA bundle generated at $combined"
}
```

Call `generate_combined_ca_bundle` immediately after `copy_ca_to_shared_volume`.

**File: `docker-compose.credential-isolation.yml`**

Remove the `read_only: false` override (line 157-164). The base compose already sets `read_only: true`, so removing the override restores it. Replace the comment block with:

```yaml
# Read-only filesystem is inherited from base compose (read_only: true).
# /etc/hosts and /etc/resolv.conf are Docker bind mounts (writable regardless).
# CA trust is handled via combined bundle in shared volume (no update-ca-certificates needed).
```

Update environment variables for the `dev` service:

```yaml
environment:
  # Explicit mode signal: tells sandbox entrypoint to use combined CA bundle
  # instead of running update-ca-certificates (which requires writable root FS)
  - SANDBOX_CA_MODE=combined
  # CA trust: combined bundle (system CAs + mitmproxy CA) from shared volume.
  # All five vars point to the combined bundle so that every TLS library
  # (OpenSSL, NSS, Node, Python requests, curl, git) trusts both system CAs
  # and the mitmproxy CA.
  - NODE_EXTRA_CA_CERTS=/certs/ca-certificates.crt
  - REQUESTS_CA_BUNDLE=/certs/ca-certificates.crt
  - SSL_CERT_FILE=/certs/ca-certificates.crt
  - CURL_CA_BUNDLE=/certs/ca-certificates.crt
  - GIT_SSL_CAINFO=/certs/ca-certificates.crt
```

All CA env vars point at the combined bundle (system CAs + mitmproxy CA) to ensure every TLS library works regardless of whether it treats the variable as additive or replacement.

**File: `entrypoint-root.sh`**

Remove the CA cert installation block (lines 51-57). Keep DNS and iptables setup (they work with read-only FS). The block to remove:

```bash
# Remove this block:
if [ -f "/certs/mitmproxy-ca.pem" ]; then
    echo "Adding mitmproxy CA to system trust store..."
    cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || true
fi
```

**File: `entrypoint.sh`**

The CA cert fallback section (lines 257-277) runs unconditionally when `/certs/mitmproxy-ca.pem` exists. This code path is shared between credential-isolation and non-credential-isolation modes, so the change must be conditional.

Replace lines 257-277 with:

```bash
# Trust mitmproxy CA when mounted (explicit proxy mode)
if [ -f "/certs/mitmproxy-ca.pem" ]; then
    echo "Configuring CA trust for proxy..."

    if [ "${SANDBOX_CA_MODE}" = "combined" ]; then
        # Combined bundle mode (credential-isolation with read-only FS).
        # Env vars (NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, etc.) are set
        # via docker-compose.credential-isolation.yml.
        #
        # The proxy generates the combined bundle early in its entrypoint,
        # before its health endpoint starts. The dev service uses
        # depends_on: condition: service_healthy, so the sandbox only
        # starts after the proxy's healthcheck passes — by which point the
        # bundle already exists. No polling needed.
        if [ ! -f "/certs/ca-certificates.crt" ]; then
            echo "FATAL: SANDBOX_CA_MODE=combined but /certs/ca-certificates.crt not found"
            echo "The proxy container may not be running or failed to generate the combined bundle."
            exit 1
        fi
        echo "Combined CA bundle available at /certs/ca-certificates.crt"

        # Defensive: set CA env vars here as a safety net in case compose-level
        # env vars are missing (e.g., manual SANDBOX_CA_MODE override without
        # the full compose environment). These are no-ops if already set by compose.
        export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-/certs/ca-certificates.crt}"
        export REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-/certs/ca-certificates.crt}"
        export SSL_CERT_FILE="${SSL_CERT_FILE:-/certs/ca-certificates.crt}"
        export CURL_CA_BUNDLE="${CURL_CA_BUNDLE:-/certs/ca-certificates.crt}"
        export GIT_SSL_CAINFO="${GIT_SSL_CAINFO:-/certs/ca-certificates.crt}"
    else
        # Legacy path: no combined bundle (standalone proxy or non-isolation mode).
        # Set env vars and attempt system CA store update.
        export NODE_EXTRA_CA_CERTS="/certs/mitmproxy-ca.pem"
        export REQUESTS_CA_BUNDLE="/certs/mitmproxy-ca.pem"
        export SSL_CERT_FILE="/certs/mitmproxy-ca.pem"
        export CURL_CA_BUNDLE="/certs/mitmproxy-ca.pem"
        export GIT_SSL_CAINFO="/certs/mitmproxy-ca.pem"
        if command -v update-ca-certificates >/dev/null 2>&1; then
            if [ "$(id -u)" = "0" ]; then
                cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
                update-ca-certificates >/dev/null 2>&1 || true
            elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
                sudo cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
                sudo update-ca-certificates >/dev/null 2>&1 || true
            elif [ -w "/usr/local/share/ca-certificates" ]; then
                cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
                update-ca-certificates >/dev/null 2>&1 || true
            fi
        fi
    fi
fi
```

This preserves the legacy `update-ca-certificates` path for non-credential-isolation configurations while using the combined bundle when `SANDBOX_CA_MODE=combined` is set.

**Behavioral change in legacy path:** The replacement code adds `GIT_SSL_CAINFO="/certs/mitmproxy-ca.pem"` to the legacy branch. The current code does NOT set this variable. This is an intentional improvement: without `GIT_SSL_CAINFO`, git-over-HTTPS relies solely on the system CA store update (which can fail silently on non-root containers). Adding it ensures git trusts the proxy CA even when `update-ca-certificates` fails.

**Startup ordering:** No polling loop needed. The proxy generates the combined bundle early in its entrypoint, before its health endpoint starts. The dev service uses `depends_on: condition: service_healthy` (already configured in `docker-compose.credential-isolation.yml`), so the sandbox only starts after the proxy's healthcheck passes. The entrypoint includes a single `test -f` guard as a safety net — if the bundle is missing, it exits fatally rather than producing a sandbox with broken TLS.

### Testing

**File: `tests/redteam-sandbox.sh`**

Add/modify tests:
- Verify filesystem is read-only: `touch /usr/bin/test-file 2>&1 | grep -q "Read-only"` → pass
- Verify CA trust works: `curl -s https://api.anthropic.com` → succeeds (via proxy)
- Verify git over HTTPS works: `git ls-remote https://github.com/...` → succeeds (via proxy)
- Verify combined CA bundle exists: `test -f /certs/ca-certificates.crt` → pass
- Verify SANDBOX_CA_MODE is set: `[ "$SANDBOX_CA_MODE" = "combined" ]` → pass
- Verify tmpfs is writable: `touch /tmp/test-file && rm /tmp/test-file` → pass
- Verify home is writable: `touch ~/test-file && rm ~/test-file` → pass

---

## Monitoring

All new blocking actions emit structured log entries for operator visibility. No alerting infrastructure is added — these are queryable via `sandbox.sh logs` or container log aggregation.

**API layer (Items 2a):** Both `github-api-filter.py` and `policy_engine.py` already log blocked requests via `ctx.log.warn()`. New blocks follow the same pattern. No additional logging needed.

**Git proxy (Item 2b):** `_check_restricted_paths()` logs the specific blocked path at `ctx.log.info()` level (server-side only — not returned to the sandbox). Failures (unpack error, diff-tree error, timeout) log at `ctx.log.warn()`. Add a structured prefix to all restricted-path log messages for easy filtering:

```python
ctx.log.info(f"[restricted-path] blocked push modifying '{line}' (policy: '{restricted}/')")
ctx.log.warn(f"[restricted-path] unpack-objects failed, blocking push (fail closed)")
```

**Operator debugging:** When a push is blocked with the generic "Push blocked by security policy" message, the operator can find the specific reason via `docker logs <proxy-container> | grep restricted-path`.

---

## Migration Notes

Existing running sandboxes are not affected by these changes — they use the compose config from their creation time. New sandboxes created after these changes land will get the hardened configuration automatically. There is no need to force-recreate existing sandboxes, but users who want the hardened config on existing sandboxes should run `./sandbox.sh stop <name> && ./sandbox.sh start <name>` (which recreates containers from the current compose config).

---

## Verification Plan

### Unit Tests
```bash
cd unified-proxy && python -m pytest tests/unit/ -v
```

### Integration Tests
```bash
cd unified-proxy && python -m pytest tests/integration/ -v
```

### End-to-End (run after each item)

1. Create a new sandbox with credential isolation: `./sandbox.sh new owner/repo`
2. Attach to sandbox: `./sandbox.sh attach <name>`
3. Inside sandbox, run red-team tests: `./tests/redteam-sandbox.sh`
4. Verify:
   - `touch /usr/bin/xxx` fails with "Read-only file system" (Item 4)
   - `touch /tmp/xxx && rm /tmp/xxx` succeeds (tmpfs still writable)
   - `touch ~/xxx && rm ~/xxx` succeeds (home tmpfs still writable)
   - `curl https://api.anthropic.com/...` works (credential injection + CA trust)
   - `git push` works for normal code changes (git wrapper + proxy)
   - Push containing `.github/workflows/` change is rejected (Item 2b)
   - `gh pr merge` fails with 403 (Item 2a)
   - `gh api -X PUT repos/.../pulls/.../auto-merge` fails with 403 (Item 2a)
   - `gh pr review --approve` fails with 403 (Item 2a)
   - `gh pr review --comment -b "test"` succeeds (non-approval reviews allowed via REST)
   - `gh api -X DELETE repos/.../pulls/.../reviews/123` fails with 403 (Item 2a)
   - Proxy logs show `[restricted-path]` prefix for blocked pushes (monitoring)

### Rollback

If Item 4 breaks sandbox boot:
1. In `docker-compose.credential-isolation.yml`, add back `read_only: false`
2. In `entrypoint-root.sh`, restore the CA cert installation block
3. Revert env var changes (point back to `/certs/mitmproxy-ca.pem`, remove `SANDBOX_CA_MODE`)

Items 2a, 2b, and 3 can be reverted independently by removing the added patterns/flags.

### Files Modified (Summary)

| File | Item | Change |
|------|------|--------|
| `unified-proxy/github-api-filter.py` | 2a | Add auto-merge, review deletion blocks (REST); block `addPullRequestReview`, `updatePullRequestBranch` entirely at GraphQL level; add auto-merge + dismiss review to `ALWAYS_BLOCKED_GRAPHQL_MUTATIONS` |
| `unified-proxy/addons/policy_engine.py` | 2a | Add auto-merge + review deletion patterns, review body inspection (REST `APPROVE` blocking) |
| `unified-proxy/addons/git_proxy.py` | 2b | Add restricted-paths check with temp object store for pack data inspection; add `pack_data` field to `GitOperation`; structured log prefixes; generic error messages |
| `unified-proxy/addons/container_identity.py` | 2b | Set `bare_repo_path` in container metadata (prerequisite for restricted-paths check) |
| `unified-proxy/git_policies.py` | 2b | Add `DEFAULT_RESTRICTED_PUSH_PATHS` config |
| `unified-proxy/git_operations.py` | 3 | Inject `-c core.hooksPath=/dev/null -c core.fsmonitor=false` at line 1803 |
| `unified-proxy/entrypoint.sh` | 4 | Generate combined CA bundle (atomic write via tmp+mv) |
| `docker-compose.credential-isolation.yml` | 4 | Remove `read_only: false` override, add `SANDBOX_CA_MODE=combined`, update CA env vars |
| `entrypoint-root.sh` | 4 | Remove CA cert installation block |
| `entrypoint.sh` | 4 | Conditional CA trust: `SANDBOX_CA_MODE=combined` vs legacy fallback |
| `docs/security/sandbox-threats.md` | 2b | New "Proxy-Side Attack Surface" section documenting untrusted pack data risk |
| `tests/unit/test_policy_engine.py` | 2a | Auto-merge, review approve/comment/request-changes, review deletion tests |
| `tests/unit/test_github_api_filter.py` | 2a | **New file.** GraphQL + REST auto-merge, review blocking, review deletion tests. Uses existing conftest.py mock infrastructure. |
| `tests/unit/test_dual_layer_consistency.py` | 2a | **New file.** Cross-layer consistency test enforcing dual-layer blocking contract between github-api-filter.py and policy_engine.py |
| `tests/unit/test_git_proxy.py` | 2b | Restricted-paths push tests (including temp unpack, fail-closed, cleanup, generic error messages) |
| `tests/unit/test_git_operations.py` | 3 | Hooks + fsmonitor disabled test, client override rejection tests |
| `tests/security/test_git_policy.py` | 3 | Hooks disabled integration test |
| `tests/redteam-sandbox.sh` | 2a, 2b, 4 | Self-merge, review deletion, updatePullRequestBranch, workflow push, read-only FS, CA trust, SANDBOX_CA_MODE, tmpfs tests |
