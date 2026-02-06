# Plan: Git Policy Hardening for foundry-sandbox

## Goal

Add git policy hardening to foundry-sandbox, working within the existing mitmproxy addon architecture. Prioritized by security impact vs implementation cost.

---

## Phase 1: Git Hook Prevention

**Impact: HIGH | Complexity: Small**

> Moved ahead of protected branches per review: simpler (4 lines of shell), zero dependencies, and immediate risk reduction.

Malicious repos can run arbitrary code via git hooks (post-checkout, pre-commit, etc.). Disable hooks at the git config level inside the sandbox.

**File:** `entrypoint.sh`

Add a new git configuration section (the current `entrypoint.sh` has no git configuration section — lines 169-173 only *remove* legacy gateway gitconfig):
```bash
# Harden git configuration: disable hooks, fsmonitor, and unsafe defaults
# Prevents malicious repos from executing arbitrary code via git hooks
if [ "${SANDBOX_GIT_HOOKS_ENABLED:-0}" != "1" ]; then
    git config --global core.hooksPath /dev/null
    git config --global init.templateDir ''
    git config --global core.fsmonitor false
    git config --global core.fsmonitorHookVersion 0
    git config --global receive.denyCurrentBranch refuse
fi
```

Default OFF (hooks disabled). Controlled by `SANDBOX_GIT_HOOKS_ENABLED` env var (default `0`). The positive name avoids double-negative confusion (i.e., "set `SANDBOX_GIT_HOOKS_ENABLED=1` to enable hooks" is clearer than "set `SANDBOX_DISABLE_GIT_HOOKS=0` to not disable hooks").

`core.fsmonitor` and `core.fsmonitorHookVersion` are hardened in addition to `core.hooksPath` because `fsmonitor` can invoke an arbitrary executable — it's a hook by another name.

`receive.denyCurrentBranch=refuse` hardens against pushes to the current branch in case any local receive operations occur.

**Limitation:** This does not prevent an agent from running `chmod +x .git/hooks/post-checkout && .git/hooks/post-checkout` directly. That's a shell command, not a git hook execution. Phase 3's `.git/` shadow mitigates this by making hook files inaccessible.

**File:** `tests/redteam-sandbox.sh`

- Test: verify `core.hooksPath` is `/dev/null`
- Test: verify `core.fsmonitor` is `false`
- Test: verify `receive.denyCurrentBranch` is `refuse`
- Test: verify a repo with a malicious post-checkout hook doesn't execute it on clone
- Test (gated regression): when `GIT_SHADOW_ENABLED=true` (Phase 3 active), assert `git -c core.hooksPath=.git/hooks checkout ...` is blocked by flag validation. When Phase 3 is inactive, this is a **known residual risk** — the test documents the gap rather than asserting a pass/fail.

---

## Phase 2: Protected Branch Enforcement + Force Push Blocking

**Impact: HIGH | Complexity: Small-Medium**

Prevent direct pushes to `main`, `master`, `release/*`, and configurable branches. This goes beyond force-push flag blocking by blocking ALL pushes to protected branches.

Protected-branch policy is enforced across two execution paths by the end of Phase 3:
- mitmproxy path (`addons/git_proxy.py`) for native git Smart HTTP traffic
- git wrapper path (`/git/exec`) introduced in Phase 3

To avoid drift, implement one shared validator (e.g., `unified-proxy/git_policies.py`) and call it from both paths.

Phase 2 implementation scope:
- Enforce immediately in `addons/git_proxy.py` for Smart HTTP pushes
- Build shared validator in `git_policies.py` now
- Wire the same validator into `/git/exec` in Phase 3 when that endpoint exists

### Design decisions

**Default enabled for all modes.** The plan gates enforcement behind `metadata.git.protected_branches.enabled` defaulting to `true` for **all modes** (bot and normal). There is no legitimate reason for a sandbox user to push directly to `main` through the sandbox proxy — the sandbox exists for isolated work. Users who need this can explicitly set `enabled: false`.

**Branch creation policy.** Do not blanket-allow creation for protected branches. Only allow protected-branch creation for an explicit bootstrap case:
- ref is exactly `refs/heads/main` (or configured default branch), and
- initialization is still open according to an atomic lock file guard:
  - **Mechanism**: `os.open(path, O_CREAT | O_EXCL | O_WRONLY)` — atomic file creation that fails if the file already exists. This is a compare-and-set in one syscall; no TOCTOU race.
  - **Lock file path**: `<bare-repo-path>/foundry-bootstrap.lock` (e.g., `/home/ubuntu/.sandboxes/repos/<name>.git/foundry-bootstrap.lock`)
  - **Orphan handling**: Host-side cleanup of lock files older than 5 minutes with no corresponding branch (handles container crash mid-push). Implemented as a check in `commands/new.sh` or a periodic cleanup in `sandbox.sh`.
  - **Owned by**: `git_policies.py` — the shared validator creates and checks the lock file

All other create/update/delete operations on protected branches are blocked.

**Files:** `unified-proxy/git_policies.py`, `unified-proxy/addons/git_proxy.py`

- Add `DEFAULT_PROTECTED_PATTERNS = ["refs/heads/main", "refs/heads/master", "refs/heads/release/*", "refs/heads/production"]`
- Add shared `check_protected_branches(...) -> Optional[str]` helper in `git_policies.py`
- For each ref in `git_op.refs`: use `fnmatch.fnmatch(ref.refname, pattern)` against all protected patterns
- Block updates (`ref.is_update()`), deletions (`ref.is_deletion()`), and non-bootstrap creations on protected branches
- Call shared check before `_check_bot_mode_restrictions()` in `git_proxy.py` — protected branches apply to all modes, bot mode restrictions are additional
- Add TODO + test stub in Phase 2 for `/git/exec` parity; complete `/git/exec` call-site integration in Phase 3
- Read custom patterns from container metadata: `metadata.git.protected_branches.patterns` (list of fnmatch patterns)
- Gate behind `metadata.git.protected_branches.enabled` (default: `true` for all modes)

### Metadata plumbing

Use explicit precedence to avoid policy drift:

1. `flow.metadata.git.protected_branches.*` (authoritative per-sandbox policy)
2. `SANDBOX_PROTECTED_BRANCHES_*` env vars (global fallback defaults)
3. hardcoded defaults in code (`enabled=true`, default protected patterns)

Implementation note: metadata precedence is required from the first implementation. Env vars apply only when metadata keys are absent.

**File:** `tests/unit/test_git_proxy.py`

- Test: push (update) to `refs/heads/main` -> blocked
- Test: push (update) to `refs/heads/feature-x` -> allowed
- Test: push (update) to `refs/heads/release/v2.0` -> blocked (wildcard match)
- Test: push to custom protected branch from metadata -> blocked
- Test: branch creation to protected branch when remote already has heads -> blocked
- Test: bootstrap creation to `refs/heads/main` succeeds once, then second concurrent attempt is blocked
- Test: branch deletion to `refs/heads/main` -> blocked (already blocked by existing deletion check, but verify protected branches also catch it)
- Test: `metadata.git.protected_branches.enabled: false` -> no enforcement
- Test: default enabled for normal mode (not just bot mode)

---

## Phase 3: `.git/` Metadata Isolation via tmpfs Shadow + Flag Validation

**Impact: HIGH | Complexity: Large**

### Why this phase includes flag validation

The original Phase 6 (flag validation) is not optional — it is a _required component_ of `.git/` shadow security. Without flag validation in the git wrapper, an agent could bypass the shadow by passing `--git-dir=/some/path` or `-c core.hooksPath=/tmp/evil` to the proxied git command. Flag validation is merged here as a mandatory part of the wrapper implementation.

### Exfiltration threat

With `.git/` accessible, a compromised agent can:
- **Mine commit history for secrets:** `git log -p --all -S "API_KEY"` finds removed credentials
- **Browse other branches:** `git branch -a && git show origin/prod:config/secrets.yml`
- **Read reflog:** See what branches existed, what was checked out, what was reset
- **Exfiltrate via allowed channels:** Encode found secrets into commit messages, PR descriptions, or API request parameters to allowed services

This is the single largest data exfiltration surface in the current sandbox.

### Architecture

```
┌─────────────────────────────┐     ┌──────────────────────────────────┐
│  Sandbox (dev container)    │     │  Unified Proxy                   │
│                             │     │                                  │
│  /workspace/                │     │  /git-workspace/                 │
│    src/  (bind mount, RW)  ─┼─────┼─  src/  (same bind mount, RW)   │
│    .git/ (tmpfs, empty)     │     │    .git  (gitdir pointer file)   │
│                             │     │                                  │
│  /usr/local/bin/git         │     │  /home/ubuntu/.sandboxes/repos/  │
│    (wrapper script)        ─┼─HTTP┼─►  (real bare repo, RW)         │
│                             │     │                                  │
│  git status ──► wrapper     │     │  POST /git/exec                  │
│  git commit ──► wrapper     │     │    validates args                │
│  git push ──► wrapper       │     │    runs real git                 │
│                             │     │    returns JSON response         │
└─────────────────────────────┘     └──────────────────────────────────┘
         ↑ same physical files ↑
```

### Key design decisions

1. **Shared bind mount for working tree files**: Both containers mount the same host worktree directory. When the agent edits `/workspace/foo.py`, the proxy sees the same edit at `/git-workspace/foo.py`. This ensures `git status`/`git diff` are accurate.

2. **Gitdir pointer file**: The proxy's `/git-workspace/.git` is a gitdir pointer file (contains `gitdir: /home/ubuntu/.sandboxes/repos/<name>.git`). No `GIT_DIR` env var needed — git discovers the repo via this standard mechanism.

3. **tmpfs shadows the `.git` file**: A tmpfs mount at `/workspace/.git` in the sandbox creates an empty directory that hides the gitdir pointer. The agent cannot discover or follow the pointer.

4. **Proxy has real git access**: The proxy mounts both the worktree and the bare repo. The gitdir pointer resolves correctly inside the proxy container.

5. **Git wrapper proxies via HTTP**: All git commands in the sandbox are intercepted by a wrapper at `/usr/local/bin/git` that sends them to a TCP endpoint on the unified-proxy (port 8083, credential-isolation network only).

### Files to create

**`unified-proxy/git_operations.py`** — New Flask module for git execution API

- `POST /git/exec` endpoint: receives JSON `{args, cwd, stdin_b64}`, validates, runs git, returns JSON response
- **Authentication/identity**: derive caller identity from source IP and registry mapping (same trust model as mitmproxy path). `X-Container-Id` may be logged for diagnostics but is not trusted for authorization.
- **Rate limiting**: Per-container token bucket (300 requests/minute burst, 120 sustained) — higher than original plan because a Claude agent doing `git status` + `git diff` loops consumes 2 requests per iteration; at 30 sustained that's only 15 iterations/minute, which throttles normal workflows. Start high, tune down based on observed abuse.
  - **Backpressure signaling**: When rate-limited, the API returns HTTP 429 with a `Retry-After` header (seconds until next available token). The git wrapper prints a human-readable error: `"error: git rate limit exceeded. Try again in <N>s."` and exits with code 1. **No automatic retry** — the wrapper does not retry on 429 to avoid burning through burst budget when an agent retries the outer command.
- **Response format**: JSON `{"stdout": "<text>", "stderr": "<text>", "exit_code": <int>}` for text output. If stdout contains non-UTF-8 bytes, fall back to `{"stdout_b64": "<base64>", "stderr": "<text>", "exit_code": <int>}`
- **Max response size**: Truncate stdout at 10MB with warning in stderr. Prevents OOM on `git log --all` for large repos.
- **Exit code handling**: Capture signal-based exit codes (128+signal) correctly from subprocess.
- **Stdin support**: Accept optional `stdin_b64` field (base64-encoded) for commands that read from stdin (`git commit` with `-F -`, `git apply`, `git am`).

**Operation validation — deny-by-default allowlist (always enforced):**

Default-allow is too weak for a sandbox security boundary. Use an allowlist as the enforcement model from day one:

- Reject commands not in allowlist with `"git <command> is not allowed in sandbox mode"`
- No observe mode and no staged rollout toggle; policy is enforced whenever `GIT_SHADOW_ENABLED=true`

Initial allowlist, organized by category:

**Working tree & staging**: `status`, `add`, `restore`, `stash`, `clean --dry-run` (only `--dry-run`; bare `clean` blocked)

**Committing**: `commit`, `cherry-pick`, `merge`, `rebase` (non-interactive), `revert`

**Branching & navigation**: `branch`, `checkout`, `switch`, `tag`

**History & inspection**: `diff`, `show`, `log`, `blame`, `shortlog`, `describe`, `name-rev`

**Remote operations**: `fetch`, `pull`, `push`, `remote` (read-only subcommands: `remote -v`, `remote show`, `remote get-url`; blocked: `remote add`, `remote set-url`, `remote remove`, `remote rename`)

**Patch & mail**: `apply`, `am`, `format-patch`

**Notes**: `notes` (read-only: `notes list`, `notes show`; blocked: `notes add`, `notes remove`, `notes edit`)

**Config**: `config --get`, `config --list`, `config --get-regexp`

**Plumbing**: `rev-parse`, `symbolic-ref`, `for-each-ref`, `ls-tree`, `ls-files`, `ls-remote`, `cat-file`, `rev-list`, `diff-tree`, `diff-files`, `diff-index`

`reset` is excluded by default (safety over compatibility). All non-allowlisted commands are denied with: `"error: git <command> is not allowed in sandbox mode"` — the error message explicitly names the blocked command.

**Per-sandbox extension**: Additional commands can be allowed via `metadata.git.allowed_commands` (list of command strings). This enables operators to unblock commands for specific sandboxes without modifying the global allowlist.

**Per-operation flag validation — targeted blocklist (revised from blanket blocking):**

- `--git-dir`, `--work-tree` — block always (directory override)
- `--exec`, `--upload-pack`, `--receive-pack` — block always (arbitrary command execution)
- `-c` flag — **allowlist of permitted config key prefixes** (consistent with the command-level allowlist model; a blocklist requires tracking every new dangerous key across git versions):
  - Permitted prefixes: `user.*`, `color.*`, `core.quotepath`, `core.autocrlf`, `core.eol`, `core.whitespace`, `diff.*`, `merge.*`, `format.*`, `log.*`, `pretty.*`, `column.*`, `pager.*`
  - Everything else denied with: `"error: config key '<key>' is not allowed with -c in sandbox mode"`
  - Parse the key from `-c key=value` and check against the permitted prefix allowlist
- `--force` / `--force-with-lease` — **default deny for safety**:
  - Block on `push` (already handled by Phase 2 for protected branches, plus defense-in-depth)
  - Block on `checkout` / `switch` / `branch` destructive variants (e.g., `-f`, `-B`, `-D`)
  - Block on `clean` (`-f`, `-ff`, `-fd`, `-fdx`) because it permanently deletes local files
  - Block on all other force-like variants unless explicitly allowlisted after risk review and tests
- `reset` hardening:
  - Deny `git reset --hard` and mixed-mode reset forms that discard worktree/index changes
  - Keep `reset` out of the default allowlist; re-enable only with explicit policy exception
- Paths containing `..` or outside `/git-workspace`
- `-i` / `--interactive` on `rebase` (requires editor, not supported in proxy)

Git credential helper configured for push/fetch using proxy's `GITHUB_TOKEN`.

**`stubs/git-wrapper.sh`** — Shell script installed at `/usr/local/bin/git` in sandbox

- **Path detection algorithm** (concrete, per critique):
  1. Resolve candidate working directory from `-C <dir>` when present, else `$PWD`
  2. Canonicalize with symlink resolution (`realpath -m` / equivalent) before prefix checks
  3. Proxy only when canonical path is exactly `/workspace` or under `/workspace/`
  4. Reject ambiguous/unresolvable paths with explicit error (do not silently fall through)
  5. Otherwise, use `/usr/bin/git` directly (e.g., `git init /tmp/test`)
  - Note: `--git-dir` is blocked by flag validation, so it can't be used to bypass this check
- Sends JSON request to `http://unified-proxy:8083/git/exec`
- Parses JSON response, writes stdout/stderr, exits with returned exit code
- Falls through to real git for non-workspace operations
- **Proxy-down handling**: If HTTP request fails (connection refused, timeout after 30s), print clear error: `"error: git proxy is unavailable. Git operations require the sandbox proxy."` and exit 1. Does not hang.
- **Signal handling**: The wrapper traps `SIGINT` and `SIGTERM`:
  1. On signal, sends a best-effort cancellation request to the proxy (non-blocking, fire-and-forget)
  2. Exits immediately with code `128 + signal_number` (standard shell convention)
  3. The proxy kills the git subprocess when it detects the client has disconnected (TCP connection closed)
  - **Known limitation**: For `git push`, if the proxy has already forwarded the push to the remote, the remote-side push may complete even after wrapper cancellation. This is inherent to git's push protocol — once the remote receives the pack, the push is committed server-side. Document this in sandbox user guidance.

### Files to modify

**`docker-compose.credential-isolation.yml`**
- Dev service: add `tmpfs: /workspace/.git:mode=755,uid=1000,gid=1000,size=1m`
- Proxy service: add volume `${WORKSPACE_PATH}:/git-workspace` (same bind mount as sandbox)
- Proxy service: add volume `${REPOS_DIR:-/tmp/sandbox-repos}:/home/ubuntu/.sandboxes/repos` (bare repos, RW for commits)
- Proxy service: expose port 8083 on credential-isolation network (git API)
- Proxy service: add `GIT_SHADOW_ENABLED=true` env var

**`unified-proxy/git_api.py`** (new)
- Dedicated TCP app on port 8083 for `/git/exec` only
- Does **not** expose `/internal/*` registry routes

**`unified-proxy/internal_api.py`**
- Keep Unix-socket-only admin API as-is (`/internal/*` routes only)

**`unified-proxy/entrypoint.sh`**
- Start `git_api.py` if `GIT_SHADOW_ENABLED=true`
- Configure git credential helper inside proxy for push/fetch operations

**`entrypoint.sh`** (sandbox)
- If `GIT_SHADOW_ENABLED=true`: keep `/workspace/.git` tmpfs empty (do not populate metadata files)
- Install git wrapper: ensure `/usr/local/bin/git` takes precedence

**`commands/new.sh`**
- Create bare repo during sandbox creation: `git init --bare "${REPOS_DIR}/${sandbox_name}.git"` + set up gitdir pointer file
- Export `REPOS_DIR` and `WORKSPACE_PATH` for docker-compose variable substitution
- Handle new repos with no remote: `git init --bare` works regardless; the remote can be added later via the git wrapper

### Edge cases

- **`git push`/`git fetch`**: Proxy runs these with real credentials (configured credential helper), through the proxy-egress network. No mitmproxy loop — direct outbound from proxy container. Add explicit audit logging and verify outbound controls remain enforced (egress allowlist + token scope constraints).
- **Interactive commands** (`git rebase -i`): Blocked by flag validation (`-i` / `--interactive` on rebase). Run with `GIT_EDITOR=true` for non-interactive rebase.
- **Wrapper bypass via `/usr/bin/git`**: Without real `.git/`, `/usr/bin/git` fails with "not a git repository". Defense-in-depth.
- **Agent installing fresh git or replacing wrapper**: Credential-isolation mode sets `read_only: false` in docker-compose, so the root filesystem is **not** read-only. Three-tier mitigation:
  - **(a) Read-only bind mount**: Mount `/usr/local/bin/git` as a read-only bind mount (`:ro`) from the host, preventing in-container replacement of the wrapper.
  - **(b) `chattr +i` alternative**: If bind mount is impractical, set the immutable attribute (`chattr +i /usr/local/bin/git`) during entrypoint setup. Requires `CAP_LINUX_IMMUTABLE` or root.
  - **(c) Compensating control**: Even if the wrapper is bypassed or replaced, there is no real `.git/` directory in the sandbox — the tmpfs shadow ensures `/usr/bin/git` or any replacement has nothing to operate on.
  - `PATH` manipulation (`PATH=/usr/bin:$PATH git status`) is covered by (c): without `.git/`, the real git binary is inert.
  - `LD_PRELOAD` hooking of the wrapper is covered by (c) for the same reason.
- **Submodules**: Only top-level `.git` is shadowed. If an agent clones a repo with submodules, submodule initialization is blocked with a clear error message: `"error: git submodule operations are not supported in sandbox mode"`. Silent failure is not acceptable — the agent needs actionable feedback.
- **Binary output**: `git diff` with binary files, `git show <blob>` for images — base64 fallback handles this but doubles response size. Acceptable trade-off.

### Known limitation: `gh` CLI (verify first)

Assume as a risk until validated: `gh repo clone` and `gh pr checkout` may bypass the git wrapper depending on how `gh` resolves git execution in this container image. Validate behavior in a spike test before implementing policy around it.

**Impact assessment**: `gh` is used extensively by Claude agents for: `gh pr create`, `gh pr view`, `gh pr checkout`, `gh issue create`, `gh issue list`, `gh api`. Most of these use the GitHub API (not git transport) and only need the remote URL, which can be provided via environment variables. The git-transport commands (`gh repo clone`, `gh pr checkout`) are the ones that break.

**Mitigation (immediate)**: In sandbox CLAUDE.md stubs, instruct agents to use `git clone` and `git checkout` instead of `gh repo clone` and `gh pr checkout` when git shadow is enabled. Set `GH_REPO=owner/repo` environment variable so `gh pr create` and other API commands work without needing `.git/` to discover the remote.

**Mitigation (future)**: Install a `gh` wrapper that intercepts clone/checkout subcommands and routes them through the git operations API.

### Bare repo lifecycle

The bare repo is created by the host-side `commands/new.sh` during sandbox creation:
1. `new.sh` calls `ensure_bare_repo` (existing function in `lib/git.sh`) to create `${REPOS_DIR}/${sandbox_name}.git`
   - For new repos with no remote: `git init --bare` works standalone; no clone needed
   - For existing repos: `ensure_bare_repo` clones from the remote URL
2. `new.sh` writes gitdir pointer file at `${WORKSPACE_PATH}/.git` containing `gitdir: /home/ubuntu/.sandboxes/repos/${sandbox_name}.git`
3. Docker Compose mounts both paths into the proxy container
4. tmpfs overlays `/workspace/.git` in the sandbox container, hiding the gitdir pointer
5. `REPOS_DIR` defaults to `${FOUNDRY_DATA_DIR}/repos` on the host; defined in `lib/constants.sh`

**Container restart resilience**: The gitdir pointer file is on the host filesystem (not in a container layer), so it survives container restarts. The tmpfs overlay is recreated on each start (empty), which is the desired behavior.

### Design notes

The `.git/` shadow with tmpfs and proxied git commands provides strong isolation. All git operations are validated before execution through the unified-proxy infrastructure.

---

## Phase 4: GitHub API Endpoint Path Enforcement

**Impact: MEDIUM | Complexity: Medium**

> Moved ahead of PR/issue controls: path enforcement is a more fundamental security primitive that protects against entire categories of API abuse (webhooks, deploy keys, secrets management), while PR/issue close blocking addresses one specific destructive action.

`config/allowlist.yaml` already defines `http_endpoints` with method+path patterns per host (parsed into `HttpEndpointConfig` at `config.py:141-167`), but `policy_engine.py` only enforces domain-level allowlisting. Make the path patterns actually enforced.

### Design correction: segment-aware endpoint matching

`fnmatch` wildcards are too permissive because `*` can span `/`. Endpoint matching should use path-segment semantics where `*` matches exactly one segment.

### Implementation: Segment-Aware Allowlist + Explicit Blocklist

**Tier 1: Segment-aware allowlist** (required for `api.github.com`)
- Replace broad patterns like `/repos/*` with explicit segment-safe patterns (e.g., `/repos/*/*`, `/repos/*/*/pulls/*`)
- For hosts with endpoint entries: require `method` match and at least one segment-aware path match
- If host has NO endpoint entries: domain-level allowlisting still applies

**Tier 2: Dangerous path blocklist** (specific, checked after allowlist passes)
- Add a new `blocked_paths` section to `allowlist.yaml` for `api.github.com`:
  ```yaml
  blocked_paths:
    - host: api.github.com
      patterns:
        - "/repos/*/*/hooks"
        - "/repos/*/*/hooks/*"
        - "/repos/*/*/keys"
        - "/repos/*/*/keys/*"
        - "/repos/*/*/deploy_keys"  # also covered by /keys but explicit
        - "/repos/*/*/deploy_keys/*"
        - "/repos/*/*/environments/*/deployment-branch-policy"
        - "/repos/*/*/actions/secrets"
        - "/repos/*/*/actions/secrets/*"
        - "/repos/*/*/actions/variables"
        - "/repos/*/*/actions/variables/*"
  ```
- Use the same path-segment-aware matcher for blocklist patterns
- Check blocklist AFTER allowlist — a request must pass both

**File:** `unified-proxy/addons/policy_engine.py`

- After domain allowlist passes (Step 2, line 164), add Step 2b: endpoint path enforcement
- Look up host in `http_endpoints` list from loaded `AllowlistConfig`
- If host is `api.github.com` and endpoint entries exist: validate with segment-aware matching (not `fnmatch`)
- After allowlist passes, check against `blocked_paths` for the host
- **Path normalization before matching** (ordered steps):
  1. URL-decode (e.g., `%2F` -> `/`, `%2e` -> `.`)
  2. Strip trailing slashes
  3. Collapse `//` -> `/` (repeated separators)
  4. Resolve `..` segments (path traversal)
  5. Strip query string (matching is path-only)
  - Treat `;` as a literal character (no matrix parameter support)
- Cache compiled matchers at config load time for allowlist + blocklist patterns
- **Immediate scope**: Enforce endpoint/path rules for `api.github.com`. Other hosts (npm, PyPI, etc.) remain domain-level by design until explicit endpoint policies are added.

**File:** `unified-proxy/config.py`

- Add `BlockedPathConfig` dataclass (host + patterns list)
- Add `blocked_paths: List[BlockedPathConfig]` field to `AllowlistConfig` (optional, defaults to empty)
- Add path-segment matcher utility: `segment_match(pattern, path)` where `*` matches exactly one path segment

**File:** `config/allowlist.yaml`

- Add `blocked_paths` section for `api.github.com`
- Audit existing path patterns for completeness

**File:** `tests/unit/test_policy_engine.py`

- Test: `GET /repos/owner/repo` -> allowed (matches `/repos/*/*`)
- Test: `POST /repos/owner/repo/hooks` -> blocked (matches blocked_paths)
- Test: `GET /repos/../admin/keys` -> blocked (path normalization catches traversal)
- Test: `GET /repos/owner%2F..%2Fadmin/keys` -> blocked (URL decode before match)
- Test: `GET /repos/owner//repo/hooks` -> blocked (repeated separators normalized)
- Test: `GET /repos/owner/%2e%2e/admin/keys` -> blocked (encoded dot-segment traversal)
- Test: `GET /repos/owner%2frepo/hooks` -> blocked (`%2f` lowercase decode normalized)
- Test: hosts without endpoint config still allowed at domain level
- Test: `GET /repos/owner/repo/pulls/1` -> allowed (explicit allowlist pattern present)
- Test: `POST /repos/owner/repo/actions/secrets` -> blocked (in blocklist)
- Test: `/repos/owner/repo/hooks?callback=evil` -> blocked (query string stripped before match)
- Test: `/repos/owner/repo/` with trailing slash -> normalized and matched correctly

---

## Phase 5: PR and Issue Operation Controls

**Impact: MEDIUM | Complexity: Medium**

Foundry-sandbox already blocks PR merge (`PUT /repos/*/pulls/*/merge`) and release creation (`POST /repos/*/releases`) via `_check_github_blocklist()` at `policy_engine.py:248-266`. Extend to block PR close and issue close operations via body inspection.

**File:** `unified-proxy/addons/policy_engine.py`

- Add `GITHUB_PATCH_PR_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+$")`
- Add `GITHUB_PATCH_ISSUE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/issues/\d+$")`
- Add `_check_github_body_policies(self, method: str, path: str, body: bytes) -> Optional[str]` method
- For `PATCH /repos/{owner}/{repo}/pulls/{number}`: parse body with `json.loads(body)` (not string matching — handles whitespace, key ordering, nested objects)
- For `PATCH /repos/{owner}/{repo}/issues/{number}`: same logic (issue closing is equally destructive)
- Block requests where parsed body contains `"state": "closed"` (prevents agent from closing PRs/issues)
- Allow `"state": "open"` — reopening is not a destructive operation
- Allow body with no `state` key (title/description edits)
- Handle malformed JSON body safely — deny targeted PATCH request with explicit error (fail closed on security-relevant endpoint)
- **Streaming mode handling (fail closed)**: If `flow.request.content is None` (mitmproxy streaming mode), block the request with an explicit error rather than skipping body inspection. This prevents bypass via streaming mode:
  ```python
  if flow.request.content is None:
      flow.response = http.Response.make(
          400,
          b'{"error": "Request body required for PATCH on security-relevant endpoint"}',
          {"Content-Type": "application/json"},
      )
      return
  ```
- Call `_check_github_body_policies()` in the `request()` hook after `_check_github_blocklist()` at the Step 3 blocklist check (lines 175-188)
- Log blocked operations with structured metadata

**File:** `tests/unit/test_policy_engine.py`

- Test: `PATCH /repos/o/r/pulls/1` with `{"title": "new"}` -> allowed
- Test: `PATCH /repos/o/r/pulls/1` with `{"state": "closed"}` -> blocked
- Test: `PATCH /repos/o/r/pulls/1` with `{"state": "open"}` -> allowed (reopen)
- Test: `PATCH /repos/o/r/pulls/1` with `{"state": "closed", "title": "new"}` -> blocked (state takes precedence)
- Test: `PATCH /repos/o/r/pulls/1` with malformed JSON body -> blocked with parse error reason
- Test: `PATCH /repos/o/r/pulls/1` with `content=None` (streaming mode) -> blocked with explicit error
- Test: `PATCH /repos/o/r/issues/1` with `{"state": "closed"}` -> blocked
- Test: `PATCH /repos/o/r/issues/1` with `{"state": "open"}` -> allowed
- Test: existing merge block still works

---

## ~~Phase 6: Git Flag Validation~~ -> Merged into Phase 3

Flag validation is a required component of the git wrapper in Phase 3, not an optional afterthought. See Phase 3's "Per-operation flag validation" section for the full specification.

---

## Out of Scope

| Feature | Reason to Skip |
|---|---|
| Per-agent branch ownership | `sandbox/*` prefix restriction (`git_proxy.py:50,291-293`) restricts bot-mode pushes to sandbox branches. Any agent can push to any `sandbox/*` branch, but this is adequate for single-tenant sandboxes where only one agent operates at a time. Multi-tenant branch ownership is out of scope. |
| Per-operation flag allowlists | **Deliberate security model difference.** Per-operation flag _allowlists_ (only explicitly permitted flags pass) cause high user friction (every new flag requires policy update). foundry-sandbox uses a command-level allowlist with a per-operation flag _blocklist_ (known-dangerous flags are blocked, others pass). This is a weaker model — new dangerous flags in future git versions are allowed until the blocklist is updated. The trade-off is intentional: foundry-sandbox prioritizes usability in single-tenant sandboxes where the compensating control is the command-level allowlist + `.git/` shadow. |
| Custom Flask gateway | mitmproxy addon chain + git operations API endpoint achieves the same result within existing architecture. |

---

## Cross-Cutting Concerns

### Testing gaps to address

- **Concurrency**: Multiple simultaneous git operations through the wrapper — verify no race conditions in bare repo access
- **Large repos**: Stress test with repos >1GB — max response size of 10MB with truncation + warning prevents OOM
- **Proxy-down fallback**: Wrapper fails with clear error message after 30s timeout, does not hang
- **Security regression**: Automated tests that attempt known bypass patterns (flag injection, path traversal, direct `/usr/bin/git` access)

### Audit logging

All security-relevant events emit structured JSON to stdout, consistent with the existing `logging_config.py` pattern.

**Base schema** (all events):
```json
{
  "timestamp": "ISO-8601",
  "event": "git.command.blocked | git.command.allowed | git.push.blocked | api.request.blocked | api.body.blocked",
  "container_id": "<sandbox-container-id>",
  "action": "<specific action, e.g., 'push refs/heads/main'>",
  "reason": "<human-readable denial reason or 'allowed'>",
  "component": "git_wrapper | git_proxy | policy_engine | git_operations"
}
```

**Event-specific fields by component:**

- **Git wrapper** (`git_operations.py`): `command` (the git subcommand), `args` (sanitized argument list — see exclusions below), `exit_code`, `duration_ms`
- **Policy engine** (`policy_engine.py`): `method`, `host`, `path`, `rule` (which policy matched), `mode` (bot/normal)
- **Git proxy** (`git_proxy.py`): `refname`, `ref_type` (create/update/delete), `protected` (bool), `pattern_matched`

**Sensitive data exclusion rules:**
- Never log `stdin_b64` content (may contain commit messages with secrets)
- Never log `Authorization` header values
- Truncate `stdout`/`stderr` in logs to 1KB (reference full output by request ID)
- Never log environment variable values (only names)

**Integration points:**
- Git wrapper: log on every request (allowed and blocked) to `/git/exec`
- Policy engine: log on every blocked request in `request()` hook; log allowed requests at DEBUG level
- Git proxy: log on every ref operation (push/fetch) with ref details
- Protected branch enforcement: log on every block with the matched pattern

### `gh` CLI handling

Behavior must be confirmed in this environment before policy assumptions are made:
- Run a spike test to determine whether `gh repo clone` / `gh pr checkout` invoke `/usr/local/bin/git` or bypass it
- If bypass is confirmed, expect failure under git shadow (safe but confusing) and document fallback commands
- `gh pr create`, `gh issue list`, `gh api` should continue to work with `GH_REPO` set because they primarily use GitHub API calls
- **Immediate mitigation**: In sandbox CLAUDE.md stubs, recommend `git clone`/`git checkout` equivalents and set `GH_REPO`
- **Future mitigation**: `gh` wrapper that intercepts clone/checkout and routes through git operations API

### Out of scope

The following concerns from the critique are explicitly out of scope for this plan:
- **Rollback / feature flag strategy**: Not needed. Sandboxes are ephemeral — destroy and recreate.
- **Migration of existing sandboxes**: Not needed. Same reason — no long-lived state to migrate.

---

## Verification Plan

After implementation, run these checks:

### Phase 1: Git Hook Prevention
```bash
# Inside sandbox
git config --global core.hooksPath
# Expected: /dev/null

git config --global core.fsmonitor
# Expected: false

git config --global receive.denyCurrentBranch
# Expected: refuse

# Clone a local fixture repo with malicious hooks (deterministic)
git clone /tmp/test-fixtures/hook-test.git /tmp/hooktest
cd /tmp/hooktest && git checkout main
# Expected: no hook execution

# Gated regression test: override attempt
if [ "${GIT_SHADOW_ENABLED:-}" = "true" ]; then
    git -c core.hooksPath=.git/hooks checkout main
    # Expected: BLOCKED by Phase 3 wrapper flag validation
else
    # Known residual risk: without Phase 3, local -c overrides bypass hook prevention
    # Document gap; do not assert pass/fail
    echo "SKIP: Phase 3 not active — local -c override is a known residual risk"
fi
```

### Phase 2: Protected Branches
```bash
# Inside sandbox (any mode)
git push origin main
# Expected: rejected by proxy — "Push to protected branch refs/heads/main is blocked"

git push origin sandbox/my-feature
# Expected: success

git push origin release/v2.0
# Expected: rejected — wildcard match on "refs/heads/release/*"

# First push to create main (from empty repo)
git push origin main  # when ref.is_creation() == True
# Expected: success only for first initializer (atomic bootstrap guard)

# Create protected branch after repo already initialized
git push origin HEAD:production
# Expected: rejected (non-bootstrap protected branch creation blocked)

# Concurrency check (run two pushes at once on empty remote)
# Expected: exactly one succeeds, one is rejected
```

### Phase 3: Git Shadow + Flag Validation
```bash
# Inside sandbox
ls -la /workspace/.git
# Expected: empty tmpfs directory (no git metadata files)

ls /workspace/.git/objects/
# Expected: empty or not found

git log --all
# Expected: works via wrapper, returns proxied result

git --git-dir=/tmp/evil status
# Expected: rejected by wrapper — "--git-dir is not allowed"

git -c core.hooksPath=/tmp/evil status
# Expected: rejected by wrapper — "config key 'core.hooksPath' is not allowed with -c"

git -c user.name="Test" commit -m "test"
# Expected: allowed — user.* is in the permitted config key prefix allowlist

git checkout --force main
# Expected: rejected by wrapper — destructive force checkout is blocked (safety over compatibility)

/usr/bin/git status
# Expected: "fatal: not a git repository" — no real .git/

ls /home/ubuntu/.sandboxes/repos/
# Expected: path doesn't exist in sandbox container
```

### Phase 4: API Path Enforcement
```bash
curl http://localhost:18080/repos/owner/repo
# Expected: allowed

curl -X POST http://localhost:18080/repos/owner/repo/hooks
# Expected: blocked — path in blocklist

curl http://localhost:18080/repos/../admin/keys
# Expected: blocked — path normalization catches traversal

curl http://localhost:18080/repos/owner/%2e%2e/admin/keys
# Expected: blocked — encoded dot-segment traversal normalized and denied

curl http://localhost:18080/repos/owner//repo/hooks
# Expected: blocked — repeated separators normalized and matched

curl http://localhost:18080/repos/owner%2frepo/hooks
# Expected: blocked — `%2f` decoded and path matched correctly

curl -X POST http://localhost:18080/repos/owner/repo/actions/secrets
# Expected: blocked — path in blocklist
```

### Phase 5: PR and Issue Controls
```bash
# Via local stub upstream behind proxy (deterministic integration test)
curl -X PATCH http://localhost:18080/repos/owner/repo/pulls/1 \
  -d '{"state": "closed"}'
# Expected: blocked by policy

curl -X PATCH http://localhost:18080/repos/owner/repo/pulls/1 \
  -d '{"title": "new title"}'
# Expected: allowed

curl -X PATCH http://localhost:18080/repos/owner/repo/pulls/1 \
  -d '{"state": "open"}'
# Expected: allowed (reopen)

curl -X PATCH http://localhost:18080/repos/owner/repo/issues/1 \
  -d '{"state": "closed"}'
# Expected: blocked by policy
```

### General
```bash
# Unit tests
pytest tests/unit/ -v

# Red team suite
./tests/redteam-sandbox.sh

# Backwards compatibility — sandbox WITHOUT GIT_SHADOW_ENABLED
# Expected: all existing functionality works as before, no regressions

# Proxy-down behavior (stop git operations API, then run git command)
# Expected: wrapper returns clear error within 30s, does not hang
```

---

## Implementation Order

```
Phase 1 (git hook prevention) ────── Batch 1a: simplest, zero dependencies, immediate value

Phase 2 (protected branches) ─────── Batch 1b: quick win, high impact, small-medium complexity

Phase 3 (.git/ shadow + flags) ───── Batch 2: largest change, highest exfiltration defense

Phase 4 (API path enforcement)  ────────┐
                                         ├── Batch 3: medium impact policy controls
Phase 5 (PR/issue operation controls) ──┘
```
