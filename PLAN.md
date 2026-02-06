# Plan: Port egg's Git Policy Advantages to foundry-sandbox

## Goal

Bring egg's strongest security advantages into foundry-sandbox while working within the existing mitmproxy addon architecture. Prioritized by security impact vs implementation cost.

---

## Phase 1: Protected Branch Enforcement + Force Push Blocking

**Impact: HIGH | Complexity: Small**

Prevent direct pushes to `main`, `master`, `release/*`, and configurable branches. This is stronger than egg's force-push flag blocking because it blocks ALL pushes to protected branches.

**File:** `unified-proxy/addons/git_proxy.py`

- Add `DEFAULT_PROTECTED_BRANCHES = {"refs/heads/main", "refs/heads/master"}` and pattern list for `release/*`, `production`
- Add `_check_protected_branches()` method that inspects parsed pkt-line refs
- Skip branch creation refs (allow initial `main` push) but block updates and deletions
- Support custom protected branches via container metadata: `metadata.protected_branches`
- Gate behind `metadata.protect_branches` flag (default: true for bot mode, false otherwise)

**File:** `lib/proxy.sh` (registration)

- Include `protect_branches: true` and optional `protected_branches` list in metadata during container registration

**File:** `tests/unit/test_git_proxy.py`

- Test: push to `refs/heads/main` blocked
- Test: push to `refs/heads/feature-x` allowed
- Test: push to custom protected branch blocked
- Test: branch creation to `main` allowed (initial push)
- Test: metadata opt-out works

---

## Phase 2: Git Hook Prevention

**Impact: HIGH | Complexity: Small**

Malicious repos can run arbitrary code via git hooks (post-checkout, pre-commit, etc.). Disable hooks at the git config level inside the sandbox.

**File:** `entrypoint.sh`

Add after git configuration section:
```bash
git config --global core.hooksPath /dev/null
git config --global init.templateDir ''
```

Default ON (hooks disabled). Controlled by `SANDBOX_DISABLE_GIT_HOOKS` env var (default `1`).

**File:** `tests/redteam-sandbox.sh`

- Test: verify `core.hooksPath` is `/dev/null`
- Test: verify a repo with a malicious post-checkout hook doesn't execute it

---

## Phase 3: `.git/` Metadata Isolation via tmpfs Shadow

**Impact: HIGH | Complexity: Large**

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
│    .git/ (tmpfs, empty)     │     │    .git  (real gitdir file)      │
│                             │     │                                  │
│  /usr/local/bin/git         │     │  /home/ubuntu/.sandboxes/repos/  │
│    (wrapper script)        ─┼─HTTP┼─►  (real bare repo, RW)         │
│                             │     │                                  │
│  git status ──► wrapper     │     │  POST /git/exec                  │
│  git commit ──► wrapper     │     │    validates args                │
│  git push ──► wrapper       │     │    runs real git                 │
│                             │     │    returns stdout/stderr/exit    │
└─────────────────────────────┘     └──────────────────────────────────┘
         ↑ same physical files ↑
```

### Key design decisions

1. **Shared bind mount for working tree files**: Both containers mount the same host worktree directory. When the agent edits `/workspace/foo.py`, the proxy sees the same edit at `/git-workspace/foo.py`. This ensures `git status`/`git diff` are accurate.

2. **tmpfs shadows the `.git` file**: The worktree's `.git` is a file (gitdir pointer to bare repo). A tmpfs mount at `/workspace/.git` creates an empty directory that hides this pointer. The agent cannot discover or follow the gitdir pointer.

3. **Proxy has real git access**: The proxy mounts both the worktree and the bare repo. The gitdir pointer in the worktree's `.git` file resolves correctly inside the proxy container.

4. **Git wrapper proxies via HTTP**: All git commands in the sandbox are intercepted by a wrapper at `/usr/local/bin/git` that sends them to a new TCP endpoint on the unified-proxy (port 8083, credential-isolation network only).

### Files to create

**`unified-proxy/git_operations.py`** — New Flask module for git execution API
- `POST /git/exec` endpoint: receives `{args, cwd}`, validates against operation allowlist, runs git, returns `{stdout, stderr, exit_code}`
- Operation allowlist (read: `status`, `diff`, `log`, `show`, `branch`, `blame`; write: `add`, `commit`, `checkout`, `switch`, `merge`, `rebase`, `push`, `fetch`, `pull`)
- Blocked operations: `config --global`, `--git-dir` overrides, paths outside `/git-workspace`
- Git credential helper configured for push/fetch using proxy's `GITHUB_TOKEN`

**`stubs/git-wrapper.sh`** — Shell script installed at `/usr/local/bin/git` in sandbox
- Detects if operating on `/workspace` (proxy it) or elsewhere (use `/usr/bin/git`)
- Sends JSON request to `http://unified-proxy:8083/git/exec`
- Streams stdout, preserves exit codes, passes stderr through
- Falls through to real git for non-workspace operations (e.g., `git init /tmp/test`)

### Files to modify

**`docker-compose.credential-isolation.yml`**
- Dev service: add `tmpfs: /workspace/.git:mode=755,uid=1000,gid=1000,size=1m`
- Proxy service: add volume `${WORKSPACE_PATH}:/git-workspace` (same bind mount as sandbox)
- Proxy service: add volume `${REPOS_DIR}:/home/ubuntu/.sandboxes/repos` (bare repos, RW for commits)
- Proxy service: expose port 8083 on credential-isolation network (git API)
- Proxy service: add `GIT_SHADOW_ENABLED=true` env var

**`unified-proxy/internal_api.py`**
- Import and register `git_operations` blueprint
- Add TCP listener on port 8083 (separate from Unix socket admin API)

**`unified-proxy/entrypoint.sh`**
- Start git operations API if `GIT_SHADOW_ENABLED=true`
- Configure git credential helper inside proxy for push/fetch operations

**`entrypoint.sh`** (sandbox)
- If `GIT_SHADOW_ENABLED=true`: populate minimal `.git/` tmpfs (HEAD, config with user.name/email only)
- Install git wrapper: ensure `/usr/local/bin/git` takes precedence

**`lib/docker.sh`**
- Export `REPOS_DIR` and `WORKSPACE_PATH` for docker-compose variable substitution

**`commands/new.sh`**
- Compute bare repo path and pass to compose_up

### Edge cases

- **`git push`/`git fetch`**: Proxy runs these with real credentials (configured credential helper), through the proxy-egress network. No mitmproxy loop — direct outbound from proxy container.
- **Binary output** (`git diff` with binary files, packfiles): Response uses `Content-Type: application/octet-stream` with chunked transfer.
- **Interactive commands** (`git rebase -i`): Blocked by the wrapper or run with `GIT_EDITOR=true`.
- **Wrapper bypass via `/usr/bin/git`**: Without real `.git/`, `/usr/bin/git` fails with "not a git repository". Defense-in-depth.
- **Agent installing fresh git**: Read-only root filesystem prevents this. Even with sudoers `apt-get install`, no real `.git/` to operate on.
- **Submodules**: Only top-level `.git` is shadowed. Submodule support deferred.

### Limitations vs egg

Equivalent security — both shadow `.git/` with tmpfs and proxy all git commands. The main difference is the transport: egg uses a custom Flask REST API while foundry-sandbox adds endpoints to the existing unified-proxy infrastructure.

---

## Phase 4: PR Operation Controls

**Impact: MEDIUM | Complexity: Medium**

Foundry-sandbox already blocks PR merge (`PUT /repos/*/pulls/*/merge`). Extend to block PR close operations and validate state-changing edits.

**File:** `unified-proxy/addons/policy_engine.py`

- Add body inspection for `PATCH /repos/{owner}/{repo}/pulls/{number}` requests
- Block requests where body contains `"state": "closed"` (prevents agent from closing PRs)
- Pass `flow` object to a new `_check_github_body_policies()` method (runs after existing blocklist check)
- Log blocked operations with structured metadata

**File:** `tests/unit/test_policy_engine.py`

- Test: PATCH with `{"title": "new"}` allowed
- Test: PATCH with `{"state": "closed"}` blocked
- Test: existing merge block still works

---

## Phase 5: GitHub API Endpoint Path Enforcement

**Impact: MEDIUM | Complexity: Small-Medium**

`config/allowlist.yaml` already defines `http_endpoints` with method+path patterns per host, but `policy_engine.py` only enforces domain-level allowlisting. Make the path patterns actually enforced.

**File:** `unified-proxy/addons/policy_engine.py`

- After domain allowlist passes, check `http_endpoints` for matching host
- If host has endpoint entries: validate method + path against patterns (wildcard matching)
- If host has NO endpoint entries: allow (domain-level sufficient)
- Start enforcement only for `api.github.com` (highest security value); other hosts remain domain-only

**File:** `config/allowlist.yaml`

- Audit existing path patterns for completeness
- Ensure all legitimate GitHub API paths used by AI agents are covered

**File:** `tests/unit/test_policy_engine.py`

- Test: `GET /repos/owner/repo` allowed
- Test: `POST /repos/owner/repo/hooks` blocked (not in allowlist)
- Test: hosts without endpoint config still allowed at domain level

---

## Phase 6: Git Flag Validation (Optional, subsumed by Phase 3)

If Phase 3 is implemented, the git wrapper in the sandbox already intercepts all git commands. Flag validation becomes trivial to add inside the wrapper — block `--upload-pack`, `--receive-pack`, `--exec`, and `-c core.hooksPath` before proxying. This is no longer a separate phase but a detail within Phase 3's wrapper implementation.

---

## What We're NOT Porting (and Why)

| egg Feature | Reason to Skip |
|---|---|
| Branch ownership tracking | `sandbox/*` prefix restriction (already exists) is simpler and equivalent. Protected branch enforcement (Phase 1) covers the critical case. |
| Per-operation flag allowlists | Subsumed by Phase 3's git wrapper which validates all commands centrally. |
| Custom Flask gateway | mitmproxy addon chain + git operations API endpoint achieves the same result within existing architecture. |

---

## Verification Plan

After implementation, run these checks:

1. **Unit tests:** `pytest tests/unit/ -v`
2. **Integration test inside sandbox:**
   - `git push origin main` → should be blocked (Phase 1)
   - `git push origin sandbox/my-feature` → should be allowed
   - Repo with `.git/hooks/post-checkout` → hook doesn't execute (Phase 2)
   - `cat /workspace/.git/HEAD` → minimal content, no history (Phase 3)
   - `git log --all` → works via wrapper, but only shows proxied result (Phase 3)
   - `ls /home/ubuntu/.sandboxes/repos/` → path doesn't exist in sandbox (Phase 3)
   - `gh pr close <number>` → should be blocked (Phase 4)
   - `curl` to non-allowlisted GitHub API path → should be blocked (Phase 5)
3. **Red team test:** `./tests/redteam-sandbox.sh` (extend with new git policy checks)
4. **Backwards compatibility:** Sandbox WITHOUT `GIT_SHADOW_ENABLED` works as before

---

## Implementation Order

```
Phase 1 (protected branches) ──┐
                                ├── Batch 1: quick wins, high impact
Phase 2 (git hook prevention) ─┘

Phase 3 (.git/ tmpfs shadow) ──── Batch 2: largest change, highest exfiltration defense

Phase 4 (PR operation controls) ──┐
                                   ├── Batch 3: medium impact policy controls
Phase 5 (API path enforcement)  ──┘
```
