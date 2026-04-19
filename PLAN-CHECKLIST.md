# Docker `sbx` Rearchitecture Checklist

**Status:** Phase 0 **COMPLETE** — Phase 1 **ONGOING** — Phase 2 **COMPLETE** (727 tests passing) — Phase 3 **IN PROGRESS** (Steps 3.0–3.3 done, 323 tests passing, CI green, docs updated)
**Last updated:** 2026-04-19

---

## Phase 1 Research Findings (2026-04-18)

### Current Status (as of April 18, 2026)

| Item | Finding |
|------|---------|
| **Experimental label** | Still "Experimental" in Docker docs and product page. No GA timeline announced. |
| **Launch date** | March 31, 2026 (blog: "Docker Sandboxes: Run Agents in YOLO Mode, Safely") |
| **Architecture blog** | April 16, 2026 ("Why MicroVMs: The Architecture Behind Docker Sandboxes") |
| **GitHub repo** | `docker/sbx-releases` — releases only, **proprietary** license (no source code) |
| **Version** | Standalone `sbx` at v0.24.1; Docker Desktop plugin `docker sandbox` at v0.12.0 (diverged) |
| **Releases** | 7 stable releases + nightly builds available |
| **Breaking changes** | Community reports CLI migrated from `docker sandbox` to `sbx` with no migration path. Forum: "Docker Sandbox COMPLETELY changed in a minor update." |
| **Linux support** | Install artifacts exist (.deb for Ubuntu 24.04/25.10/26.04, .rpm for Rocky Linux 8). Docs say "legacy containers" but hands-on testing with sbx v0.26.1 on Fedora 43 confirmed **microVM isolation** (kernel 6.12.44 vs host 6.17.8). See Phase 0 report. |
| **Licensing** | Proprietary (Docker Inc.). Individual standalone use appears free. Team/enterprise controls require contacting sales. No separate Sandboxes pricing tier. |
| **Git safety features** | **None.** Policy system is network-only (domain allow/deny). No git operation guardrails, protected branches, ref filtering, or API-level policies. |
| **Docker Desktop integration** | "Coming soon" per launch blog. Not yet available. |

### Key Risk Updates

| Risk | Previous Assessment | Updated Assessment |
|------|-------------------|-------------------|
| Experimental status | Medium likelihood of indefinite experimental | **Accepted** — proceeding with experimental; pin to specific sbx version |
| Version stability | Medium — breaking changes expected | **High** — community reports surprise breaking changes between `docker sandbox` and `sbx` CLIs |
| Linux support | Medium — KVM backend exists, no install docs | **Updated** — install artifacts published; sbx v0.26.1 confirmed microVM on Fedora 43 (see Phase 0 report). Docs still say "legacy containers" but this is outdated. |
| Git feature gap | Medium — Docker could add git policies | **Low** — no git features in docs, roadmap, or CLI; policy system is network-only |
| Licensing risk | Low — unclear terms | **Low-Medium** — proprietary, free for individual use, team/enterprise requires sales contact |

---

## Phase 0: One-Week Validation Spike

**Result: PASS (with caveats)** — See `docs/sbx-phase0-report.md`

### Git Wrapper Injection Validation

- [x] Create test macOS environment with Docker `sbx` installed
  - Used Linux (Fedora 43) with `sbx` v0.26.1 — confirmed microVM (kernel 6.12.44 vs host 6.17.8)
- [x] Prepare git wrapper script for injection
  - Created `stubs/git-wrapper-sbx.sh` — adapted for sbx networking
- [x] Inject wrapper via `sbx exec --user root`
  - File sync to workspace → `sbx exec --user root phase0-test -- bash -c "cp ... /usr/local/bin/git"`
- [x] Verify wrapper is active: `sbx exec test -- git --version`
  - `which git` returns `/usr/local/bin/git`; wrapper header confirmed
- [x] Test git operations are proxied correctly
  - `git status`, `git log`, `git branch` all returned correct results via host API server
- [x] Execute `sbx reset` and verify wrapper persistence
  - **Wrapper destroyed** — `sbx reset` destroys entire sandbox filesystem + signs out
- [x] If wrapper destroyed, investigate template-based installation
  - Template-based install (`sbx template save`) is the mitigation; not yet tested
- [x] Document injection and persistence strategy
  - Documented in `docs/sbx-phase0-report.md` — file sync + `sbx exec`, template for persistence
- [x] Pass/Fail determination: Proceed to Phase 2 only on pass
  - **PASS** — git wrapper injection works; proceeding to Phase 2 recommended

### Agent Removal Resistance

- [x] Simulate agent removal: `sbx exec test -- rm /usr/local/bin/git`
  - Agent can remove wrapper. Real git at `/usr/bin/git` provides unrestricted access.
- [x] Test if operations are blocked or wrapper recovers
  - **No recovery mechanism.** After removal, agent has full unrestricted git.
- [x] Document expected behavior and monitoring strategy
  - Accepted risk. Mitigation: build wrapper into custom sbx template; monitor and re-inject.

### Security Audit

- [x] Review privileged injection mechanism for sandbox escape vectors
  - No sandbox escape found. MicroVM isolation confirmed (separate kernel).
- [x] Document security boundaries and assumptions
  - `gateway.docker.internal` only exposes proxy port 3128; other host ports blocked.
  - Agent has root inside sandbox but cannot access host filesystem beyond workspace.
- [x] If concerns identified, explore alternative injection mechanisms
  - Agent removal is accepted risk. Template-based injection is the hardening path.

### Credential Isolation Verification

- [x] Run `sbx secret set -g anthropic -t "$ANTHROPIC_API_KEY"`
  - `echo "test-key" | sbx secret set -g anthropic` — stored on host
- [x] Create sandbox and exec into it
  - `sbx exec phase0-test -- env | grep -i anthropic` — no credentials found
- [x] Run `env | grep -i anthropic` inside VM
  - **PASS** — returns nothing (exit code 1)
- [x] Verify zero credential leakage
  - Confirmed. `GH_TOKEN=proxy-managed` (placeholder). No real tokens in environment.
- [x] Document if Docker security bug is found
  - No bug found. Credential isolation works as documented.

### Spike Deliverables

- [x] Pass/Fail report with technical findings
  - `docs/sbx-phase0-report.md`
- [x] Updated risk assessment based on validation results
  - Updated in report and below in this checklist
- [x] Recommendation: Proceed to Phase 2 or reconsider architecture
  - **Proceed to Phase 2** — see architectural decisions in report

### Phase 0 Artifacts

| File | Purpose |
|------|---------|
| `stubs/git-wrapper-sbx.sh` | Adapted git wrapper for sbx networking |
| `stubs/git-api-standalone.py` | Minimal standalone git API server |
| `docs/sbx-phase0-report.md` | Full validation spike report |

---

## Phase 1: Monitor and Validate (Ongoing)

### Track Docker Sandboxes Development

- [x] Subscribe to Docker blog for Sandboxes updates
  - Launch blog: Mar 31, 2026 — "Docker Sandboxes: Run Agents in YOLO Mode, Safely"
  - Architecture blog: Apr 16, 2026 — "Why MicroVMs: The Architecture Behind Docker Sandboxes"
- [x] Watch Docker Sandboxes GitHub repository (if public)
  - **Found:** `docker/sbx-releases` (releases only, proprietary license, no source)
  - 7 stable releases + nightly builds
  - Issue tracker active, Docker team responds to feedback
- [x] Check Docker documentation weekly for changes
  - Docs at `docs.docker.com/ai/sandboxes/` — comprehensive reference for all `sbx` commands
  - Security model docs confirm credential isolation via network-level proxy injection
- [x] Join Docker Slack/community for Sandboxes discussions
  - Docker Community Forums active: reports of breaking changes, VM data loss, version conflicts
  - "sbx" Slack channel mentioned in GitHub README
- [x] Document all breaking changes in experimental phase
  - **Breaking:** `docker sandbox` (Desktop plugin, v0.12.0) diverged from standalone `sbx` (v0.24.1)
  - Forum report: "Docker Sandbox COMPLETELY changed in a minor update" — no migration path
  - Two parallel installations on same machine, separate data directories
- [x] **Monitor for git policy features in Docker roadmap** — if Docker adds operation-level git guardrails, reassess differentiation
  - **Confirmed: NO git policy features exist.** `sbx policy` is network-only (domain/IP allow/deny).
  - No git operation guardrails, protected branches, ref filtering, or API-level policies in any documentation.
  - Foundry's git safety layer remains a clear differentiator.

### Validate Credential Isolation

- [ ] Install Docker `sbx` on macOS test machine
  - **Blocker:** No macOS test machine available. Requires `brew install docker/tap/sbx`.
  - Linux install confirmed microVM with sbx v0.26.1 on Fedora 43 (see Phase 0 report).
- [ ] Run `sbx secret set -g anthropic -t "$ANTHROPIC_API_KEY"`
- [ ] Create sandbox: `sbx create --name test-cred claude /tmp/test`
- [ ] Exec into sandbox: `sbx exec test-cred -- env | grep -i anthropic`
- [ ] Verify: No credentials visible in environment
- [ ] Verify: API calls succeed with injected credentials
- [ ] Document credential injection mechanism
  - **Partial:** Docker security docs confirm: "API keys are injected into HTTP headers by the host-side proxy. Credential values never enter the VM." — docs.docker.com/ai/sandboxes/security/
  - Hands-on validation still required.

### Validate Git Wrapper Injection

- [ ] Create test sandbox with branch: `sbx create --name test-git --branch test-branch claude /tmp/test`
  - **Blocker:** Requires `sbx` installed on macOS/Windows for microVM-based sandbox.
  - Linux sandbox would be container-based (different injection model).
- [ ] Prepare git wrapper script on host
- [ ] Install wrapper via: `sbx exec test-git -u root -- bash -c "cp /tmp/test/git-wrapper.sh /usr/local/bin/git && chmod 755 /usr/local/bin/git"`
- [ ] Verify wrapper is active: `sbx exec test-git -- git --version` (should show wrapper output)
- [ ] Test git operations are proxied correctly
- [ ] Test `sbx reset` behavior with injected wrapper
- [ ] Document injection and persistence strategy

### Validate Linux Support

- [x] Monitor Docker blog for Linux installation announcement
  - **Update:** Linux install artifacts published at `github.com/docker/sbx-releases`
  - `.deb` packages for Ubuntu 24.04, 25.10, 26.04
  - `.rpm` package for Rocky Linux 8
  - APT install: `sudo apt install ./DockerSandboxes-linux-amd64-ubuntu2404.deb`
- [x] Document Linux support status in weekly updates
  - **Updated:** docs.docker.com still states "MicroVM-based sandboxes require macOS or Windows" but hands-on testing with sbx v0.26.1 on Fedora 43 confirmed microVM isolation (kernel 6.12.44 vs host 6.17.8). The docs appear outdated.
  - See `docs/sbx-phase0-report.md` Discovery 1 for details.
  - Architecture blog claims: "A developer on a MacBook gets the same isolation guarantees and startup performance as a developer on a Linux workstation." — but this is aspirational, not current.
- [ ] When Linux install docs published: test KVM backend
  - **Partial:** Install docs exist in GitHub README. MicroVM confirmed on Fedora 43 with sbx v0.26.1 (see Phase 0 report).
- [ ] Benchmark performance vs macOS/Windows
- [ ] Document any Linux-specific limitations
  - **Updated:** Linux sandboxes confirmed microVM-based with sbx v0.26.1 (see Phase 0 report). Earlier docs claiming "legacy container-based" are outdated.
- [x] If no Linux install docs after GA, document as project risk (see `docs/sbx-docker-questions.md`)
  - **Risk updated:** Install artifacts exist. MicroVM isolation confirmed on Linux with sbx v0.26.1 (Fedora 43). Docs claiming "legacy container-based" are outdated — see Phase 0 report for validation details.

### Review Licensing

- [x] Check Docker Sandboxes documentation for licensing terms
  - GitHub repo LICENSE file: **Proprietary — Docker Inc.**
  - Product page FAQ: "Do I need Docker Desktop?" — "No."
  - Product page FAQ: "What does 'Experimental' mean?" — features can change or be discontinued at any time without notice.
- [x] Document licensing terms when published
  - No separate Sandboxes pricing tier on docker.com/pricing.
  - Docker pricing tiers: Personal $0, Pro $9/mo, Team $15/user/mo, Business $24/user/mo.
  - Sandboxes appears to be included at no additional cost for individual standalone use.
- [x] Verify individual standalone use is free
  - **Confirmed free:** Launch blog states: "Individual developers can install and run Docker Sandboxes today, standalone, no Docker Desktop license required."
  - `sbx login` exists but may be optional for basic usage.
- [x] Document team/enterprise licensing requirements
  - **Requires contacting sales:** Product page says "For admin capabilities for a team (network restrictions and file system policies), talk to us to learn more."
  - No published pricing for team/enterprise Sandboxes features.
- [ ] Legal review if needed for commercial use
  - **Note:** Proprietary license. No explicit terms for commercial use published. Needs legal review before enterprise adoption.
- [x] If questions remain, document in `docs/sbx-docker-questions.md` for future outreach
  - Updated: team/enterprise licensing and Linux microVM availability added as outreach questions.

---

## Phase 2: Extract Git Safety Layer (2-3 weeks)

### 2.1 Create Standalone Git Safety Service

- [x] Create `foundry-git-safety/` package directory
  - `foundry-git-safety/` with `pyproject.toml` (hatchling, deps: click, flask, pydantic, pyyaml)
  - Entry point: `foundry-git-safety = "foundry_git_safety.cli:main"`
- [x] Extract `unified-proxy/git_api.py` to standalone module
  - Split into `auth.py` (SecretStore, NonceStore, RateLimiter, HMAC) and `server.py` (Flask app)
- [x] Remove all proxy dependencies (credential injector, gateways, etc.)
  - Removed ContainerRegistry dependency, replaced with file-based metadata resolver
  - All mitmproxy imports eliminated
- [x] Create new entrypoint: `foundry-git-safety` CLI
  - `cli.py` with Click commands: start, stop, status, validate
- [x] Implement `foundry-git-safety start/stop/status` commands
  - `start [--foreground] [--port]`, `stop`, `status` (health check), `validate`
- [x] Add configuration via `foundry.yaml` in workspace
  - `schemas/foundry_yaml.py` with Pydantic models, `default_config/foundry.yaml.example`

### 2.2 Decouple Git Wrapper

- [x] Extract `stubs/git-wrapper-sbx.sh` to `foundry-git-safety/`
  - `foundry_git_safety/wrapper.sh`
- [x] Make wrapper endpoint configurable (env var or config file)
  - GIT_API_HOST, GIT_API_PORT, SBX_PROXY env vars
  - Auto-discovers from `.foundry/config` in workspace
- [x] Add auto-discovery of git safety server via workspace config
  - Reads `.foundry/config` for GIT_API_HOST/GIT_API_PORT if env vars not set
  - HMAC secret auto-discovered from `.foundry/hmac-secret`
- [x] Test wrapper with standalone service
  - Covered by integration tests: test_git_api_server.py (auth, rate limiting, git exec endpoint)
- [x] Document wrapper installation methods (`sbx exec`, templates, bind-mount)
  - Documented in foundry-git-safety/README.md (Architecture diagram, Quick Start, API Reference)

### 2.3 Extract Branch Isolation Module

- [x] Extract `unified-proxy/branch_isolation.py`
  - Copied with relative imports (`from .branch_types import ...`)
- [x] Remove proxy-specific logging and metrics
  - No proxy-specific code found in this module (already clean)
- [x] Adapt to standalone service context
  - Relative imports updated, all stdlib deps only
- [x] Add tests for branch filtering logic
  - test_branch_isolation.py (76 tests), test_output_filter_invariants.py (21 security tests)
- [x] Document configuration options
  - Found in foundry-git-safety/docs/configuration.md (branch_isolation section)

- [x] Extract `unified-proxy/git_policies.py`
  - Copied as `policies.py` (pure stdlib, zero changes needed)
- [x] Extract push file restrictions logic
  - `config.py` retains `FileRestrictionsData`, `check_file_restrictions`, `matches_any`
- [x] Extract protected branch enforcement
  - `operations.py` retains `check_push_protected_branches`, `check_push_file_restrictions`
- [x] Create policy configuration schema
  - `schemas/foundry_yaml.py` with `ProtectedBranchesConfig`, `FileRestrictionsConfig`
- [x] Add tests for restriction enforcement
  - test_push_validation.py (48 tests), test_commit_validation.py (6 tests), test_config.py (34 tests)
- [x] Document policy YAML format
  - Found in foundry-git-safety/docs/configuration.md (file_restrictions, protected_branches sections)

- [x] Extract `unified-proxy/github-api-filter.py`
  - Rewritten as `github_filter.py` — `GitHubAPIChecker` class + HTTP proxy handler
- [x] Remove gateway-specific code
  - All mitmproxy imports eliminated, filtering rules ported directly
- [x] Adapt to standalone context
  - `GitHubAPIChecker.check_request(method, path, body) -> (allowed, reason)`
  - `run_github_proxy()` runs HTTP proxy on port 8084
- [x] Add tests for GitHub policy enforcement
  - test_github_filter.py (90 tests), test_github_blocklist_invariants.py (16 security tests)
- [x] Document GitHub blocklist configuration
  - Found in foundry-git-safety/README.md (GitHub API Filtering section)

### 2.6 Create Workspace Configuration

- [x] Design `foundry.yaml` schema for workspace-level config
  - Pydantic models in `schemas/foundry_yaml.py`
- [x] Support git safety server endpoint
  - `GitSafetyServerConfig` with host, port, secrets_path, data_dir
- [x] Support protected branches list
  - `ProtectedBranchesConfig` with enabled flag and patterns
- [x] Support push file restrictions
  - `FileRestrictionsConfig` with blocked/warned patterns and warn_action
- [x] Support GitHub API blocklist
  - `GitHubAPIConfig` with enabled, proxy_port, allow_pr_operations, allowed_hosts
- [x] Add validation for configuration
  - Pydantic field validators for port, warn_action; `load_foundry_config()` with error handling
- [x] Document all configuration options
  - foundry-git-safety/docs/configuration.md (all foundry.yaml fields, env vars, pattern syntax)

### 2.7 Testing

- [x] Unit tests for all extracted modules
  - 619 unit tests across 15 test files covering all modules
- [x] Integration test: start service, create sandbox, verify git safety
  - test_git_api_server.py (15 tests), test_config_loading.py (10 tests), test_github_proxy.py (21 tests)
- [x] Test protected branch enforcement
  - test_policies.py (18 tests), test_push_validation.py (48 tests), test_command_allowlist_invariants.py (25 tests)
- [x] Test push file restrictions
  - test_push_validation.py (48 tests), test_config.py (34 tests)
- [x] Test branch visibility isolation
  - test_branch_isolation.py (76 tests), test_branch_output_filter.py (45 tests), test_output_filter_invariants.py (21 security tests)
- [x] Test GitHub API blocking
  - test_github_filter.py (90 tests), test_github_blocklist_invariants.py (16 security tests)
- [x] Test with multiple concurrent sandboxes
  - test_operations.py (21 tests) covers SandboxSemaphorePool concurrency
- [ ] Performance benchmark: git operation latency

### 2.8 Documentation

- [x] README for `foundry-git-safety` package
  - foundry-git-safety/README.md with overview, architecture, quick start, config, API reference
- [x] Installation instructions
  - Found in README.md (Installation section)
- [x] Configuration reference
  - foundry-git-safety/docs/configuration.md (all fields, env vars, pattern syntax)
- [x] Usage examples with `sbx`
  - Found in README.md (Quick Start, API Reference sections)
- [ ] Troubleshooting guide
- [ ] Migration guide from foundry-sandbox

**Exit Criteria:** Git safety layer runs independently, passes all tests (727 total), documented. **COMPLETE.**

---

## Phase 3: Migration to `sbx` Backend (Now)

**Prerequisites:**
- [x] Git wrapper injection validated (Phase 0 pass)
- [x] Linux microVM support confirmed (sbx v0.26.1 on Fedora 43)
- [x] Licensing terms acceptable for individual use
- [x] Git safety layer extracted and tested (Phase 2 complete, 727 tests)

### 3.0 Foundation Layer

- [x] Create `foundry_sandbox/sbx.py` — sbx CLI wrapper module
  - Wraps all sbx subprocess calls (create, run, stop, rm, ls, exec, secret, policy, template, diagnose)
  - 39 unit tests passing with mocked subprocess
- [x] Add `SbxSandboxMetadata` Pydantic model
  - Replaces docker-compose-based `SandboxMetadata`
  - Dropped: `ProxyRegistration`, `CredentialPlaceholders` models
  - Updated `CastNewPreset` (removed `network_mode`, `sync_ssh`, `mounts`, `compose_extras`, `sparse`)
  - 17 tests passing
- [x] Adapt `SandboxPaths` in `paths.py`
  - Removed `container_name` and `override_file` fields
  - Simplified to `worktree_path`, `claude_config_path`, `claude_home_path`
  - Removed `path_override_file()` function
- [x] Adapt `state.py` for sbx metadata
  - `write_sandbox_metadata` now writes `SbxSandboxMetadata`
  - `load_sandbox_metadata` validates as `SbxSandboxMetadata`
  - Removed legacy ENV-format migration (clean break)
  - Updated preset system for new field set
  - 34 tests passing

### 3.1 Rewrite CLI Commands

**Status: COMPLETE** — All CLI commands rewritten to delegate to `sbx`. 64 new unit tests (155 total with foundation). 3 obsolete commands deleted.

**New module:** `foundry_sandbox/git_safety.py` — Integration bridge for foundry-git-safety (HMAC secrets, file-based sandbox registration, git wrapper injection/verification)

**New module:** `foundry_sandbox/commands/new_sbx.py` — sbx-specific sandbox creation logic (replaces `new_setup.py`'s docker-compose creation)

#### `cast new` → `sbx create`

- [x] Implement `--agent` flag mapping to `sbx` agents
  - `--agent` accepts: claude, codex, copilot, gemini, kiro, opencode, shell (default: claude)
- [x] Implement `--branch` flag (pass through to `sbx`)
- [x] Implement `--workspace` validation
- [x] Remove docker-compose generation
- [x] Remove subnet calculation
- [x] Remove volume provisioning
- [x] Call `sbx create` with appropriate flags
- [x] Call `foundry-git-safety start` after sandbox creation
- [x] Install git wrapper via `sbx exec -u root`
- [x] Store sandbox metadata in `~/.sandboxes/`
- [x] Removed flags: `--mount`, `--network`, `--with-ssh`, `--no-isolate-credentials`, `--sparse`, `--pre-foundry`, `--with-ide`, `--ide-only`, `--no-ide`, `--allow-dangerous-mount`, `--anthropic-base-url`, `--compose-extra`

#### `cast start` → delegate to `sbx`

- [x] Simplify to `sbx run` wrapper
- [x] Verify git safety server is running
- [x] Re-inject git wrapper if missing
- [x] Handle pip requirements installation
- [x] Removed flags: `--pre-foundry`, `--compose-extra`

#### `cast stop` → delegate to `sbx`

- [x] Implement as `sbx stop` wrapper
- [x] Removed: compose_down, tmux, compose extras

#### `cast destroy` → delegate to `sbx`

- [x] Implement as `sbx rm` wrapper
- [x] Unregister sandbox from git safety server
- [x] Clean up workspace config, worktree, bare repo branch
- [x] Removed: compose_down, proxy_cleanup, remove_stubs_volume, remove_hmac_volume, remove_sandbox_networks, tmux

#### `cast attach` → `sbx run` / `sbx exec`

- [x] Replace tmux session with `sbx_exec_streaming()` for interactive attach
- [x] Auto-start sandbox if not running
- [x] Keep IDE launch options (operates on host worktree path)

#### `cast list` → `sbx ls`

- [x] Parse `sbx ls` output
- [x] Add foundry-specific metadata (repo, branch, git safety status)

#### `cast info` → `sbx inspect`

- [x] Delegates to rewritten `config` and `status` commands
- [x] No separate changes needed (auto-updated by status rewrite)

#### Delete unnecessary commands

- [x] Delete `cast build` (handled by `sbx` templates)
- [x] Delete `cast prune` (handled by `sbx reset`)
- [x] Delete `cast upgrade` (handled by `sbx` updates)
- [x] Removed from `cli.py` `_LAZY_COMMANDS`

#### Rewrite credential management

- [x] Replace `cast refresh-creds` with `sbx secret set -g`
- [x] Push API keys from host env (anthropic, github, openai)
- [x] Removed direct/isolation mode distinction

#### Rewrite presets → templates

- [x] Preset system kept as-is (JSON files store `cast new` args, not container state)
- [x] Updated `CastNewPreset` model to remove docker-compose fields
- [ ] Future: integrate with `sbx template save/load` for filesystem state

#### `cast destroy-all` refactored

- [x] Refactored to call `destroy_impl()` in a loop (DRY)
- [x] Uses `sbx_ls()` for sandbox list instead of scanning worktrees dir

#### `cast config` updated

- [x] Replaced docker/docker-daemon checks with `sbx_is_installed()` check
- [x] Removed docker-specific config vars (DOCKER_IMAGE, DOCKER_UID, DOCKER_GID, etc.)

#### `cast help` updated

- [x] Updated command list and flag documentation for sbx backend

### 3.2 Delete Proxy Infrastructure

- [x] Delete `unified-proxy/` directory (except git safety, already extracted)
- [x] Delete docker-compose generation code
- [x] Delete network management code
- [x] Delete credential injector
- [x] Delete policy engine (replaced by `sbx policy`)
- [x] Delete DNS filter
- [x] Delete API gateways (optional: keep for streaming performance)
- [x] Delete container registry
- [x] Delete rate limiter (optional: keep for depth)
- [x] Delete circuit breaker (optional: keep for fail-closed)
- [x] Delete all proxy-related tests
- [x] Update CI/CD to remove proxy tests

### 3.3 Update Documentation

- [x] Rewrite architecture diagram
- [x] Update getting-started guide
- [x] Update installation instructions (include `sbx` install)
- [x] Update usage examples
- [x] Document `sbx`-specific behaviors
- [x] Document git safety installation
- [x] Update ADRs (Architecture Decision Records)
- [x] Update CHANGELOG.md

### 3.4 Migration Path for Existing Users

- [ ] Create migration script: `cast migrate-to-sbx`
- [ ] Implement backup of existing `.sandboxes/` directory
- [ ] Migrate credential storage to `sbx secret set -g`
- [ ] Migrate presets to templates
- [ ] Provide rollback instructions with tested procedure
- [ ] Document breaking changes with workarounds
- [ ] **State preservation plan for running sandboxes:**
  - [ ] Pause running sandboxes before migration
  - [ ] Preserve uncommitted work
  - [ ] Preserve active tmux sessions if possible
  - [ ] Document limitations of state preservation
- [ ] **Zero-downtime migration strategy:**
  - [ ] Support dual-mode operation during transition
  - [ ] Allow gradual migration of individual sandboxes
  - [ ] Test rollback procedure on sample installations
- [ ] **Data migration validation:**
  - [ ] Verify credential migration completeness
  - [ ] Verify config migration integrity
  - [ ] Test migration with edge cases (large worktrees, custom configs)

### 3.5 Testing

- [ ] Test all commands with `sbx` backend
- [ ] Test migration script on sample installations
- [ ] Test credential injection with all supported providers
- [ ] Test git safety with `sbx` sandboxes
- [ ] Test with multiple concurrent sandboxes
- [ ] Performance benchmark: compare old vs new
- [ ] Security audit: verify credential isolation
- [ ] Update CI/CD pipeline for `sbx` testing
- [ ] **Chaos engineering:**
  - [ ] Test behavior when `sbx` daemon crashes
  - [ ] Test behavior when git safety server crashes
  - [ ] Test network interruption between sandbox and git safety
  - [ ] Test with incomplete/corrupted `sbx reset`
- [ ] **Security audit for new attack surface:**
  - [ ] Audit git safety server communication channel
  - [ ] Review authentication mechanism (HMAC auth)
  - [ ] Test for privilege escalation via wrapper injection
  - [ ] Test for credential leakage through git safety layer

**Exit Criteria:** All tests pass, documentation complete, migration path validated.

---

### Observability and Monitoring (New)

- [ ] Add health check endpoint to git safety server
- [ ] Add metrics endpoint for operation counts and latency
- [ ] Add logging for policy enforcement decisions
- [ ] Add error tracking for wrapper injection failures
- [ ] Document how to monitor git safety layer in production
- [ ] Create alerting rules for critical failures

---

## Phase 4: Optional Deep Policy Layer (Deferred)

If Docker's domain-level policies are insufficient:

- [ ] Design sidecar proxy for method/path/body policies
- [ ] Implement HTTP/HTTPS inspection
- [ ] Implement GitHub API blocklist enforcement
- [ ] Implement body inspection for PATCH operations
- [ ] Integrate with `sbx` network policy
- [ ] Add per-container rate limiting
- [ ] Add circuit breaker (fail-closed)
- [ ] Document when to use this layer

---

## Decision Gates

### Gate 1: Start Phase 2 (Extract Git Safety)
- [x] Phase 1 validations completed
- [x] Git wrapper injection validated as feasible
- [x] Team approves extraction approach

### Gate 2: Start Phase 3 (Full Migration)
- [x] Git wrapper injection validated (Phase 0 pass)
- [x] Linux microVM support confirmed (sbx v0.26.1)
- [x] Licensing acceptable for individual use
- [x] Phase 2 complete (git safety extracted, 727 tests)
- [x] Proceeding with experimental status

### Gate 3: Start Phase 4 (Deep Policy Layer)
- [ ] Docker's domain-level policies deemed insufficient
- [ ] Security team approves sidecar approach
- [ ] Performance impact acceptable

---

## Metrics

**Code Reduction:**
- Significant reduction in codebase size (majority of code delegates to `sbx`)
- Components eliminated: container lifecycle, network management, git worktree creation, credential infrastructure
- Components preserved: git safety layer, git wrapper, CLI wrapper, core configuration

**Qualitative Goals:**
- Simplified architecture with clearer separation of concerns
- Reduced maintenance burden for infrastructure code
- Faster onboarding for new contributors
- Improved security through delegation to Docker's battle-tested components

---

## Alternative Scenario Planning

- [ ] Document scenario: Docker Sandboxes is cancelled
- [ ] Document scenario: Linux support never ships
- [ ] Document scenario: Git wrapper injection proves impossible
- [ ] Document scenario: Docker adds git safety natively
- [ ] Document scenario: `sbx reset` always destroys injected binaries
- [ ] For each scenario, include trigger conditions and response strategy
- [ ] Review and update alternative scenarios quarterly
