# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.21.0] - 2026-04-21

### Added

- **HMAC secret relocated outside VCS tree** — `write_hmac_secret_to_sandbox()` now writes to `/run/foundry/hmac-secret` (tmpfs) instead of `{worktree}/.foundry/hmac-secret`, preventing accidental VCS exposure
- **Config-driven decision log path** — `decision_log_dir` field in `GitSafetyServerConfig` threads through `create_git_api()` to `DecisionLogWriter` with singleton reset on path change
- **Decision-log health checks** — `/ready` reports `decision_log: {ok: true/false}` without triggering 503; `/health` includes a `logging` section with path and writability
- **Integration test: blocked commands → 422** — Full-stack test proving blocked commands return HTTP 422 (not 500) through the HTTP layer
- **Integration tests: denial paths with broken logging** — Verifies 401, 422, and 429 responses are unchanged when the decision log directory is unwritable
- **CI pipeline for foundry-git-safety** — `test.yml` now runs `git-safety-unit`, `git-safety-security`, and `git-safety-integration` as merge-blocking jobs; `scripts/ci-local.sh` mirrors all steps
- **`cast diagnose` command** — Collects sbx diagnostics, git safety health, decision log entries, wrapper tamper events, and kernel isolation status with automatic secret redaction
- **`cast watchdog` command** — Runs the wrapper integrity watchdog as a long-lived foreground process with configurable poll interval

- **sbx CLI wrapper** (`foundry_sandbox/sbx.py`) — wraps all Docker `sbx` subprocess calls (create, run, stop, rm, ls, exec, secret, policy, template, diagnose)
- **Git safety integration bridge** (`foundry_sandbox/git_safety.py`) — manages foundry-git-safety server lifecycle, HMAC secret provisioning, sandbox registration, and git wrapper injection
- **sbx sandbox creation** (`foundry_sandbox/commands/new_sbx.py`) — 9-step setup: bare repo, worktree, sbx create, git safety server, HMAC, wrapper injection, metadata
- **`cast migrate-to-sbx` command** — migrates 0.20.x docker-compose state (metadata, presets, credentials) to sbx backend; creates snapshot for rollback; supports `--plan` dry run
- **`cast migrate-from-sbx` command** — rolls back to 0.20.x state from a migration snapshot
- **Migration guide** (`docs/migration/0.20-to-0.21.md`) — breaking changes, credential mapping, and rollback procedure
- **`--agent` flag** for `cast new` — select agent type: claude, codex, copilot, gemini, kiro, opencode, shell (default: claude)
- **`--name` flag** for `cast new` — override auto-generated sandbox name
- **`--save-as` flag** for `cast new` — save configuration as named preset
- **`--skip-key-check` flag** for `cast new` — skip API key validation
- **`--with-opencode` flag** for `cast new` — enable OpenCode setup
- **`--with-zai` flag** for `cast new` — enable ZAI Claude alias
- **`SbxSandboxMetadata` model** — Pydantic model for sbx sandbox state
- **ADR-008: sbx Migration** — architecture decision record documenting the migration from docker-compose to Docker sbx backend

### Changed

- **All CLI commands** now delegate to `sbx` instead of docker-compose
- **`cast new`** creates sbx microVM sandboxes instead of Docker containers; starts git safety server and injects git wrapper
- **`cast start`** starts sandboxes via `sbx run`; verifies git safety server and re-injects wrapper if missing
- **`cast stop`** stops sandboxes via `sbx stop`
- **`cast destroy`** removes sandboxes via `sbx rm`; unregisters from git safety server
- **`cast attach`** uses `sbx exec` with streaming I/O instead of tmux
- **`cast list`** parses `sbx ls --json` output with foundry metadata enrichment
- **`cast config`** checks for `sbx` availability instead of Docker
- **`cast refresh-creds`** pushes API keys via `sbx secret set -g`; no more direct/isolation mode distinction
- **`cast help`** updated for sbx backend flags and commands
- **`cast destroy-all`** uses `sbx_ls()` and shared `destroy_impl()` for DRY cleanup
- **Credential injection** now handled by sbx (`sbx secret set -g`) instead of unified proxy
- **Network isolation** now handled by sbx policy instead of Squid/mitmproxy/iptables
- **Git operations** proxied through standalone `foundry-git-safety` server instead of unified proxy git API
- **All documentation** updated to reflect sbx architecture (architecture, security model, configuration, operations, observability, getting started, commands, ADRs)
- **ADR-001, 002, 004, 005, 007** marked as superseded by ADR-008

### Fixed

- **`sbx exec` flag ordering** — `sbx exec` requires flags before the sandbox name; reordered argument passing to match CLI expectations
- **`quiet=True` suppressing stdout** — Subprocess calls with `capture_output=True` and `quiet=True` swallowed stdout needed by callers; fixed to only suppress logging while preserving output
- **Base64 encoding for wrapper injection** — Git wrapper injection now correctly base64-encodes the wrapper script before passing through `sbx exec` to avoid shell escaping issues
- **CI smoke gate syntax error** — `scripts/ci-local.sh` had inline comments between `&&` continuations in a multi-line command, causing a shell syntax error; moved comments above the command block

### Removed

- **`unified-proxy/` directory** — entire proxy infrastructure deleted (mitmproxy, Squid, API gateways, DNS filter, circuit breaker, rate limiter, container registry, credential injector, policy engine)
- **`cast build` command** — sandbox images managed by sbx templates
- **`cast prune` command** — orphan cleanup handled by sbx
- **`cast upgrade` command** — updates handled by sbx
- **Docker-compose generation code** — no longer needed
- **Network management code** — handled by sbx policy
- **Container registry** — replaced by file-based registration with foundry-git-safety
- **All proxy-related tests** — replaced by foundry-git-safety tests (727 tests)
- **`--mount`, `-v` flag** — sbx uses file sync instead of bind mounts
- **`--network`, `-n` flag** — replaced by `sbx policy` commands
- **`--with-ssh` flag** — sbx handles SSH differently
- **`--no-isolate-credentials` flag** — sbx always isolates credentials
- **`--sparse` flag** — deferred to future implementation
- **`--pre-foundry`, `--compose-extra` flags** — docker-compose specific
- **`--allow-dangerous-mount` flag** — no bind mounts in sbx
- **`--anthropic-base-url` flag** — sbx handles credential routing
- **`foundry_sandbox/commands/new_setup.py`** — replaced by `new_sbx.py`
- **`foundry_sandbox/commands/new_wizard.py`** — simplified
- **`foundry_sandbox/commands/build.py`** — deleted
- **`foundry_sandbox/commands/prune.py`** — deleted
- **`foundry_sandbox/claude_settings.py`** — removed

## [0.20.15] - 2026-02-28

### Changed
- **Unattended autonomy posture in sandbox CLAUDE.md** — Sandbox stub now declares `autonomy_posture.profile = "unattended"` so agents auto-select tasks, auto-approve plans, and auto-continue between tasks without user prompts.
- **README tagline update** — Added "batteries-included" to the project description.

### Fixed
- **Path validation error not accepted in disallowed command test** — Test assertion updated to accept the proxy's path-validation error response for disallowed git commands.

## [0.20.14] - 2026-02-25

### Fixed
- **`git rm` blocked by proxy allowlist** — `git rm` was not included in the deny-by-default command allowlist, so sandboxed agents couldn't stage file deletions. Added `rm` to the working-tree command set.

## [0.20.13] - 2026-02-23

### Fixed
- **`gh pr create` fails inside sandboxes** — GitHub CLI injects `-c credential.helper=...` overrides into its internal git commands, which the proxy's `CONFIG_NEVER_ALLOW` blocklist rejected, causing all `gh` operations to fail with "failed to run git: exit status 1". The proxy now strips `credential.*` config overrides before validation since it manages credentials independently via its own credential-helper pipeline.

## [0.20.12] - 2026-02-23

### Fixed
- **Push file restrictions tried default branch before `from_branch`** — The fallback chain for enumerating changed files on push diffed against the repo default branch before trying `from_branch` metadata; this included all pre-existing branch history and flagged files the agent never touched. Reordered to try `from_branch` first so diffs only capture the agent's own changes.

## [0.20.11] - 2026-02-23

### Fixed
- **Circuit breaker self-generated 503s counted as upstream failures** — When the circuit breaker blocked a request with a 503 response, mitmproxy's `response()` hook still fired on the same flow, counting the self-generated 503 as another upstream failure; this kept the circuit open forever. Now marks blocked flows with `flow.metadata["circuit_breaker_blocked"]` so `response()` skips them.

## [0.20.10] - 2026-02-23

### Fixed
- **Stale `origin/main` tracking ref in sandbox worktrees** — `git clone --bare` omits the fetch refspec, so `git fetch` never updated `refs/remotes/origin/*`; added `_ensure_fetch_refspec()` to configure it, and `fetch_bare_branch()` now also updates the remote tracking ref alongside the local branch ref, preventing phantom ahead/behind counts
- **`git push` fails on first push in sandbox** — New sandbox branches had no upstream tracking configured, requiring `--set-upstream` on first push; worktree creation now sets `push.autoSetupRemote = true` so `git push` works immediately

## [0.20.9] - 2026-02-23

### Fixed
- **`git branch --show-current` returns empty in sandbox** — The branch output filter regex required a leading `* ` or `  ` indicator, but `--show-current` outputs just the bare branch name; added early detection of `--show-current` in args to validate and pass through the branch name directly
- **Worktree branch divergence warning suppressed** — When `fetch_bare_branch` failed during worktree creation, the error was logged at info level with a misleading "may already exist locally" message; upgraded to `log_warn` with clear messaging that the worktree may be based on stale data

### Removed
- **Sandbox-context CLAUDE.md injection** — Removed `inject_sandbox_branch_context()` which appended `<sandbox-context>` tags to `/workspace/CLAUDE.md` at runtime with branch and PR target info; Claude Code already discovers this natively via `gitStatus` in its system prompt, and the injection could contain stale or incorrect values (e.g. referencing a nonexistent `beta` branch)

## [0.20.8] - 2026-02-22

### Fixed
- **Git wrapper python3 heredoc executes response file as script** — `python3 <<'PY' "$FILE"` treats `$FILE` as the script to execute, ignoring the heredoc; added `-` argument to force stdin reading so the JSON response is properly parsed instead of executed as Python code

## [0.20.7] - 2026-02-22

### Fixed
- **Git operations returning spurious exit code 1 in sandboxes** — Replaced jq-based response parsing in `git-wrapper.sh` with python3 to avoid silent pipe failures that defaulted `exit_code` to 1; changed commit-time file restriction checks from fail-closed to warn-and-allow since the security boundary is at push time; added diagnostic logging to `_enumerate_staged_files` for easier debugging
- **Pyright type errors in unified-proxy** — Added `[tool.pyright]` config with `extraPaths` for import resolution; fixed `_read_remote_urls_from_bare_config` return type from `Dict[str, Dict[str, list]]` to `Dict[str, Dict[str, Any]]` to match actual mixed-type values

## [0.20.6] - 2026-02-22

### Fixed
- **First push of sandbox branch blocked by file validation** — When a sandbox pushed a new branch for the first time, `check_push_file_restrictions()` could not enumerate changed files because (1) `_is_within_boundary()` produced `"//"` when boundary was `/`, breaking bare repo resolution, and (2) there was no fallback to the `from_branch` metadata field. Fixed the root boundary check and added a third fallback using `from_branch` before fail-closing.

## [0.20.5] - 2026-02-22

### Fixed
- **`cast new` crash on bytes stderr** — `subprocess.CalledProcessError.stderr` can be `bytes` when `text=` is not set; the error handler now decodes before calling `.strip()`, preventing a `TypeError` crash during rollback logging
- **Docker compose timeout too short** — Increased `TIMEOUT_DOCKER_COMPOSE` from 120s to 300s and made it configurable via `CAST_COMPOSE_TIMEOUT` environment variable

## [0.20.4] - 2026-02-22

### Fixed
- **Statusline config not copied into sandbox** — `SCRIPT_DIR` env var was never set during `cast new`, so the bundled `statusline.conf` path resolved to a non-existent `/workspace` directory; now uses `Path(__file__)`-based resolution consistent with the rest of the codebase
- **E402 lint errors in credential_setup.py** — Reordered imports to satisfy ruff's module-level import position checks

## [0.20.3] - 2026-02-22

### Fixed
- **Sandbox worktrees created from stale branch refs** — When `cast new repo branch` ran without `--from`, the bare repo's `refs/heads/<branch>` was never updated from the remote, causing worktrees to check out the commit from the original clone; now fetches and updates the ref before worktree creation
- **Foundry upgrade test assertion wrong call** — `_enable_user_site_packages` added an extra `subprocess.run` call, so the test was asserting on the MCP config patch instead of the pip install command

## [0.20.2] - 2026-02-22

### Fixed
- **Commit/push blocked by missing file restrictions config** — `push-file-restrictions.yaml` was not mounted into the proxy container, causing `get_file_restrictions_config()` to fail and the fail-closed logic to block all commits and pushes

## [0.20.1] - 2026-02-22

### Fixed
- **Pre-release foundry-mcp not used by MCP server** — Choosing pre-release in `cast new` installed the beta to user site-packages (`~/.local/`) via `PIP_USER=1`, but the MCP server config used `python -s` which skips that directory; the server silently kept running the global stable version. Now `upgrade_foundry_mcp_prerelease` removes the `-s` flag from the MCP config after a successful install so the pre-release is actually loaded.

## [0.20.0] - 2026-02-21

### Added
- **Gemini OAuth auto-refresh** — Proxy now automatically refreshes expired Gemini OAuth tokens using Google's token endpoint with the public Gemini CLI client credentials, instead of returning 401 errors; refreshed tokens are persisted to `oauth_creds.json` for future sessions
- **Pathspec auto-expansion for branch isolation** — `git diff docs/foo.md`, `git log README.md`, `git blame src/main.py` and similar ref-reading commands now auto-insert `--` before path-like arguments, preventing false branch isolation rejections when users omit the `--` separator
- **Package installation in sandboxes** — `pip install` and `npm install` now work out of the box; `PIP_USER=1` env var routes pip installs to `~/.local/` on the read-only root filesystem; new red-team test module validates pip, npm, and system-level install boundaries
- **GitHub Actions API read access** — Added read-only allowlist paths for actions runs, workflows, jobs, and artifacts so `gh run view`, `gh workflow list`, etc. work in sandboxes
- **Gemini trusted folders** — Entrypoint pre-trusts `/workspace` in `~/.gemini/trustedFolders.json` to avoid interactive Gemini CLI trust prompt

### Changed
- **GitHub API routing moved to MITM path** — `api.github.com` re-added to mitmproxy credential injection because `gh` CLI does not support `GITHUB_API_URL`; the gateway (`:9850`) now handles only git operations; Squid MITM intercepts, credential injector replaces placeholder `GH_TOKEN`, and `policy_engine.py` enforces security policies
- **Statusline config uses bundled file** — Always copies the project-bundled `statusline.conf` instead of looking for `~/.claude/statusline.conf` on the host
- **Removed OAuth token expiry warnings from `cast new`** — No longer needed since Gemini tokens auto-refresh and Codex tokens self-refresh via refresh_token

## [0.19.4] - 2026-02-21

### Fixed
- **Gemini OAuth token expiry gives clear 401 error** — Proxy now detects expired Gemini OAuth tokens and returns a helpful 401 with instructions to run `gemini login` + `cast refresh-creds`, instead of silently forwarding a stale token that produces an opaque API error
- **`cast refresh-creds` can't update Gemini OAuth credentials** — Switched from `docker compose restart` to `up --force-recreate` so the unified-proxy container is fully recreated, ensuring read-only bind-mounted credential files (like Gemini `oauth_creds.json`) are re-read from the host
- **`cast refresh-creds` times out with many containers** — Increased `TIMEOUT_DOCKER_QUERY` from 10s to 30s to prevent timeouts during `docker ps`/`inspect` queries

### Added
- **`cast refresh-creds --all`** — Refresh credentials for all running sandboxes at once
- **OAuth token expiry warnings on `cast new`** — Checks Gemini and Codex OAuth tokens before sandbox creation and warns if they're expired, with an option to continue or abort

## [0.19.3] - 2026-02-21

### Fixed
- **Codex CLI 404 in subscription mode** — `OPENAI_BASE_URL` was unconditionally set to the OpenAI gateway (`http://unified-proxy:9849`), which only handles API-key mode; Codex subscription mode sends `POST /responses` to `chatgpt.com` and got 404 from the gateway. Now `OPENAI_BASE_URL` is always unset so Codex routes through `chatgpt.com` → TLS interception on port 443; OpenAI API-key traffic restored to MITM credential injection path
- **Gemini CLI 403 in OAuth mode** — Container identity failed for HTTPS CONNECT tunnels because Squid sets XFF on the outer CONNECT request, but mitmproxy's `request()` hook fires on inner (decrypted) requests which don't carry XFF. Added `http_connect` handler to extract real client IP from CONNECT-level XFF and store it for subsequent `request()` calls

## [0.19.1] - 2026-02-21

### Fixed
- **Container identity resolution on MITM path** — When Squid's cache_peer forwards MITM traffic to mitmproxy, the TCP source IP is 127.0.0.1 (Squid itself); the container identity addon now recovers the real container IP from X-Forwarded-For (set by `forwarded_for truncate`) and strips XFF before forwarding upstream to prevent information leakage

### Added
- **`backports.zstd` dependency** — Zstandard decompression support for aiohttp, required by Codex CLI

## [0.19.0] - 2026-02-21

### Added
- **Dedicated API gateways** — Migrates API traffic from mitmproxy addons to purpose-built gateways (GitHub, OpenAI, Gemini, ChatGPT) with a Squid forward proxy, reducing credential exposure surface and improving auditability
- **Gemini API gateway** — New gateway with OAuth support for Gemini API traffic
- **ChatGPT gateway** — New gateway with transparent TLS interception for ChatGPT API traffic
- **Shared gateway infrastructure** — Extracts `gateway_base.py`, `gateway_middleware.py`, and `security_policies.py` as reusable modules for consistent auth injection, rate limiting, circuit breaking, and error handling
- **Documentation** — Security feature gap analysis, provider base URL research, mitmproxy elimination analysis, gateway rollback procedures, threat model updates, and security review plan

### Fixed
- **Security hardening** — Closes IPv6 IP literal bypass, git diff arg order bypass, identity bypass, ConnectionResetError crash, credential detection in clone URLs, symlink boundary checks, placeholder filter gaps, and more
- **Squid forward proxy** — Resolves container startup issues including domain dedup conflicts, PID file paths, effective user configuration, and log directory permissions
- **Test coverage** — Adds comprehensive unit tests for policy engine, gateway middleware, GitHub gateway, branch isolation, push/commit file restrictions, git command validation, and git API auth

## [0.18.2] - 2026-02-20

### Fixed
- **`/home/ubuntu` tmpfs missing `exec` flag** — Pip-installed binaries (ruff, pytest, etc.) in `/home/ubuntu/.local/bin` failed with "Permission denied" because the tmpfs mount lacked the `exec` option; `/tmp` already had `exec` so this adds no new attack surface

## [0.18.1] - 2026-02-20

### Added
- **Allowlist merge layering** — `load_allowlist_config()` accepts an optional extra allowlist YAML that is additively merged with the base config; supports `PROXY_ALLOWLIST_EXTRA_PATH` env var for host-to-container threading
- **`destroy_impl()` programmatic API** — Non-interactive destroy implementation with `best_effort`, `skip_tmux`, and `skip_branch_cleanup` parameters
- **`exec_in_container_streaming()`** — Streaming `docker exec` with timeout handling (SIGTERM → SIGKILL escalation)
- **`compose_extras` parameter** — `get_compose_command()`, `compose_up()`, and `compose_down()` accept additional compose override files

### Fixed
- **`fetch_bare_branch` ref injection** — Branch names are now validated against a strict regex and path traversal before constructing `refs/heads/` paths
- **Inline import in policy engine** — Moved `HttpEndpointConfig` import from inside `_add_anthropic_base_url_host()` to module-level
- **Silent fallback in `_detect_remote_default_branch`** — Now logs a warning when falling back to `"main"` because neither `main` nor `master` was found on the remote
- **Compose YAML path quoting** — Host paths in allowlist-extra overrides are single-quoted to handle paths with spaces, colons, or other YAML-significant characters
- **Empty `blocked_paths.patterns` accepted** — `_parse_extra_allowlist()` now rejects entries with empty `patterns` lists

## [0.18.0] - 2026-02-20

### Added
- **`--pre-foundry` flag for `cast new` and `cast start`** — Upgrade foundry-mcp to the latest pre-release inside the sandbox; the wizard also offers a Foundry MCP version step when a newer pre-release is available on PyPI
- **`patch_sandbox_metadata()` helper** — Partial-update function for sandbox metadata that validates fields through the Pydantic model
- **Release workflow supports pre-release tags** — `v0.18.0b1`, `v1.0.0a1`, etc. now create GitHub pre-releases and publish to PyPI

### Changed
- Wizard returns a `WizardResult` named tuple instead of a plain tuple for better readability and extensibility

## [0.17.4] - 2026-02-19

### Fixed
- **Sandbox worktrees created from stale branch refs** — `git clone --bare` omits the fetch refspec, so `git fetch --all` never updated `refs/heads/*` in the cached bare repo; additionally, the targeted fetch in `create_worktree` was silently blocked by git's "checked-out branch" guard. New `fetch_bare_branch()` fetches to `FETCH_HEAD` then uses `update-ref` to bypass both issues.

## [0.17.3] - 2026-02-19

### Fixed
- **Bare `git push` blocked by branch isolation** — `git push` and `git push origin` (no refspec) were rejected because branch isolation requires explicit targets; the proxy now auto-expands these with the sandbox branch from container metadata, so the AI can push without specifying the branch name

## [0.17.2] - 2026-02-19

### Fixed
- **`ANTHROPIC_CUSTOM_HEADERS` not injected for custom `ANTHROPIC_BASE_URL` hosts** — The credential injector's `PROVIDER_MAP` only contained `api.anthropic.com`, so requests to a custom base URL (e.g. a LiteLLM proxy) short-circuited before credential or custom header injection; now registers the custom host in `PROVIDER_MAP` and `credentials_cache` at startup so it receives the same treatment as `api.anthropic.com`

## [0.17.1] - 2026-02-19

### Fixed
- **`cast new` fails when current branch doesn't exist on remote** — Auto-detects whether the current branch is on the remote; falls back to the remote's default branch (e.g. `main`) instead of blindly using a local-only branch as the base
- **`git worktree add` fails with cryptic error for missing base branch** — Added pre-check that verifies the `from_branch` ref exists before attempting worktree creation, with a clear error message suggesting `--from`
- **Custom `ANTHROPIC_BASE_URL` blocked by policy engine** — The credential injector already forwarded requests to custom base URL hosts, but the policy engine's domain allowlist didn't include them; now dynamically adds the custom host and mirrors the `api.anthropic.com` endpoint config

## [0.17.0] - 2026-02-19

### Added
- **`ANTHROPIC_CUSTOM_HEADERS` environment variable** — Pass custom headers to Anthropic API requests via comma/newline-separated `Name: Value` pairs; the credential proxy injects them on outbound requests to `api.anthropic.com` (and any custom `ANTHROPIC_BASE_URL` host). Reserved headers (`x-api-key`, `authorization`) are blocked to prevent conflicts with credential injection.

## [0.16.0] - 2026-02-19

### Fixed
- **GitHub GraphQL API blocked despite `--allow-pr`** — `/graphql` was missing from the `api.github.com` endpoint paths in `allowlist.yaml`, causing `policy_engine.py` to reject all GraphQL requests before `github-api-filter.py` could apply its mutation filtering; `gh pr create`, `gh pr view`, and other GraphQL-based CLI commands now work when `--allow-pr` is enabled
- **`@{u}` / `@{upstream}` / `@{push}` incorrectly blocked by branch isolation** — `_strip_rev_suffixes()` consumed the entire `@{...}` ref before the allowlist check could run; now checks the original ref for `@{...}` forms first
- **`git remote --verbose` blocked by command validation** — only `-v` was in `REMOTE_ALLOWED_SUBCOMMANDS`, not `--verbose`
- **`git push -u` fails with "could not lock config file"** — added stale `config.lock` cleanup before push execution in the proxy, and before config writes in `fix_proxy_worktree_paths()`
- **Stale git lockfiles block all sandboxes sharing a bare repo** — `cast start` now removes stale `config.lock` and `HEAD.lock` files (older than 2 minutes) from the shared bare repo before fetching, preventing a killed sandbox from blocking every other sandbox using the same repo

## [0.15.8] - 2026-02-17

### Added
- **`--anthropic-base-url` option for `cast new`** — Override the Anthropic API base URL via CLI flag or `ANTHROPIC_BASE_URL` environment variable; CLI arg takes precedence over host env

## [0.15.7] - 2026-02-16

### Fixed
- **`cast git-mode` fails when sandbox is running** — Advisory lock sidecar used `.lock` suffix which collides with git's internal `config.lock` mechanism; renamed to `.castlock` to avoid the conflict
- **Stale git lock files from `virtiofsd`** — `git config` writes now remove leftover `.lock` files held open by `virtiofsd` (the container filesystem daemon) before proceeding

## [0.15.6] - 2026-02-15

### Fixed
- **ChatGPT API 403 "Request denied by policy engine"** - Proxy allowlist used `/*` (single-segment) path patterns for `chatgpt.com`, but Codex sends requests to multi-segment paths like `/backend-api/codex/responses/compact`; changed to `/**` to allow all sub-paths

## [0.15.5] - 2026-02-15

### Added
- **Git-mode helper** — `cast git-mode <name> --mode <host|sandbox>` lets you switch a sandbox worktree between host-friendly and sandbox proxy layouts, updating the `.git` config and syncing the running proxy for immediate effect.
  - The command now shows up in `cast help`, validates sandbox names, and ensures worktree/bare paths stay within the expected roots before touching git config.

### Fixed
- **Graceful metadata reads** — `cast list`, `cast status`, and `cast info` skip sandboxes whose metadata lock cannot be created (e.g., due to restrictive permissions) so they no longer crash with `PermissionError(13)`; the loader logs the skip and continues with available sandboxes.

## [0.15.4] - 2026-02-15

### Fixed
- **Stale base branch on `cast start`** - `cast start` now fetches the latest refs from origin before starting containers, so the sandbox's view of the base branch stays current for PRs and rebasing
- **`gh pr create` broken in sandbox** - `git rev-parse --git-dir` was blocked by the git proxy's global flag check; narrowed the exemption to only `rev-parse` subcommand args (read-only path queries) while keeping global `--git-dir` options blocked

## [0.15.3] - 2026-02-13

### Fixed
- **Zed editor not launching on macOS** - IDE launcher now prefers `open -a` on macOS for reliable app activation, falling back to CLI command; previously the `zed` CLI would exit 0 without actually opening the app

## [0.15.2] - 2026-02-13

### Fixed
- **`claude-zai` 403 "Request denied by policy engine"** - Proxy allowlist used `/*` (single-segment) path patterns for `api.z.ai` and `open.bigmodel.cn`, but `claude-zai` sends requests to multi-segment paths like `/api/anthropic/v1/messages`; changed to `/**` to allow all paths
- **Settings merge silently skipped in container** - `claude_settings.py` was missing its `__main__` block after migration from `lib/python/`, so `python3 -m foundry_sandbox.claude_settings merge ...` imported the module but never executed the merge

## [0.15.1] - 2026-02-13

### Fixed
- **`claude-zai` broken with credential isolation** - `ZHIPU_API_KEY` placeholder was only injected when OpenCode was enabled, not when ZAI was enabled via `--with-zai`; the dev container received an empty key even though the proxy had the real one
- **Feature flags always saved as `true` in metadata** - `bool("0")` evaluates to `True` in Python, so `enable_opencode` and `enable_zai` were always stored as `true` in sandbox metadata regardless of actual flags passed to `cast new`

## [0.15.0] - 2026-02-13

### Added
- **PyPI update checker** - CLI now checks PyPI for newer versions after commands, with 24-hour cache, and prints an upgrade notice to stderr when a newer release is available
  - Automatically disabled in CI, non-interactive mode, or via `CAST_DISABLE_UPDATE_CHECK=1`
  - Skipped when running `cast upgrade` to avoid redundant checks
- **Local CI script** - `scripts/ci-local.sh` runs ruff, mypy, shellcheck, and pytest locally to catch CI failures before committing
  - `--all` flag includes integration tests, `--no-fail-fast` shows all results

### Fixed
- **macOS symlink path validation** - `validate_git_url` now checks both expanded and resolved paths for sensitive locations, fixing false negatives on macOS where `/etc` symlinks to `/private/etc`
- **Linting** - Added `# noqa: E402` to unified-proxy addon imports after `sys.path.insert()` calls; added `lib/python/**` to ruff per-file E402 ignores

## [0.14.0] - 2026-02-13

### Added
- **IDE launch macOS fallback** - When an IDE CLI command fails, automatically falls back to `open -a` on macOS for Cursor, Zed, and VS Code; surfaces CLI stderr to the user
- **Auto-select current branch in wizard** - The "Base it on?" prompt in `cast new` guided mode now pre-selects the current branch via a new `default` parameter on `tui_choose`
- **Legacy shell alias migration** - Installer detects and removes stale `alias cast=…sandbox.sh`, `_sb()` completion functions, and old `completion.bash` source lines from shell rc files
- **ZAI stub function** - Sandboxes created with `--with-zai` but missing `ZHIPU_API_KEY` at runtime now get a `claude-zai` stub that prints a helpful error instead of "command not found"

### Changed
- **`--with-zai` fails early** - `cast new --with-zai` now exits with an error if `ZHIPU_API_KEY` is not set, instead of silently skipping ZAI setup
- **Default ZAI models updated** - `claude-zai` alias now uses GLM-5 (was GLM-4.7/GLM-4.5-Air)
- **Default OpenCode model updated** - Bumped to `openai/gpt-5.3-codex` (was `gpt-5.2-codex`)
- **CI simplified** - Release workflow no longer gates on test/orchestration/performance/drift-check jobs; test matrix reduced to Python 3.12 only
- **Removed unused `sandbox_name` parameter** from `prompt_ide_selection()` in IDE module

### Fixed
- **Installer migration message** - Tells the user to `unalias cast` after legacy alias is removed so the current shell picks up the pip-installed `cast`

## [0.13.0] - 2026-02-12

### Changed
- **Complete Python CLI migration** - Removed legacy `sandbox.sh` shell entrypoint and `lib/container_config.sh`; `cast` (Python CLI) is now the sole entry point
- **CI simplified** - Removed shell/python matrix strategy from orchestration tests since only Python CLI remains
- **Documentation updated** - All references to `sandbox.sh` replaced with `cast`/Python CLI across docs, compose files, CLAUDE.md, AGENTS.md, and README
- **PyPI publishing** - Added package metadata (`authors`, `readme`, `classifiers`, `urls`) and automated publish-to-PyPI job in release workflow using trusted publishing

### Removed
- `sandbox.sh` - Legacy shell entrypoint (fully replaced by `cast`)
- `lib/container_config.sh` - Shell-based container configuration (fully replaced by `foundry_sandbox/container_setup.py`)

## [0.12.0] - 2026-02-08

### Added
- **Self-merge prevention** - Blocks sandbox from merging its own PRs via REST API (`PUT /pulls/*/merge`, `PUT /pulls/*/auto-merge`), GraphQL mutations (`mergePullRequest`, `enablePullRequestAutoMerge`, `disablePullRequestAutoMerge`), and request body inspection (`event: APPROVE`, `state: open`)
- **Workflow push blocking** - Prevents pushes containing `.github/workflows` or GitHub Actions files that could modify CI/CD pipelines, with restricted-path checks using temp bare repos and `git diff-tree`
- **Push rate limiting** - Per-container token bucket rate limiter for git push operations to prevent resource exhaustion from rapid push attempts (configurable via `PUSH_RATE_CAPACITY` and `PUSH_RATE_REFILL_PER_SEC`)
- **GraphQL comment stripping** - Strips `# comment` lines from GraphQL queries before mutation regex matching, preventing bypass via comments between mutation names and opening parentheses
- **Path traversal hardening** - Added `os.path.realpath()` validation and `/` component checks in container identity addon to catch URL-encoded traversal, unicode normalization, and symlink attacks
- **Red-team test extensions** - New sections in `redteam-sandbox.sh` for self-merge prevention, workflow push blocking, and PR reopen attack vectors
- **Dual-layer consistency tests** - New test suite (`test_dual_layer_consistency.py`) validating that policy engine and GitHub API filter agree on blocking decisions
- **Git operations unit tests** - New test suite (`test_git_operations.py`) for command parsing edge cases

### Changed
- **Fail-closed on unparseable bodies** - GraphQL requests with malformed JSON are now blocked instead of allowed through, preventing parser-differential attacks
- **Fail-closed on push metadata gaps** - Push operations missing container config or repo metadata are denied instead of allowed
- **HTTP method normalization** - Policy engine and GitHub API filter now normalize `flow.request.method` to uppercase, preventing bypass via lowercase HTTP methods (`put`, `delete`, etc.)
- **Case-insensitive PR reopen detection** - REST API filter now uses case-insensitive comparison for `state: open` to block `OPEN`, `Open`, etc.
- **Read-only filesystem restored** - Credential-isolation sandboxes use a combined CA bundle (`/certs/ca-certificates.crt`) generated by the proxy instead of running `update-ca-certificates`, allowing `read_only: true` in Docker compose
- **Proxy-side git hook prevention** - `--no-verify` flag injected by the proxy for push operations, complementing the client-side `core.hooksPath=/dev/null` defense
- **Temp dir cleanup logging** - `shutil.rmtree` failures in restricted-path checks now log warnings instead of being silently ignored
- **Entrypoint fail-fast** - `generate_ca_cert()` in unified-proxy entrypoint now detects if mitmdump dies before producing the CA certificate

### Fixed
- **Test mock pollution** - Removed per-test-file `sys.modules["mitmproxy"]` overwrites that polluted the global module cache and broke cross-file test runs; all tests now use shared conftest.py mocks

## [0.11.1] - 2026-02-08

### Added
- **GitHub HTTPS credential injection** - Added `github.com` to the credential injector provider map so git push/pull/clone over HTTPS through the proxy are authenticated with `GITHUB_TOKEN` (or `GH_TOKEN` fallback)
- **Credential injector unit tests** - New test suite (`tests/unit/test_credential_injector.py`) covering github.com injection, GH_TOKEN fallback, unauthenticated passthrough, placeholder stripping, and non-GitHub host handling
- **MockHeaders helper** - Case-insensitive mock headers class in `conftest.py` for realistic mitmproxy header behavior in tests

### Fixed
- **Git push/pull authentication** - `FOUNDRY_PROXY_GIT_TOKEN` is now passed through the sanitized subprocess environment in `build_clean_env()`, fixing authentication failures for git push/pull/fetch operations through the proxy

## [0.11.0] - 2026-02-07

### Added
- **Branch Isolation** - Complete cross-sandbox branch isolation in the git proxy, preventing sandboxes from reading, diffing, cherry-picking, or enumerating other sandboxes' branches
  - **Branch isolation validator** with ref validation, subcommand parsing, and deny-by-default enforcement for checkout/switch, fetch/pull, worktree add, bisect, reflog, notes, and ref-reading commands
  - **Output filtering** hides other sandboxes' branches from `git branch`, `for-each-ref`, `ls-remote`, `show-ref`, and `log --decorate` output
  - **SHA reachability enforcement** blocks unreachable SHAs in ref-reading commands with per-request memoization and shallow repo skip
  - **Enhanced notes isolation** checking positional ref args and `--ref` flag
  - **Server-side fetch locking** with bare repo resolver (`_resolve_bare_repo_path`) and `fcntl.flock` exclusive locking to serialize concurrent fetch/pull operations per bare repo
  - **Branch cleanup on sandbox destroy and prune** - safely deletes sandbox branches from the bare repo, skipping well-known branches and branches still in use by other worktrees
  - **Sandbox branch identity** passed to proxy metadata in `new.sh` and `start.sh` with fail-closed enforcement for legacy sandboxes without branch identity
- **Sparse checkout proxy support** - allows `git sparse-checkout list` through proxy with read-only enforcement; adds `core.sparseCheckout`/`core.sparseCheckoutCone` to permitted config keys
- **Comprehensive test suite for branch isolation**
  - Unit tests (96): subcommand extraction, rev suffix stripping, branch name validation, ref validation, `validate_branch_isolation`, output filtering
  - Integration tests (34): cross-sandbox blocking and filtering end-to-end
  - Security regression tests (12): leak channel coverage for reflog, notes, for-each-ref, log decorations, branch -a, show-ref
- **Structured plan documentation** under `docs/plans/branch-isolation/` with per-phase implementation details

### Fixed
- **Push protection** now uses `_resolve_bare_repo_path()` instead of unpopulated metadata field, with default branch detection from bare repo HEAD
- **`repositoryformatversion`** bumped to 1 so git extensions like `worktreeConfig` are recognized; applied in both host-side `configure_sparse_checkout()` and proxy-side `fix_proxy_worktree_paths()`
- **VirtioFS stale inode** workaround - defensive `cat` refresh on bare repo config and re-set of `extensions.worktreeConfig` in the proxy
- **Sandbox creation bugs** from git policy hardening phases 4-6: missing git package in unified-proxy Dockerfile, replaced tmpfs `.git` overlay with `/dev/null` bind mount for worktree support, fixed addon validation matching, added git identity configuration and `/workspace` path translation in proxy

## [0.10.0] - 2026-02-06

### Added
- **Git Policy Hardening** - six-phase security hardening for git operations in sandboxes
  - **Phase 1: Git hook prevention** - Disables git hooks via `core.hooksPath=/dev/null`, `core.fsmonitor=false`; controlled by `SANDBOX_GIT_HOOKS_ENABLED` env var
  - **Phase 2: Protected branch enforcement** - Blocks direct pushes to `main`, `master`, `release/*`, `production` with fnmatch pattern support and atomic bootstrap lock
  - **Phase 3: .git/ shadow mode isolation** - Hides `.git/` metadata behind tmpfs overlay; all git operations proxied through HTTP API with HMAC-SHA256 authentication
    - `stubs/git-wrapper.sh` - Shell wrapper intercepting git commands with signal handling, 30s timeout, fail-closed on errors
    - `unified-proxy/git_api.py` - HTTP API (port 8083) for git command execution
    - `unified-proxy/git_operations.py` - Deny-by-default command allowlist with per-operation flag validation, path traversal prevention, 10MB output limit
  - **Phase 4: GitHub API endpoint path enforcement** - Blocks dangerous API paths (webhooks, deploy keys, secrets, actions) with segment-aware matching and path normalization
  - **Phase 5: PR/issue operation controls** - Blocks closing PRs/issues via PATCH with JSON body inspection; fail-closed on malformed/streaming bodies
  - **Phase 6: Auto-track new branches** - Configures tracking on branch creation so `git push` works without `--set-upstream`
- **Git policy hardening spec** and implementation plan documentation
- **Security test suite** for git policy enforcement (`tests/security/test_git_policy.py`)
- **Unit tests** for git wrapper, git operations, and git proxy components

### Fixed
- **Prune command** now treats stopped containers as prunable (previously only removed exited containers)
- **Orphaned Docker network cleanup** improved in prune command with better detection logic

## [0.9.5] - 2026-02-05

### Added
- **Unified Proxy Architecture**: Consolidated separate api-proxy and credential-isolation gateway into a single `unified-proxy/` component
  - mitmproxy-based addons for credential injection, DNS filtering, policy enforcement, rate limiting, circuit breaking, and Git proxy support
  - Single container replaces two, simplifying deployment and reducing resource usage
  - Internal API for health checks, metrics, and container registration
  - Structured JSON logging with configurable log levels
- **DNS filtering enabled by default** with allowlist-based domain control
  - Security hardening to block non-allowlisted domains at the DNS level
  - Integrated into unified-proxy instead of separate dnsmasq container
- **Expanded allowlist** with additional AI providers and services
  - ChatGPT/Codex endpoints (`chatgpt.com`, `auth.openai.com`)
  - Tavily, Perplexity, and Semantic Scholar APIs
  - Google Auth endpoints for Gemini OAuth flows
  - Additional GitHub domains (`release-assets`, `codeload`, `uploads`)
  - Expanded package registries (npm, crates.io, Go proxy, Homebrew)
- **Comprehensive test suite** for unified-proxy
  - Unit tests: circuit breaker, container identity, DNS filter, Git proxy, pktline, policy engine, rate limiter, registry, credential injector, metrics
  - Integration tests: API proxy, container lifecycle, Git operations, DNS registration flow
  - Performance tests: latency benchmarks, throughput testing
- **Architecture Decision Records** (ADRs) for key design decisions
  - ADR-001: Consolidation of api-proxy and gateway
  - ADR-002: Container identity model
  - ADR-003: Policy engine design
  - ADR-004: DNS integration approach
  - ADR-005: Failure modes and circuit breaker strategy

### Changed
- **Documentation overhaul**: Restructured security docs, added operational guides, updated all references from gateway/api-proxy to unified-proxy
- **Defense-in-depth renumbering**: Updated security layer numbering after shell overrides removal
- `docker-compose.credential-isolation.yml` updated for unified-proxy architecture

### Removed
- **Shell overrides layer** (`safety/shell-overrides.sh`): Replaced by proxy-level controls in the unified-proxy
  - Command blocking now handled at the network/policy layer instead of shell interception
  - Reduces attack surface and eliminates shell escape vectors
- **Separate api-proxy and gateway containers**: Replaced by single unified-proxy

## [0.9.2] - 2026-02-03

### Added
- **`cast refresh-credentials` command** to reload credentials in running sandboxes
  - Direct mode: Syncs credentials from host to container
  - Credential isolation mode: Restarts api-proxy to reload credentials
  - `--last` flag to refresh the last attached sandbox
  - Auto-detects sandbox when run from a worktree directory
  - Interactive fzf selection when no sandbox specified

## [0.9.1] - 2026-02-03

### Added
- **`--without-opencode` build flag** for smaller Docker images
  - `cast build --without-opencode` skips Go and OpenCode installation
  - `install.sh --without-opencode` propagates to build step
  - Reduces image size when OpenCode is not needed
- **`SANDBOX_ENABLE_TAVILY` flag** for explicit Tavily enablement tracking
  - Replaces checking for placeholder values in container

### Changed
- **Tavily MCP baked into Docker image** instead of runtime installation
  - Required for credential isolation mode (npm blocked by firewall)
  - Falls back to runtime install for older images
- OpenCode directories only created when `SANDBOX_ENABLE_OPENCODE=1`
- Improved log messages for CLI tool setup (cleaner formatting)

### Fixed
- **Tavily MCP credential injection** in credential isolation mode
  - Tavily API sends `api_key` in both header AND request body
  - Proxy now injects credentials into JSON body, not just Authorization header
- **Network warning accuracy**: Distinguishes orphaned vs active sandbox networks
  - Shows count of orphaned networks that can be cleaned up
  - Provides appropriate cleanup command based on network state

## [0.9.0] - 2026-02-03

### Added
- **Presets and command history** for `cast new`
  - `cast new --last` or `cast repeat` to repeat the previous `cast new` command
  - `cast new --save-as <name>` to save current configuration as a named preset
  - `cast new --preset <name>` to create a sandbox from a saved preset
  - `cast preset list|show|delete` commands for preset management
  - Auto-increment sandbox names (`-2`, `-3`, etc.) when repeating to allow multiple sandboxes
- **IDE launch integration** for `cast new` and `cast attach`
  - `--with-ide[=name]` flag to launch an IDE (cursor, zed, code) then terminal
  - `--ide-only[=name]` flag to launch IDE only, skip terminal
  - `--no-ide` flag to skip IDE selection prompt
  - Interactive IDE selection prompt when multiple IDEs are available
  - Supports Cursor, Zed, and VS Code
- **`cast reattach` command** - auto-reattach to last sandbox or detect from current directory
  - `cast attach --last` to reattach to the previously attached sandbox
  - `cast attach` (no args) auto-detects sandbox when run from a worktree directory
- **Opt-in tool enablement** for OpenCode and ZAI
  - `--with-opencode` flag to enable OpenCode setup (requires host auth file)
  - `--with-zai` flag to enable ZAI Claude alias (requires `ZHIPU_API_KEY`)
  - Tools are disabled by default; explicitly enable to use them
- **Docker network capacity check** before sandbox creation
  - Proactive detection of exhausted Docker network address pools
  - Helpful error messages with remediation steps
  - Warning when sandbox network count exceeds 20
- **Guided mode command echo** shows the equivalent CLI command after interactive setup
- Network cleanup on destroy: credential isolation networks (`credential-isolation`, `proxy-egress`) are now explicitly removed

### Changed
- **Claude authentication is now mandatory**
  - Requires `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`
  - Other AI tools (Gemini, Codex, OpenCode) are optional with helpful warnings when unconfigured
- **OpenCode and ZAI configuration** only applied when explicitly enabled
  - Reduces container startup noise and avoids copying unnecessary config files
  - Auth files, config stubs, and plugin syncing skipped unless tool is enabled
- Improved authentication warnings on `cast start` for missing CLI credentials

### Fixed
- Orphaned Docker networks now cleaned up during `cast destroy` and `cast destroy-all`
- TOML syntax error in `.foundry-mcp.toml` provider lists (missing comma)

## [0.8.0] - 2026-02-02

### Added
- **Tavily MCP server integration** for all AI tools (Claude Code, OpenCode, Codex CLI, Gemini CLI)
  - Auto-configured in each tool's MCP server settings
  - Permissions auto-approval for `mcp__tavily-mcp__*` tools
  - Requires `TAVILY_API_KEY` environment variable
- **Guided interactive mode** for `cast new` command
  - TUI-based questionnaire using gum (with read fallback)
  - Friendly prompts for repo, branch, working directory, and options
  - Summary confirmation before sandbox creation
- **GitHub API filter improvements**
  - Conditional PR operations controlled by `--allow-pr` / `ALLOW_PR_OPERATIONS`
  - GraphQL mutation filtering for history protection (`mergePullRequest`, `reopenPullRequest` always blocked)
  - Release asset upload support for `uploads.github.com`
- **Improved installer** with auto-install for dependencies
  - tmux: auto-installs via Homebrew (macOS), apt, dnf, or yum
  - gum: auto-installs via Homebrew (macOS), optional on Linux
  - Better error messages with platform-specific installation instructions
- **AGENTS.md stub file** for foundry workflow documentation in sandboxes
- `api-proxy/github_config.py` for shared GitHub API configuration

### Changed
- **Gateway public repo support**: Read operations no longer require GitHub token (public repos accessible anonymously)
- **Gateway auth handling**: Added `WWW-Authenticate` header for proper git credential retry
- GitHub token lookup now checks both `GITHUB_TOKEN` and `GH_TOKEN` environment variables
- mitmproxy CA certificate automatically added to system trust store for git SSL verification

### Fixed
- Git operations to public repos now work without authentication in gateway

## [0.7.0] - 2026-02-01

### Added
- `stubs/` directory for files injected into sandboxes (CLAUDE.md stub)
- Expanded red team security tests with comprehensive attack scenarios
  - Credential extraction attempts (env vars, files, proxy attacks)
  - Network escape vectors (DNS bypass, IP literals, tunneling)
  - Container escape attempts (mounts, sockets, cgroups)
  - Social engineering defense tests
- Security documentation reorganization:
  - `docs/security/security-model.md` - Security model (consolidated from former index.md)
  - `docs/security/credential-isolation.md` - Credential isolation threat model
  - `docs/security/sandbox-threats.md` - Sandbox threat model and attack taxonomy
  - `docs/security/security-architecture.md` - Defense-in-depth architecture

### Changed
- Simplified project `CLAUDE.md` to concise developer reference
- Reorganized security documentation into `docs/security/` directory

### Added
- Git push ref update parsing and fast-forward detection in gateway
- GitHub API filter proxy support
- `*.openai.com` and `*.chatgpt.com` wildcards to firewall allowlist
- `chatgpt.com` and `cloudcode-pa.googleapis.com` to OAuth injection
- Multi-sandbox support with dynamic DNS configuration
- **Dual-layer egress filtering**: Defense-in-depth security for credential isolation
  - API proxy hostname validation: Blocks HTTP requests to non-allowlisted hosts before proxying
  - DNS default-deny mode: dnsmasq blocks all domains by default, only forwards allowlisted domains
  - Both layers share the same `firewall-allowlist.generated` configuration
  - Prevents data exfiltration to arbitrary external services

### Changed
- **DNS security hardening**: dnsmasq now uses `no-resolv` and `address=/#/` to block all unallowlisted domains
- DNS queries forwarded to Docker's internal DNS (127.0.0.11) instead of upstream resolvers
- Added DNS query logging for security auditing
- **Default credential isolation**: `--isolate-credentials` is now the default behavior
  - API keys are held in a proxy container and never enter the sandbox
  - Use `--no-isolate-credentials` to opt out (not recommended)
- **OpenCode authentication**: Switched from OAuth to API key authentication for zai-coding-plan model
- **Codex OAuth endpoint**: Updated from `auth0.openai.com` to `auth.openai.com`
- **Firewall architecture**: Simplified to wildcard DNS filtering mode (replaced rotating IP domain handling)
- **Gateway socket location**: Moved from `/tmp` to `~/.foundry-sandbox/sockets/` for Docker Desktop macOS compatibility
- Gateway socket now uses bind mount instead of named volume for host accessibility

### Removed
- **Full network mode**: `--network=full` has been removed for security reasons
  - Available modes: `limited` (default), `host-only`, `none`
  - Attempting to use `full` mode shows a helpful error message
- **Runtime domain additions**: `sudo network-mode allow <domain>` has been disabled
  - To allow additional domains, set `SANDBOX_ALLOWED_DOMAINS` on the host before creating the sandbox
- Cursor AI tool configuration and references

### Fixed
- Dynamic DNS configuration for multi-sandbox support (no more IP conflicts)
- OAuth token handling for Codex, Gemini, and OpenCode CLIs
  - Extract JWT exp claim for accurate token expiry
  - Use distinct placeholders for OpenCode vs Codex
  - Add Gemini and OpenCode config stubs for OAuth
- Gateway socket accessible from host for session management
- Gateway and sandbox infrastructure improvements

## [0.6.0] - 2026-02-01

### Added
- **Credential Isolation Gateway**: Complete implementation of a secure proxy gateway for credential isolation
  - HTTP/HTTPS egress proxy with domain allowlist enforcement
  - DNS filtering via dnsmasq to restrict domain resolution
  - Network firewall rules for limited egress mode
  - Audit logging for all proxy allow/deny decisions
  - IP literal request blocking to prevent DNS bypass attacks
- Wildcard domain support (`*.example.com`) for dynamic subdomains
  - Suffix-based matching for CDNs and rotating API endpoints
  - Gateway-level hostname validation against wildcard patterns
  - DNS forwarding for wildcard domains via dnsmasq `server=` directive
  - Wildcard mode in firewall opens ports 80/443 (security via DNS + gateway)
- Gateway security hardening:
  - Privilege dropping after startup (runs as unprivileged user)
  - Session limits and rate limiting
  - Input sanitization and request validation
  - CAP_NET_RAW capability handling for health checks
  - IPv6 firewall rules mirroring IPv4 restrictions
- Conditional gateway mode with Basic auth and repository scoping
- Security documentation: threat model and security overview for credential isolation
- Comprehensive test suite for gateway functionality:
  - DNS bypass prevention tests
  - Wildcard domain matching tests
  - Hostname allowlist validation tests

### Changed
- Removed rotating IP domain handling (replaced by wildcard mode)

## [0.5.9] - 2026-01-31

### Added
- Gemini CLI OAuth support in credential isolation mode
  - Automatic token refresh using Gemini CLI's embedded OAuth credentials
  - Token validation interception for placeholder tokens (tokeninfo, userinfo)
  - Support for `cloudcode-pa.googleapis.com` initialization endpoint

### Fixed
- Clear `GOOGLE_API_KEY` and `GEMINI_API_KEY` env vars when OAuth is configured to prevent API key auth override
- Fixed tokeninfo validation to check Authorization header (google-auth-library sends token there)
- Reordered OAuth handlers so Gemini has priority over OpenCode for Google APIs

## [0.5.8] - 2026-01-29

### Changed
- Credential isolation refactored from transparent to explicit proxy mode
  - Switch from iptables-based traffic redirection to HTTP_PROXY/HTTPS_PROXY environment variables
  - Remove NET_ADMIN capability requirement (no longer needed)
  - Use `regular` proxy mode instead of `transparent`
  - Make credential-isolation network internal for added security

### Removed
- `safety/credential-proxy-init.sh` script (iptables setup no longer needed)
- `CREDENTIAL_ISOLATION` and `CREDENTIAL_PROXY_PORT` environment variables

### Fixed
- Gracefully handle missing OAuth credential files in proxy entrypoint
- Auto-detect api-proxy container in `compose_down` for proper cleanup

## [0.5.7] - 2026-01-28

### Added
- Pip requirements installation support with `--pip-requirements` / `-r` flag for `cast new`
  - Specify path: `--pip-requirements requirements.txt` or `-r requirements-dev.txt`
  - Auto-detect: `--pip-requirements` or `-r` alone detects `/workspace/requirements.txt`
  - Supports host paths (copied into container), workspace-relative paths, and tilde expansion
  - Pip requirements automatically re-installed on `cast start`/`cast attach`
  - Configuration persisted in sandbox metadata for session restoration

### Changed
- Removed `~/.foundry-mcp` volume mount from docker-compose.yml; directories now created in entrypoint.sh
  - Creates `~/.foundry-mcp/cache`, `~/.foundry-mcp/errors`, `~/.foundry-mcp/metrics` at container startup

## [0.5.6] - 2026-01-27

### Added
- Perplexity search provider configuration options in `.foundry-mcp.toml`
  - `perplexity_search_context_size`, `perplexity_max_tokens`, `perplexity_country`, etc.
- Semantic Scholar search provider configuration options in `.foundry-mcp.toml`
  - `semantic_scholar_publication_types`, `semantic_scholar_sort_by`, `semantic_scholar_use_extended_fields`
- Block dangerous GitHub CLI commands that require operator approval:
  - `gh api` (raw API access)
  - `gh secret` (repository secrets access)
  - `gh variable` (repository variables access)
- Add `gh issue` and `gh pr` commands to auto-allowed permissions for workflow automation

### Changed
- Removed risky git commands from auto-allow permissions: `cherry-pick`, `clean`, `rebase`, `reset`, `rm`
- Broadened workspace permissions from `/workspace/**/specs/**` to `/workspace/**`
- Hooks configuration now restored after host settings are copied (fixes hooks being overwritten)
- Skip `hooks.json` when copying hook executables (plugin-specific format)
- Use `exec` for tmux attach to avoid orphan shell processes

## [0.5.5] - 2026-01-26

### Added
- Automatic installation of foundry workspace documentation into sandboxes
  - Copies `CLAUDE.md` from claude-foundry plugin cache to `/workspace/CLAUDE.md`
  - Copies `AGENTS.md` from opencode-foundry to `/workspace/AGENTS.md`
  - Uses marker comments to prevent duplicate content on subsequent runs
  - Configurable via `SANDBOX_OPENCODE_FOUNDRY_PATH` environment variable

## [0.5.4] - 2026-01-26

### Added
- `foundry-upgrade` alias in sandboxes for upgrading foundry-mcp (includes pre-release versions)
- `FOUNDRY_SEARCH_PROVIDERS` environment variable to explicitly configure search providers
  - Accepts comma-separated list: `tavily`, `perplexity`, `semantic_scholar`
  - When set, overrides auto-detection (based on API keys)
  - When unset, uses existing auto-detection behavior
- Expanded `.foundry-mcp.toml` example configuration:
  - Tavily search provider settings (`tavily_search_depth`, `tavily_topic`, `tavily_country`, etc.)
  - Tavily extract provider settings for deep research URL extraction
  - Token management configuration (`token_management_enabled`, `token_safety_margin`, `runtime_overhead`)
  - Summarization configuration with provider fallback chain
  - Content dropping and archive settings for budget management

### Changed
- Updated config priority documentation to include XDG config path (`~/.config/foundry-mcp/config.toml`)

## [0.5.3] - 2026-01-25

### Added
- `DISABLE_INSTALLATION_CHECKS` environment variable to suppress Claude Code startup checks inside sandboxes

### Changed
- Refactored `ensure_claude_statusline()` to properly add statusLine config when binary exists (previously only removed config when missing)

### Removed
- `installMethod` setting from onboarding configuration (Claude Code handles this automatically)

## [0.5.2] - 2026-01-24

### Added
- Timezone synchronization: sandboxes now inherit host timezone
  - Detects timezone from `/etc/timezone` or `/etc/localtime` symlink
  - Mounts `/etc/localtime` and `/etc/timezone` read-only into containers
  - Sets `TZ` environment variable for applications that use it
- Configurable default OpenCode model inside sandboxes via `SANDBOX_OPENCODE_DEFAULT_MODEL`
- Configurable tmux scrollback and mouse mode via `SANDBOX_TMUX_SCROLLBACK` and `SANDBOX_TMUX_MOUSE` (mouse default off)

### Changed
- Codex CLI now defaults to `approval_policy = "on-failure"` and `sandbox_mode = "danger-full-access"` inside containers when host config doesn't set them

### Fixed
- Network firewall script silently exiting when debug mode disabled, preventing tmux attach after `cast new`

## [0.5.1] - 2026-01-24

### Added
- Dynamic research provider configuration: `deep_research_providers` is now automatically configured based on available API keys
  - If `TAVILY_API_KEY` is set, tavily is added to providers
  - If `PERPLEXITY_API_KEY` is set, perplexity is added to providers
  - `semantic_scholar` is always included (no API key required)
- Per-phase fallback provider lists for deep research resilience
- Retry configuration for deep research (`deep_research_max_retries`, `deep_research_retry_delay`)

### Changed
- Updated `.foundry-mcp.toml` example config with per-phase fallback providers and retry settings
- Removed deprecated `storage_backend` and `storage_path` settings from research config

## [0.5.0] - 2026-01-24

### Changed
- Foundry plugin installation replaced with direct global install
  - Skills copied directly to `~/.claude/skills/` (no plugin namespace)
  - Hooks copied to `~/.claude/hooks/` and registered in `settings.json`
  - MCP server registered in `~/.claude.json` under `mcpServers`
  - Eliminates plugin update mechanism that caused issues in sandboxes
  - Skill commands change from `/foundry:foundry-spec` to `/foundry-spec`

### Fixed
- GitHub connectivity in limited network mode: added CIDR range whitelisting to handle DNS-based IP rotation
  - GitHub publishes IPs at https://api.github.com/meta
  - Whitelists 4 CIDR blocks covering web, api, git, and pages endpoints
  - Matches existing approach used for Cloudflare IPs

### Removed
- Plugin system files no longer created: `installed_plugins.json`, `enabledPlugins`, `marketplace.json`, `known_marketplaces.json`
- `rewrite_claude_plugin_remotes()` and `rewrite_claude_marketplaces()` functions (no longer needed)
- `claude plugin enable` and `claude mcp add-json` CLI calls (replaced with direct file writes)

## [0.4.0] - 2026-01-22

### Added
- GitHub CLI authentication passthrough: `gh auth` credentials now automatically work inside containers
  - New `export_gh_token()` extracts token from macOS keychain
  - `GH_TOKEN` environment variable passed to container
  - `gh auth git-credential` configured as git credential helper
- Nested git repository detection: warns when sparse checkout contains nested `.git` directories that shadow the worktree
- Auto-add `specs/.backups` to worktree `.gitignore` for foundry spec backups
- Additional dangerous command detection: `rsync --delete`, `find -delete`, `find -exec rm`

### Changed
- Shell safety layer now blocks all `rm` commands (previously only blocked `-rf` patterns)
  - Any file deletion now requires human operator approval

### Fixed
- Sparse worktree detection: sets `core.worktree` config for `--no-checkout` sparse worktrees

## [0.3.0] - 2026-01-22

### Added
- Monorepo support with `--wd <path>` flag to set working directory within repo
- Sparse checkout support with `--sparse` flag (only checkouts working directory + root configs)
- Container tmux sessions now start in the specified working directory

### Changed
- Foundry MCP config path changed from `~/.foundry-mcp.toml` to `~/.config/foundry-mcp/config.toml`
- Foundry MCP specs directories now created relative to working directory when `--wd` is used
- Permissions module now uses `~/.claude/settings.json` instead of `/workspace/.claude/settings.local.json`

### Fixed
- Docker daemon timeout check now uses gtimeout/timeout command instead of manual implementation

## [0.2.0] - 2026-01-22

### Added
- `.env.example` template for API key configuration
- `lib/permissions.sh` module for installing foundry permissions into workspace `.claude/settings.local.json`
- `docs/configuration.md` consolidating configuration reference (API keys, plugins, config file mappings)
- `.foundry-mcp.toml` config file sync from host to container
- Automatic creation of foundry-mcp workspace directories (`/workspace/specs/*`, `~/.foundry-mcp/*`)
- Git retry logic with exponential backoff for network resilience
- Sandbox name collision detection to prevent overwriting existing sandboxes
- `sanitize_ref_component()` function for generating valid git branch names
- `codexdsp` alias for `codex --dangerously-bypass-approvals-and-sandbox`

### Changed
- API keys are now passed via environment variables instead of file sync
- Updated documentation for environment variable-based credential management
- Installer no longer creates a git repository in `~/.foundry-sandbox`; files are synced directly, eliminating update conflicts from local modifications
- README simplified; detailed usage, config, and architecture content moved to docs
- Branch naming now uses `{user}/{repo}-{timestamp}` format instead of `sandbox/{repo}-{timestamp}`
- Sandbox naming simplified to use branch name only (without repo prefix)
- Renamed `cdsp` alias to `claudedsp` for clarity

### Removed
- `--with-api-keys` and `--no-api-keys` CLI flags
- `~/.api_keys` file sync functionality
- `SANDBOX_SYNC_API_KEYS` configuration variable
- `cdspr` alias (use `claudedsp --resume` instead)

## [0.1.0] - 2026-01-21

### Added

- Initial release of Foundry Sandbox
- Core sandbox creation and management (`cast new`, `cast attach`, `cast destroy`)
- Git worktree-based ephemeral workspaces
- Defense in depth safety system:
  - Credential redaction
  - Operator approval (TTY-based human-in-loop)
  - Sudoers allowlist (kernel-enforced)
  - Network isolation (iptables/Docker)
  - Read-only root filesystem (Docker-enforced)
- Network modes: full, limited (whitelist), host-only, none
- Volume mount support (`--mount`, `--copy`)
- SSH agent forwarding (`--with-ssh`)
- Pre-installed AI tools: Claude Code, Gemini CLI, Codex CLI, OpenCode
- Pre-installed claude-foundry plugin with MCP server
- JSON output for all commands (`--json`)
- Tab completion for bash
- macOS and Linux support

[Unreleased]: https://github.com/foundry-works/foundry-sandbox/compare/v0.21.0...HEAD
[0.21.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.15...v0.21.0
[0.20.15]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.14...v0.20.15
[0.20.14]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.13...v0.20.14
[0.20.13]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.12...v0.20.13
[0.20.12]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.11...v0.20.12
[0.20.11]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.10...v0.20.11
[0.20.10]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.9...v0.20.10
[0.20.9]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.8...v0.20.9
[0.20.8]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.7...v0.20.8
[0.20.7]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.6...v0.20.7
[0.20.6]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.5...v0.20.6
[0.20.5]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.4...v0.20.5
[0.20.4]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.3...v0.20.4
[0.20.3]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.2...v0.20.3
[0.20.2]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.1...v0.20.2
[0.20.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.20.0...v0.20.1
[0.20.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.19.4...v0.20.0
[0.19.4]: https://github.com/foundry-works/foundry-sandbox/compare/v0.19.3...v0.19.4
[0.19.3]: https://github.com/foundry-works/foundry-sandbox/compare/v0.19.1...v0.19.3
[0.19.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.18.2...v0.19.0
[0.18.2]: https://github.com/foundry-works/foundry-sandbox/compare/v0.18.1...v0.18.2
[0.18.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.17.4...v0.18.0
[0.17.4]: https://github.com/foundry-works/foundry-sandbox/compare/v0.17.3...v0.17.4
[0.17.3]: https://github.com/foundry-works/foundry-sandbox/compare/v0.17.2...v0.17.3
[0.17.2]: https://github.com/foundry-works/foundry-sandbox/compare/v0.17.1...v0.17.2
[0.17.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.9...v0.16.0
[0.15.9]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.8...v0.15.9
[0.15.8]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.7...v0.15.8
[0.15.7]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.6...v0.15.7
[0.15.6]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.5...v0.15.6
[0.15.5]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.4...v0.15.5
[0.15.4]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.3...v0.15.4
[0.15.3]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.2...v0.15.3
[0.15.2]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.9.5...v0.10.0
[0.9.5]: https://github.com/foundry-works/foundry-sandbox/compare/v0.9.2...v0.9.5
[0.9.2]: https://github.com/foundry-works/foundry-sandbox/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.9...v0.6.0
[0.5.9]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.8...v0.5.9
[0.5.8]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.7...v0.5.8
[0.5.7]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/foundry-works/foundry-sandbox/releases/tag/v0.1.0
