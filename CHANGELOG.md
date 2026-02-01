# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Cursor domain configuration simplified from individual domains to wildcards (`*.cursor.com`, `*.cursor.sh`)
- Removed rotating IP domain handling (replaced by wildcard mode)

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
- 6-layer defense in depth safety system:
  - Layer 1: Shell overrides (UX warnings)
  - Layer 2: Credential redaction
  - Layer 3: Operator approval (TTY-based human-in-loop)
  - Layer 4: Sudoers allowlist (kernel-enforced)
  - Layer 5: Network isolation (iptables/Docker)
  - Layer 6: Read-only root filesystem (Docker-enforced)
- Network modes: full, limited (whitelist), host-only, none
- Volume mount support (`--mount`, `--copy`)
- SSH agent forwarding (`--with-ssh`)
- Pre-installed AI tools: Claude Code, Gemini CLI, Codex CLI, OpenCode, Cursor Agent
- Pre-installed claude-foundry plugin with MCP server
- JSON output for all commands (`--json`)
- Tab completion for bash
- macOS and Linux support

[Unreleased]: https://github.com/foundry-works/foundry-sandbox/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.8...v0.6.0
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
