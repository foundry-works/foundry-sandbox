# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/foundry-works/foundry-sandbox/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/foundry-works/foundry-sandbox/releases/tag/v0.1.0
