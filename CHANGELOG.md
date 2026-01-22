# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/foundry-works/foundry-sandbox/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/foundry-works/foundry-sandbox/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/foundry-works/foundry-sandbox/releases/tag/v0.1.0
