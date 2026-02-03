# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  - `docs/security/index.md` - Security overview and quick reference
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
- Pre-installed AI tools: Claude Code, Gemini CLI, Codex CLI, OpenCode
- Pre-installed claude-foundry plugin with MCP server
- JSON output for all commands (`--json`)
- Tab completion for bash
- macOS and Linux support

[Unreleased]: https://github.com/foundry-works/foundry-sandbox/compare/v0.9.1...HEAD
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
