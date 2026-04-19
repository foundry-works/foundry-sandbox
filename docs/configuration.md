# Configuration

This guide covers configuration options for Foundry Sandbox, including AI tool plugins, API keys, git safety settings, and `foundry.yaml` workspace configuration.

## Claude Plugin

The [claude-foundry](https://github.com/foundry-works/claude-foundry) plugin is installed automatically when you create a new sandbox. This provides:
- **foundry-mcp** MCP server with spec-driven development tools
- Skills: `/foundry-spec`, `/foundry-implement`, `/foundry-review`, `/foundry-test`, etc.

No host installation required. The plugin is fetched from GitHub and configured during sandbox creation.

### Statusline

`claude-statusline` is bundled and configured automatically.

### LSPs

The `pyright-lsp` plugin is installed from the official Claude marketplace for type checking support.

## API Keys

API keys are stored on the host via `sbx secret set -g` and injected into sandbox requests by sbx's proxy. They never enter the sandbox VM directly.

```bash
# Store API keys on the host
echo "$ANTHROPIC_API_KEY" | sbx secret set -g anthropic
echo "$GITHUB_TOKEN" | sbx secret set -g github
echo "$OPENAI_API_KEY" | sbx secret set -g openai
```

Or use `cast refresh-creds` to push all configured keys at once:

```bash
cast refresh-creds          # Refresh last sandbox
cast refresh-creds --all    # Refresh all running sandboxes
```

Set your keys in your shell profile or `.env` file:

```bash
# AI Provider Keys (at least one required)
export ANTHROPIC_API_KEY="..."
export CLAUDE_CODE_OAUTH_TOKEN="..."   # Get via: claude setup-token

# Search Provider Keys (optional - for deep research features)
export TAVILY_API_KEY="..."
export PERPLEXITY_API_KEY="..."
```

## Config Files

The sandbox copies configuration files from your host into the sandbox via `sbx exec`:

| Source | Destination | Purpose |
|--------|-------------|---------|
| `~/.claude.json` | Claude preferences (host file only) | Claude Code preferences |
| `~/.claude/settings.json` | Claude settings | Claude Code settings |
| `~/.gitconfig` | Git configuration | Git user/name/email |
| `~/.config/gh/` | GitHub CLI config | From `gh auth login` |
| `~/.gemini/` | Gemini CLI OAuth | From `gemini auth` |
| `~/.config/opencode/opencode.json` | OpenCode config | OpenCode settings |

## Tool-Specific Notes

### Gemini CLI

Run `gemini auth` on your host to authenticate. The OAuth credentials in `~/.gemini/` are automatically copied into sandboxes.

Sandboxes default to disabling auto-updates, update nags, telemetry, and usage stats unless you set them in `~/.gemini/settings.json`.

### Codex CLI

Sandboxes default to disabling update checks and analytics via `~/.codex/config.toml`. If your host config does not set them, sandboxes also default to `approval_policy = "on-failure"` and `sandbox_mode = "danger-full-access"` inside the sandbox.

### OpenCode

Run `opencode auth login` for zai-coding-plan authentication.

### Python / PyPI Packages

Install Python packages from a requirements file using `--pip-requirements` / `-r`:

```bash
# Explicit requirements file
cast new owner/repo feature -r requirements.txt

# Auto-detect: looks for requirements.txt, requirements-dev.txt, etc.
cast new owner/repo feature -r auto
```

When `auto` is specified, the sandbox scans the repository root for common requirements file patterns (`requirements*.txt`) and installs them automatically.

Packages are re-installed on `cast start` and `cast attach` (if the sandbox was stopped), ensuring dependencies stay in sync.

### ZAI

ZAI provides a Claude alias backed by the Zhipu API. Enable with `--with-zai` when creating a sandbox:

```bash
cast new owner/repo feature --with-zai
```

Requires `ZHIPU_API_KEY` set in your environment.

### Search Providers

The `foundry-mcp` research tools support multiple search providers. Set these optional API keys for enhanced research capabilities:

| Variable | Provider | Purpose |
|----------|----------|---------|
| `TAVILY_API_KEY` | Tavily | Web search for deep research |
| `PERPLEXITY_API_KEY` | Perplexity | AI-powered search |
| `SEMANTIC_SCHOLAR_API_KEY` | Semantic Scholar | Academic paper search |

## Git Safety Configuration

The git safety layer (`foundry-git-safety`) is configured via `foundry.yaml` in the workspace root. See `foundry-git-safety/docs/configuration.md` for the complete reference.

### `foundry.yaml` Schema

```yaml
git_safety_server:
  host: "127.0.0.1"
  port: 8083
  secrets_path: "/run/secrets/sandbox-hmac"
  data_dir: "/var/lib/foundry-git-safety"

protected_branches:
  enabled: true
  patterns:
    - "main"
    - "master"
    - "release/*"
    - "production"

file_restrictions:
  blocked_patterns:
    - ".github/workflows/"
    - "Makefile"
  warned_patterns:
    - "package.json"
    - "pyproject.toml"
  warn_action: "log"  # "log" or "reject"

github_api:
  enabled: true
  proxy_port: 8084
  allow_pr_operations: false
```

### Git Safety Server Management

```bash
# Start the server (runs as a daemon by default)
foundry-git-safety start

# Check status
foundry-git-safety status

# Stop the server
foundry-git-safety stop

# Validate configuration
foundry-git-safety validate
```

The server is automatically started by `cast new` if not already running.

## Network Policy Configuration

Network access is managed by sbx's policy system:

```bash
# Set default profile
sbx policy set-default balanced    # Default: common dev domains
sbx policy set-default allow-all   # No restrictions
sbx policy set-default deny-all    # Block all external traffic

# Add domain exceptions
sbx policy allow network example.com
sbx policy deny network ads.example.com
```

## Push File Restrictions

Sandboxes enforce push-time file restrictions to prevent agents from modifying CI/CD pipelines, build system files, or other sensitive configuration. Restrictions are defined in `foundry.yaml` under `file_restrictions`.

### How It Works

File restrictions are enforced at two points:
- **Push time** — The git safety server's `check_push_files()` enumerates files changed between the remote tracking branch and HEAD, matching each against restriction patterns. Blocked files reject the entire push.
- **Commit time** — `check_file_restrictions()` runs against staged files for early feedback before the push attempt.

### Default Restrictions

The default configuration blocks CI/CD pipeline files and generates warnings for dependency/build files:

**Blocked** (always rejected):
- `.github/workflows/`, `.github/actions/` — GitHub Actions
- `Makefile`, `Justfile`, `Taskfile.yml` — Build system entry points
- `.pre-commit-config.yaml` — Git hook configuration
- `CODEOWNERS` — Approval requirement definitions

**Warned** (logged by default):
- `package.json`, `pyproject.toml`, `requirements.txt`, `Gemfile`, `go.mod`, `Cargo.toml` — Dependency manifests
- `Dockerfile`, `docker-compose*.yml` — Container definitions
- `.env*` — Environment files

### Customization

Edit `foundry.yaml` to modify restrictions. Changes take effect on the next git safety server restart. To switch warned patterns from monitoring to enforcement:

```yaml
file_restrictions:
  warn_action: "reject"
```

For pattern matching semantics (directory prefix, glob, basename) and the difference between blocked and warned patterns, see [Security Model: Git Safety](security/security-model.md#git-safety).

## Environment Variables

### Sandbox Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `SANDBOX_HOME` | `~/.sandboxes` | Root directory for sandbox state |
| `SANDBOX_DEBUG` | (unset) | Enable debug logging |
| `SANDBOX_VERBOSE` | (unset) | Show sbx subprocess commands |
| `SANDBOX_ASSUME_YES` | (unset) | Auto-confirm prompts |
| `SANDBOX_NONINTERACTIVE` | (unset) | Non-interactive mode (no prompts) |

### Git Safety

| Variable | Default | Purpose |
|----------|---------|---------|
| `GIT_API_SECRETS_PATH` | `/run/secrets/sandbox-hmac` | HMAC secrets directory |
| `FOUNDRY_DATA_DIR` | `/var/lib/foundry-git-safety` | Git safety data directory |

## See Also

- [Commands](usage/commands.md) — Full CLI reference
- [Getting Started](getting-started.md) — Installation and first sandbox
- [Security Model](security/security-model.md) — Threats, defenses, and hardening
- [foundry-git-safety Configuration](../foundry-git-safety/docs/configuration.md) — Complete git safety config reference
