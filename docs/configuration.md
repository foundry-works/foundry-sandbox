# Configuration

This guide covers configuration options for Foundry Sandbox, including AI tool plugins, API keys, and config file mappings.

## Claude Plugin

The [claude-foundry](https://github.com/foundry-works/claude-foundry) plugin is installed automatically when you create a new sandbox. This provides:
- **foundry-mcp** MCP server with spec-driven development tools
- Skills: `/foundry-spec`, `/foundry-implement`, `/foundry-review`, `/foundry-test`, etc.

No host installation required. The plugin is fetched from GitHub and configured during sandbox creation.

### Statusline

If you use [cc-context-stats](https://github.com/luongnv89/cc-context-stats), place your `statusline.conf` in `~/.claude/statusline.conf` and it will be copied into new sandboxes. The Docker image includes `claude-statusline`, so the statusline works out of the box.

### LSPs

The `pyright-lsp` plugin is installed from the official Claude marketplace for type checking support.

## API Keys

API keys are passed to containers via environment variables. Set them in your shell profile or use a `.env` file:

```bash
# AI Provider Keys (at least one required)
export CLAUDE_CODE_OAUTH_TOKEN="..."   # Get via: claude setup-token

# Search Provider Keys (optional - for deep research features)
export TAVILY_API_KEY="..."
export PERPLEXITY_API_KEY="..."
```

See `.env.example` for all supported keys.

## Config Files

The sandbox automatically copies configuration files from your host into containers:

| Source | Destination | Purpose |
|--------|-------------|---------|
| `~/.claude.json` | `/home/ubuntu/.claude.json` | Claude Code preferences (host file only) |
| `~/.claude/settings.json` | `/home/ubuntu/.claude/settings.json` | Claude Code settings |
| `~/.claude/statusline.conf` | `/home/ubuntu/.claude/statusline.conf` | Optional Claude statusline config (cc-context-stats; `claude-statusline` is bundled in the image) |
| `~/.gitconfig` | `/home/ubuntu/.gitconfig` | Git configuration |
| `~/.ssh/` | `/home/ubuntu/.ssh/` | SSH config/keys (when enabled) |
| `~/.config/gh/` | `/home/ubuntu/.config/gh/` | GitHub CLI (from `gh auth login`) |
| `~/.gemini/` | `/home/ubuntu/.gemini/` | Gemini CLI OAuth (from `gemini auth`) |
| `~/.config/opencode/opencode.json` | `/home/ubuntu/.config/opencode/opencode.json` | OpenCode config |
| `~/.local/share/opencode/auth.json` | `/home/ubuntu/.local/share/opencode/auth.json` | OpenCode auth (from `opencode auth login`) |

## Tool-Specific Notes

### Gemini CLI

Run `gemini auth` on your host to authenticate. The OAuth credentials in `~/.gemini/` are automatically copied into containers. Large Gemini CLI artifacts (e.g. `~/.gemini/antigravity`) are skipped to keep sandboxes lightweight.

Sandboxes default to disabling auto-updates, update nags, telemetry, and usage stats unless you set them in `~/.gemini/settings.json`.

### Codex CLI

Sandboxes default to disabling update checks and analytics via `~/.codex/config.toml`. If your host config does not set them, sandboxes also default to `approval_policy = "on-failure"` and `sandbox_mode = "danger-full-access"` inside the container.

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

Packages are re-installed on `cast start` and `cast attach` (if the sandbox was stopped), ensuring dependencies stay in sync after container restart.

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

### Tmux

Sandbox tmux sessions can be tuned via environment variables:

```bash
export SANDBOX_TMUX_SCROLLBACK=200000
export SANDBOX_TMUX_MOUSE=0
```

## Proxy Allowlist Extension

The unified proxy enforces network access via an allowlist that declares permitted domains, HTTP endpoints, and blocked paths. To grant additional network access to a sandbox without replacing the entire allowlist, use the `PROXY_ALLOWLIST_EXTRA_PATH` environment variable:

```bash
export PROXY_ALLOWLIST_EXTRA_PATH="/path/to/allowlist-extra.yml"
```

When credential isolation is enabled, this file is automatically mounted into the container at `/etc/unified-proxy/allowlist-extra.yml` and merged with the base allowlist.

### Merge Semantics

The merge is **additive-only**: extra entries can only grant access, never revoke access granted by the base allowlist. This preserves the security properties of the base allowlist while allowing controlled expansion.

The extra file uses a relaxed schema where `domains`, `http_endpoints`, and `blocked_paths` may all be omitted. Only the `version` field is required. For example:

```yaml
version: "1"
domains:
  - example.com
http_endpoints:
  - host: private-registry.example.com
    methods: [GET, POST]
    paths: [/v2/*, /manifests/*]
```

### Failure Policy

This is a **fail-closed** mechanism:

- If `PROXY_ALLOWLIST_EXTRA_PATH` is set but the file does not exist, proxy startup fails
- If the file exists but contains invalid YAML or schema errors, proxy startup fails
- If the file is missing the required `version` field, proxy startup fails

No partial allowlist startup is permitted. This prevents silent security degradation from misconfigured extras.

For detailed merge canonicalization rules and precedence logic, see [ADR-008: Allowlist Layering](/docs/adr/008-allowlist-layering.md).

## Internal API: Docker Compose Overrides

The `foundry_sandbox.docker` module provides a `compose_extras` parameter on programmatic compose operations (`get_compose_command()`, `compose_up()`, `compose_down()`) for advanced use cases.

`compose_extras` accepts a list of paths to additional docker-compose override files:

```python
from foundry_sandbox.docker import compose_up

compose_up(
    worktree_path=...,
    claude_config_path=...,
    container=...,
    compose_extras=["/path/to/override1.yml", "/path/to/override2.yml"],
)
```

Each file must exist and be a regular file; non-existent paths raise `FileNotFoundError`. Files are appended as `-f <path>` arguments to the docker compose command in list order, after the base compose file and credential isolation file.

This is an internal API intended for programmatic integration. End users typically configure docker-compose overrides via the standard docker-compose.override.yml mechanism or via other sandboxing features.
