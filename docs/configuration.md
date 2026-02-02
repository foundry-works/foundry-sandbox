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

Run `opencode auth login` for standard auth. OAuth for OpenAI/Codex models works automatically via the sandbox proxy - no additional plugins needed.

To set a sandbox-wide OpenCode default model (when `~/.config/opencode/opencode.json` has no `model` set), use:

```bash
export SANDBOX_OPENCODE_DEFAULT_MODEL="openai/gpt-5.2-codex"
```

### Tmux

Sandbox tmux sessions can be tuned via environment variables:

```bash
export SANDBOX_TMUX_SCROLLBACK=200000
export SANDBOX_TMUX_MOUSE=0
```
