# Configuration

This guide covers configuration options for Foundry Sandbox, including skills, API keys, and config file mappings.

## Skills

Sandboxes are empty by default — no MCP servers or tools are pre-installed. You configure what to mount into sandboxes using **skills**, defined in `~/.sandboxes/skills.toml`.

Each skill can provide:
- A **host directory** to mount into the container (read-only)
- An **MCP server** registration
- **Permission** allow/deny rules
- **Stub files** to append to `/workspace/` (e.g. a CLAUDE.md guide)
- **Environment variables** (with `$VAR` resolution from the host)

### Quick Start

```bash
# Create an example skills.toml
cast skills init

# Edit it to define your skills
$EDITOR ~/.sandboxes/skills.toml

# List configured skills
cast skills list

# Show details for a specific skill
cast skills show my-tool

# Create a sandbox with skills
cast new owner/repo feature --skill my-tool --skill another-tool
```

Skills can also be selected interactively in the `cast new` wizard.

### Configuration Format

```toml
[skills.my-research-tool]
# Host directory to mount into the container (read-only)
path = "~/GitHub/my-research-tool"

# Where to mount inside the container (optional, defaults to /skills/<name>)
mount_target = "/skills/my-research-tool"

# MCP server to register (optional)
mcp_server = { command = "python", args = ["/skills/my-research-tool/server.py"] }

# Extra permissions for this skill (optional)
permissions_allow = ["Bash(my-tool:*)"]
permissions_deny = []

# Stub files from the skill directory to append to /workspace/ (optional)
stubs = ["SKILL_GUIDE.md"]

# Environment variables (optional, $VAR resolves from host env)
env = { MY_API_KEY = "$MY_API_KEY" }
```

### How Skills Are Installed

1. **At creation time** (`cast new`): skill mounts and env vars are added to the container's docker-compose config
2. **At setup time**: MCP servers are registered in the container's `~/.claude.json`, stubs are appended to `/workspace/`, and permissions are merged into `~/.claude/settings.json`
3. **On reattach** (`cast start`): skills are re-installed to ensure MCP servers and stubs are present after container restart

Stubs use HTML comment markers for idempotency — repeated installs won't duplicate content.

### Statusline

The Docker image includes `claude-statusline` and a bundled `statusline.conf`, so the statusline works out of the box.

### LSPs

The `pyright-lsp` plugin is installed from the official Claude marketplace for type checking support.

## API Keys

API keys are passed to containers via environment variables. Set them in your shell profile or use a `.env` file:

```bash
# AI Provider Keys (at least one required)
export CLAUDE_CODE_OAUTH_TOKEN="..."   # Get via: claude setup-token
```

See [Commands: Environment Variables](usage/commands.md#environment-variables) for the full reference, or `.env.example` for a quick template.

## Config Files

The sandbox automatically copies configuration files from your host into containers:

| Source | Destination | Purpose |
|--------|-------------|---------|
| `~/.claude.json` | `/home/ubuntu/.claude.json` | Claude Code preferences (host file only) |
| `~/.claude/settings.json` | `/home/ubuntu/.claude/settings.json` | Claude Code settings |
| (bundled) `statusline.conf` | `/home/ubuntu/.claude/statusline.conf` | Claude statusline config (`claude-statusline` is bundled in the image) |
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

### Tmux

Sandbox tmux sessions can be tuned via environment variables:

```bash
export SANDBOX_TMUX_SCROLLBACK=200000
export SANDBOX_TMUX_MOUSE=0
```

## User-Defined Services

Define custom API services for automatic credential injection and proxy allowlisting. This lets you add new API providers (e.g., OpenRouter, Groq) without modifying the codebase.

### Config File

Create `config/user-services.yaml` (or copy `config/user-services.yaml.example`):

```yaml
version: "1"

services:
  - name: OpenRouter
    env_var: OPENROUTER_API_KEY
    domain: openrouter.ai
    header: Authorization
    format: bearer
    paths: ["/api/**"]

  - name: CustomService
    env_var: CUSTOM_API_KEY
    domain: api.custom.example
    header: X-Api-Key
    format: value
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Display name shown in CLI status output |
| `env_var` | Yes | Host environment variable holding the real API key. Must match `[A-Z_][A-Z0-9_]*` |
| `domain` | Yes | Target domain for credential injection and allowlisting |
| `header` | Yes | HTTP header name for credential injection (e.g., `Authorization`, `X-Api-Key`) |
| `format` | Yes | `bearer` (injects `Bearer <key>`) or `value` (injects raw key) |
| `methods` | No | Allowed HTTP methods. Default: all standard methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `HEAD`) |
| `paths` | No | Allowed URL path globs. Default: `["/**"]` (all paths). Uses the same glob syntax as the proxy allowlist |

### Config File Search Order

1. `FOUNDRY_USER_SERVICES_PATH` environment variable (explicit path)
2. `./config/user-services.yaml` (relative to project root)

If no file is found, the system proceeds without user-defined services.

### What Happens at Runtime

For each service where the corresponding `env_var` is set on the host:

1. **CLI status** — `cast new` displays the service as "configured" or "not configured"
2. **Placeholder generation** — The sandbox receives a placeholder value (e.g., `CRED_PROXY_<hex>`) instead of the real key
3. **Proxy credential injection** — The unified proxy injects the real API key into outbound requests matching the service's domain
4. **Allowlist expansion** — The domain is added to the proxy's allowlist and MITM interception list

### Verifying a Service

```bash
# 1. Set the API key on your host
export OPENROUTER_API_KEY="sk-or-..."

# 2. Create a sandbox — check status output
cast new owner/repo feature
# Should show: "OpenRouter: configured"

# 3. From inside the sandbox, test the service
curl -X POST https://openrouter.ai/api/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{}'
# The proxy injects the real key — check proxy logs for injection confirmation
```

### Limitations

User-defined services support **header-based credential injection only**. The following patterns from built-in providers are not supported:

- OAuth token refresh flows (e.g., Claude OAuth)
- Request body injection (e.g., API keys embedded in JSON payloads)
- File-based credential loading (e.g., Gemini settings files)

### Conflict Resolution

If a user-defined service specifies a domain that already exists in the built-in provider map, the user entry is **skipped** with a warning. Built-in providers cannot be overridden.

### Security

User-defined services expand the proxy's allowlist and MITM interception scope. The config file is host-side only and requires the same trust level as other host-side configuration. See [Security Model: User-Defined Services](security/security-model.md#user-defined-services) for details.

## Push File Restrictions

Sandboxes enforce push-time file restrictions to prevent agents from modifying CI/CD pipelines, build system files, or other sensitive configuration that could enable persistent compromise outside the sandbox. Restrictions are defined in `config/push-file-restrictions.yaml`.

### How It Works

File restrictions are enforced at two points:
- **Push time** — The git API's `check_push_files()` enumerates files changed between the remote tracking branch and HEAD, matching each against the restriction patterns. Blocked files reject the entire push.
- **Commit time** — `check_file_restrictions()` runs against staged files for early feedback before the push attempt.

### Configuration Format

```yaml
version: "1.0"

blocked_patterns:
  - ".github/workflows/"    # Directory prefix
  - "Makefile"              # Exact basename match
  - "*.yml"                 # Glob pattern (hypothetical)

warned_patterns:
  - "package.json"
  - "requirements-*.txt"

warn_action: "log"          # "log" or "reject"
```

For pattern matching semantics (directory prefix, glob, basename) and the difference between blocked and warned patterns, see [Security Model: Git Safety](security/security-model.md#git-safety).

### Default Restrictions

The default configuration blocks CI/CD pipeline files and generates warnings for dependency/build files:

**Blocked** (always rejected):
- `.github/workflows/`, `.github/actions/` — GitHub Actions
- `Makefile`, `Justfile`, `Taskfile.yml` — Build system entry points
- `.pre-commit-config.yaml` — Git hook configuration
- `CODEOWNERS` — Approval requirement definitions
- `.github/FUNDING.yml` — Funding configuration

**Warned** (logged by default):
- `package.json`, `pyproject.toml`, `requirements.txt`, `Gemfile`, `go.mod`, `Cargo.toml` — Dependency manifests
- `Dockerfile`, `docker-compose*.yml` — Container definitions
- `.env*` — Environment files

### Customization

To modify restrictions, edit `config/push-file-restrictions.yaml`. Changes take effect on the next proxy startup. To switch warned patterns from monitoring to enforcement:

```yaml
warn_action: "reject"
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

For detailed merge canonicalization rules and precedence logic, see [ADR-006: Allowlist Layering](adr/006-allowlist-layering.md).

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

## See Also

- [Commands](usage/commands.md) — Full CLI reference and environment variables
- [Getting Started](getting-started.md) — Installation and first sandbox
- [Security Model](security/security-model.md) — Push file restrictions and git safety
