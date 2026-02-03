# Command Reference

Complete reference for all `cast` commands.

## cast new

Create a new sandbox from a repository.

### Synopsis

```
cast new <repo> [branch] [from-branch] [options]
cast new --last
cast new --preset <name>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `repo` | GitHub repo (owner/repo), full URL, or local path (e.g., `.`) |
| `branch` | Branch to checkout or create (optional) |
| `from-branch` | Base branch when creating new branch (optional) |

### Options

| Option | Description |
|--------|-------------|
| `--last` | Repeat the previous `cast new` command |
| `--preset <name>` | Use a saved preset configuration |
| `--save-as <name>` | Save this configuration as a named preset |
| `--mount`, `-v` | Mount host path: `host:container[:ro]` |
| `--copy`, `-c` | Copy host path once: `host:container` |
| `--network`, `-n` | Network isolation mode: `limited` (default), `host-only`, `none` |
| `--with-ssh` | Enable SSH agent forwarding (opt-in, agent-only) |
| `--with-opencode` | Enable OpenCode setup (requires host auth file) |
| `--with-zai` | Enable ZAI Claude alias (requires `ZHIPU_API_KEY`) |
| `--no-isolate-credentials`, `--no-isolate` | Disable credential isolation (pass API keys directly) |
| `--skip-key-check` | Skip API key validation |
| `--wd <path>` | Working directory within repo (relative path) |
| `--sparse` | Enable sparse checkout (requires `--wd`) |
| `--pip-requirements`, `-r` | Install Python packages from requirements.txt (`auto` to detect) |
| `--allow-pr`, `--with-pr` | Allow PR operations (create/comment/review); blocked by default |

### Examples

```bash
# Clone and checkout main (creates auto-named branch)
cast new owner/repo

# Use current repo/branch
cast new .

# Checkout existing branch
cast new owner/repo feature-branch

# Create new branch from main
cast new owner/repo my-feature main

# With volume mounts
cast new owner/repo feature --mount /data:/data
cast new owner/repo feature -v /models:/models:ro

# With file copies (copied once at creation)
cast new owner/repo feature --copy ~/configs:/configs
cast new owner/repo feature -c /path/to/data:/data

# With network restrictions
cast new owner/repo feature --network=limited    # whitelist only
cast new owner/repo feature --network=host-only  # local network only
cast new owner/repo feature --network=none       # no network

# With SSH agent forwarding
cast new owner/repo feature --with-ssh

# Disable credential isolation (pass API keys directly)
cast new owner/repo feature --no-isolate-credentials

# Work in a subdirectory of a monorepo
cast new owner/monorepo feature --wd packages/backend

# Sparse checkout (only checkout the working directory + root configs)
cast new owner/monorepo feature --wd packages/backend --sparse

# Save configuration as a preset for reuse
cast new owner/repo feature --wd packages/app --save-as myproject

# Use a saved preset
cast new --preset myproject

# Repeat the last cast new command
cast new --last
cast repeat  # shorthand alias

# Enable optional tools
cast new owner/repo feature --with-opencode  # requires ~/.local/share/opencode/auth.json
cast new owner/repo feature --with-zai       # requires ZHIPU_API_KEY
```

Note: SSH forwarding is disabled by default and agent-only (no key copy); use `--with-ssh` or set `SANDBOX_SYNC_SSH=1` to enable. API keys are passed via environment variables (see `.env.example`).

> **Monorepo support:** Use `--wd` to set the initial working directory inside the container. Combine with `--sparse` for large monorepos to checkout only the specified directory plus essential root files (`*.json`, `*.yaml`, `*.toml`, `*.md`, `*.lock`, `.github/`). Run `git sparse-checkout add <path>` inside the container to include additional paths.

### Behavior

1. Clones repository as bare repo (if not already cloned)
2. Creates git worktree with specified branch
3. Sets up Claude Code configuration
4. Starts Docker container
5. Attaches to tmux session inside container

If `repo` is `.` and no branch is provided, the sandbox branch is created from your current branch.

Running `cast new` with no arguments launches the guided wizard (gum if available, read-based fallback).

---

## cast repeat

Alias for `cast new --last`. Repeats the previous `cast new` command.

### Synopsis

```
cast repeat
```

### Examples

```bash
# Create a sandbox
cast new owner/repo feature --wd packages/app

# Later, repeat the same setup
cast repeat
```

---

## cast preset

Manage saved presets for `cast new`.

### Synopsis

```
cast preset list
cast preset show <name>
cast preset delete <name>
```

### Commands

| Command | Description |
|---------|-------------|
| `list` | List all saved presets |
| `show <name>` | Show preset details (JSON) |
| `delete <name>` | Delete a preset |

### Examples

```bash
# Save a preset when creating a sandbox
cast new owner/repo feature --wd packages/app --save-as myproject

# List all presets
cast preset list

# Show preset details
cast preset show myproject

# Use a preset
cast new --preset myproject

# Delete a preset
cast preset delete myproject
```

### Notes

Presets are stored in `~/.sandboxes/presets/` as JSON files. The last `cast new` command is stored in `~/.sandboxes/.last-cast-new.json` for the `--last` flag.

---

## cast list

List all sandboxes.

### Synopsis

```
cast list [--json]
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format |

### Examples

```bash
# Human-readable output
cast list

# JSON output
cast list --json
```

### Output

Human-readable:
```
Sandboxes:
───────────────────────────────────────
  repo-feature-branch     running
  repo-sandbox-20240115   stopped
```

JSON:
```json
[
  {"name": "repo-feature-branch", "status": "running", ...},
  {"name": "repo-sandbox-20240115", "status": "stopped", ...}
]
```

---

## cast attach

Attach to a running sandbox.

### Synopsis

```
cast attach [name]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (optional if fzf available) |

### Behavior

- If sandbox is stopped, starts it first
- Syncs credentials from host to container when `SANDBOX_SYNC_ON_ATTACH=1` (default: `0`)
- Attaches to tmux session

### Examples

```bash
# Attach by name
cast attach repo-feature-branch

# Use fzf selector (if no name provided)
cast attach
```

---

## cast start

Start a stopped sandbox.

### Synopsis

```
cast start <name>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (required) |

### Behavior

1. Checks Docker image freshness
2. Sets up Claude config if missing
3. Copies credentials from host
4. Starts container with docker-compose

### Examples

```bash
cast start repo-feature-branch
```

---

## cast stop

Stop a running sandbox.

### Synopsis

```
cast stop <name>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (required) |

### Behavior

- Kills tmux session
- Stops container (preserves worktree)
- Home directory contents are lost (tmpfs), except `~/.claude` which is persisted per sandbox

### Examples

```bash
cast stop repo-feature-branch
```

---

## cast destroy

Remove a sandbox completely.

### Synopsis

```
cast destroy <name> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (required) |

### Options

| Option | Description |
|--------|-------------|
| `-f`, `--force` | Skip confirmation prompt |
| `-y`, `--yes` | Assume yes to confirmation |
| `--keep-worktree` | Remove container but keep worktree |

### Behavior

1. Prompts for confirmation (unless `-f` or `-y`)
2. Kills tmux session
3. Removes Docker container and volumes
4. Removes Claude config directory
5. Removes git worktree

### Examples

```bash
# Interactive confirmation
cast destroy repo-feature-branch

# Skip confirmation
cast destroy repo-feature-branch --yes
cast destroy repo-feature-branch -f

# Keep the worktree (just remove container)
cast destroy repo-feature-branch --keep-worktree
```

---

## cast status

Show sandbox status.

### Synopsis

```
cast status [name] [--json]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (optional, shows all if omitted) |

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format |

### Examples

```bash
# All sandboxes
cast status

# Specific sandbox
cast status repo-feature-branch

# JSON output
cast status --json
cast status repo-feature-branch --json
```

### Output

```
Sandbox: repo-feature-branch
  Worktree      /home/user/.sandboxes/worktrees/repo-feature-branch
  Claude config /home/user/.sandboxes/claude-config/repo-feature-branch
  Container     sb-repo-feature-branch-dev-1 (running)
  Tmux          attached
  Repo          https://github.com/owner/repo
  Branch        feature-branch
  From branch   main
```

---

## cast build

Build or rebuild the Docker image.

### Synopsis

```
cast build
```

### Behavior

- Runs `docker compose build` with current user's UID/GID
- Image is tagged as `foundry-sandbox:latest`

### Examples

```bash
cast build
```

---

## cast config

Show configuration and environment checks.

### Synopsis

```
cast config [--json]
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format |

### Examples

```bash
cast config

cast config --json
```

### Output

```
Sandbox config
  SANDBOX_HOME       /home/user/.sandboxes
  REPOS_DIR          /home/user/.sandboxes/repos
  WORKTREES_DIR      /home/user/.sandboxes/worktrees
  CLAUDE_CONFIGS_DIR /home/user/.sandboxes/claude-config
  SCRIPT_DIR         /path/to/foundry-sandbox
  DOCKER_IMAGE       foundry-sandbox:latest
  ...

Checks
  git           ok
  docker        ok
  docker daemon ok
```

---

## cast prune

Remove orphaned configuration directories.

### Synopsis

```
cast prune [-f] [--json]
```

### Options

| Option | Description |
|--------|-------------|
| `-f`, `--force` | Remove without prompting |
| `--json` | Output in JSON format |

### Behavior

Finds Claude config directories that don't have a corresponding worktree (orphaned after manual cleanup) and removes them.

### Examples

```bash
# Interactive
cast prune

# Force remove all orphans
cast prune -f

# JSON output
cast prune --json
```

---

## cast info

Show combined config and status.

### Synopsis

```
cast info [--json]
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output in JSON format |

### Examples

```bash
cast info

cast info --json
```

---

## cast help

Show help message.

### Synopsis

```
cast help
```

### Examples

```bash
cast help
cast --help
cast -h
```

---

## Environment Variables

These environment variables affect `cast` behavior:

| Variable | Description | Default |
|----------|-------------|---------|
| `SANDBOX_HOME` | Base directory for sandbox data | `~/.sandboxes` |
| `SANDBOX_DEBUG` | Enable debug output | `0` |
| `SANDBOX_VERBOSE` | Enable verbose output | `0` |
| `SANDBOX_ASSUME_YES` | Skip confirmations | `0` |
| `SANDBOX_NETWORK_MODE` | Default network mode | `limited` |
| `SANDBOX_ALLOWED_DOMAINS` | Extra domains for limited mode (comma-separated) | - |
| `SANDBOX_SYNC_ON_ATTACH` | Sync runtime credentials on `cast attach` | `0` |
| `SANDBOX_SYNC_SSH` | Enable SSH agent forwarding (opt-in) | `0` |
| `SANDBOX_SSH_MODE` | Deprecated; use `always` when `SANDBOX_SYNC_SSH=1` | `always` |
| `SANDBOX_SSH_AUTH_SOCK` | Override host SSH agent socket path | - |
| `SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS` | Drop non-local OpenCode npm plugins from config | `1` |
| `SANDBOX_OPENCODE_PLUGIN_DIR` | Host directory of OpenCode plugins to sync on first attach | - |
| `SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS` | Prefetch OpenCode npm plugins during sandbox init | `1` |
| `SANDBOX_HOME_TMPFS_SIZE` | Size of `/home/ubuntu` tmpfs (configs, caches) | `2g` |
| `CLAUDE_CODE_TMPDIR` | Claude Code temp directory inside the container | `/workspace/.claude-tmp` |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` | Disable Claude Code auto-updates, telemetry, bug reports | `1` |
| `DISABLE_AUTOUPDATER` | Disable Claude Code auto-updates | `1` |
| `DISABLE_BUG_COMMAND` | Disable Claude Code bug reporting | `1` |
| `DISABLE_ERROR_REPORTING` | Disable Claude Code error reporting | `1` |
| `DISABLE_TELEMETRY` | Disable Claude Code telemetry | `1` |
| `OPENCODE_DISABLE_AUTOUPDATE` | Disable OpenCode auto-updates | `1` |
| `OPENCODE_DISABLE_MODELS_FETCH` | Disable OpenCode model fetching | `1` |
| `OPENCODE_DISABLE_LSP_DOWNLOAD` | Disable OpenCode LSP downloads | `1` |
| `OPENCODE_DISABLE_SHARE` | Disable OpenCode sharing | `1` |
| `ANTHROPIC_API_KEY` | Passed to containers | - |
| `GITHUB_TOKEN` | Optional; GitHub API + private repo access | - |
| `GH_TOKEN` | Optional; fallback to `GITHUB_TOKEN` (gh keychain) | - |
| `CLAUDE_CODE_OAUTH_TOKEN` | Passed to containers | - |
| `OPENAI_API_KEY` | Passed to containers | - |
| `TAVILY_API_KEY` | Passed to containers | - |
| `PERPLEXITY_API_KEY` | Passed to containers | - |
| `GOOGLE_API_KEY` | Passed to containers | - |
| `GOOGLE_CSE_ID` | Passed to containers | - |
| `ZHIPU_API_KEY` | Required for `--with-zai` (ZAI Claude alias) | - |

Gemini CLI uses OAuth credentials stored under `~/.gemini/` (from `gemini auth`). Large Gemini CLI artifacts (e.g. `~/.gemini/antigravity`) are skipped to keep sandboxes lightweight. Sandboxes default to disabling Gemini auto-updates, update nags, telemetry, and usage stats via `~/.gemini/settings.json`, and Codex update checks/analytics via `~/.codex/config.toml`. If your host Codex config does not set them, sandboxes also default to `approval_policy = "on-failure"` and `sandbox_mode = "danger-full-access"` inside the container.

OpenCode plugin notes: set `SANDBOX_OPENCODE_PLUGIN_DIR` to a host directory containing plugin subfolders (use package names; scoped packages are nested like `@scope/name`). On first attach, the folder is synced into the container and plugin entries are rewritten to local paths. OpenCode npm plugins are prefetched by default during sandbox init; set `SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS=0` to disable.

### Debugging

```bash
# Enable debug output
SANDBOX_DEBUG=1 cast list

# Enable verbose output
SANDBOX_VERBOSE=1 cast start mybox
```
