# Command Reference

Complete reference for all `cast` commands.

> The `cast` CLI is installed via `pip install -e .` and can also be invoked as `python3 -m foundry_sandbox.cli`.

## Contents

**Lifecycle:** [new](#cast-new) | [attach](#cast-attach) | [start](#cast-start) | [stop](#cast-stop) | [destroy](#cast-destroy) | [destroy-all](#cast-destroy-all)

**Presets:** [preset](#cast-preset)

**Status & Info:** [list](#cast-list) | [status](#cast-status) | [config](#cast-config) | [diagnose](#cast-diagnose)

**Maintenance:** [refresh-creds](#cast-refresh-creds) | [watchdog](#cast-watchdog) | [git-mode](#cast-git-mode) | [help](#cast-help)

**Reference:** [Environment Variables](#environment-variables)

---

## Lifecycle Commands

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
| `--agent <type>` | Agent type: claude, codex, copilot, gemini, kiro, opencode, shell (default: claude) |
| `--copy`, `-c` | Copy host path once: `host:container` (multiple allowed) |
| `--name <name>` | Override auto-generated sandbox name |
| `--pip-requirements`, `-r` | Install Python packages from requirements.txt (`auto` to detect) |
| `--allow-pr`, `--with-pr` | Allow PR operations (create/comment/review); blocked by default |
| `--with-opencode` | Enable OpenCode setup (requires host auth file) |
| `--with-zai` | Enable ZAI Claude alias (requires `ZHIPU_API_KEY`) |
| `--skip-key-check` | Skip API key validation |
| `--wd <path>` | Working directory within repo (relative path) |
| `--template <tag>` | Template tag for sandbox creation (default: `foundry-git-wrapper:latest`; use `none` to disable) |

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

# With a specific agent
cast new owner/repo feature --agent codex
cast new owner/repo feature --agent gemini
cast new owner/repo feature --agent shell

# With file copies (copied once at creation)
cast new owner/repo feature --copy ~/configs:/configs
cast new owner/repo feature -c /path/to/data:/data

# With Python dependencies
cast new owner/repo feature -r requirements.txt
cast new owner/repo feature -r auto

# Work in a subdirectory of a monorepo
cast new owner/monorepo feature --wd packages/backend

# Save configuration as a preset for reuse
cast new owner/repo feature --wd packages/app --save-as myproject

# Use a saved preset
cast new --preset myproject

# Repeat the last cast new command
cast new --last

# Enable optional tools
cast new owner/repo feature --with-opencode  # requires ~/.local/share/opencode/auth.json
cast new owner/repo feature --with-zai       # requires ZHIPU_API_KEY

# Override auto-generated name
cast new owner/repo feature --name my-sandbox
```

API keys are stored on the host via `sbx secret set -g` and injected at the network level (see `.env.example`).

> **Monorepo support:** Use `--wd` to set the initial working directory inside the sandbox.

### Behavior

1. Validates sbx CLI is available
2. Clones repository (if not already cloned)
3. Creates git worktree with specified branch
4. Creates sbx microVM sandbox (via `sbx create`)
5. Starts git safety server (if not already running)
6. Generates HMAC secret and registers sandbox with git safety
7. Injects git wrapper into sandbox
8. Copies files and installs pip requirements (if specified)
9. Writes sandbox metadata

If `repo` is `.` and no branch is provided, the sandbox branch is created from your current branch.

Running `cast new` with no arguments launches the guided wizard (gum if available, read-based fallback).

---

## cast attach

Attach to a running sandbox.

### Synopsis

```
cast attach [name]
cast attach --last
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (optional if fzf available) |

### Options

| Option | Description |
|--------|-------------|
| `--last` | Reattach to the last attached sandbox |

### Behavior

- If sandbox is stopped, starts it first (via `sbx run`)
- Verifies git safety server is running and re-injects wrapper if missing
- Attaches via `sbx exec` with streaming I/O
- Auto-detects sandbox from current working directory if inside a worktree

### Examples

```bash
# Attach by name
cast attach repo-feature-branch

# Use fzf selector (if no name provided)
cast attach

# Attach to the last sandbox
cast attach --last
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

1. Verifies sbx sandbox exists
2. Starts sandbox via `sbx run`
3. Verifies git safety server is running
4. Re-injects git wrapper if missing
5. Installs pip requirements (if configured in metadata)

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

- Stops sandbox via `sbx stop`
- Worktree and host-side state are preserved

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
| `--keep-worktree` | Remove sandbox but keep worktree |

### Behavior

1. Prompts for confirmation (unless `-f` or `-y`)
2. Removes sandbox via `sbx rm` (best-effort)
3. Unregisters sandbox from git safety server
4. Removes Claude config directory
5. Removes git worktree
6. Cleans up sandbox branch (if not used by other worktrees)

### Examples

```bash
# Interactive confirmation
cast destroy repo-feature-branch

# Skip confirmation
cast destroy repo-feature-branch --yes
cast destroy repo-feature-branch -f

# Keep the worktree (just remove sandbox)
cast destroy repo-feature-branch --keep-worktree
```

---

## cast destroy-all

Destroy all sandboxes with double confirmation.

### Synopsis

```
cast destroy-all [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--keep-worktree` | Remove sandboxes but keep worktrees |

### Behavior

1. Lists all sandboxes that will be destroyed
2. Requires double confirmation (type "yes" twice)
3. Destroys each sandbox sequentially using `destroy_impl()`

### Examples

```bash
# Destroy everything
cast destroy-all

# Remove sandboxes only, keep worktrees
cast destroy-all --keep-worktree
```

---

## Presets

## cast preset

Manage saved presets for `cast new`.

### Synopsis

```
cast preset list
cast preset show <name>
cast preset save <name> [--sandbox <sandbox-name>]
cast preset delete <name>
```

### Commands

| Command | Description |
|---------|-------------|
| `list` | List all saved presets |
| `show <name>` | Show preset details (JSON) |
| `save <name>` | Save a preset with a filesystem snapshot from a running sandbox |
| `delete <name>` | Delete a preset (cleans up managed templates if last reference) |

### cast preset save

Creates a preset from a running sandbox. The sandbox's runtime state is captured as an sbx template snapshot, so recreating the sandbox via `cast new --preset <name>` restores both the CLI flags and the filesystem state.

If `--sandbox` is omitted, the sandbox is auto-detected from the current working directory (must be inside a worktree).

The operation is all-or-nothing: if the template snapshot fails, no preset is written.

### cast new --save-as vs. cast preset save

| Feature | `cast new --save-as` | `cast preset save` |
|---------|---------------------|-------------------|
| Saves CLI flags | Yes | Yes |
| Snapshots runtime state | No | Yes |
| Creates sbx template | No | Yes |
| Auto-cleanup on delete | No | Yes (if last reference) |

Use `--save-as` for quick CLI-flag presets. Use `preset save` when you want to preserve installed packages, config changes, or other runtime modifications.

### Examples

```bash
# Save a preset when creating a sandbox (CLI flags only)
cast new owner/repo feature --wd packages/app --save-as myproject

# Save a preset with runtime snapshot from a running sandbox
cast preset save mysetup --sandbox my-sandbox

# Save from inside a worktree (auto-detects sandbox)
cd ~/worktrees/my-sandbox
cast preset save mysetup

# List all presets
cast preset list

# Show preset details
cast preset show myproject

# Use a preset (restores CLI flags + template if managed)
cast new --preset myproject

# Delete a preset
cast preset delete myproject
```

### Notes

Presets are stored in `~/.sandboxes/presets/` as JSON files. The last `cast new` command is stored in `~/.sandboxes/.last-cast-new.json` for the `--last` flag.

Managed templates (created by `cast preset save`) are tagged `preset-<name>:latest`. When a preset with a managed template is deleted, the template is removed only if no other preset references it. Non-managed templates are never auto-deleted.

---

## Status & Info

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

JSON output includes foundry-specific metadata (repo, branch, git safety status).

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
  SANDBOX_CONFIGS_DIR /home/user/.sandboxes/sandboxes
  ...

Checks
  git           ok
  sbx           ok
```

---

## cast diagnose

Collect diagnostic information for support and troubleshooting.

### Synopsis

```
cast diagnose [--json]
```

### Options

| Option | Description |
|--------|-------------|
| `--json` | Output structured JSON instead of human-readable text |

### Output Sections

| Section | What it collects |
|---------|-----------------|
| Versions | Python, sbx, and git versions |
| sbx Diagnostics | sbx diagnostic output (secrets redacted) |
| Git Safety Server | Health and readiness checks with per-check breakdown |
| Decision Log | Last 10 entries from the JSONL decision log |
| Wrapper Tamper Events | Recent wrapper integrity violations |
| Kernel Isolation | Verifies sandbox kernels differ from host kernel |

All output is automatically redacted: HMAC secrets, API keys (`sk-...`), and GitHub tokens (`ghp_...`) are masked. Each section degrades gracefully — a failing subsystem does not prevent other sections from being reported.

### Examples

```bash
# Human-readable diagnostics
cast diagnose

# JSON output for scripting or bug reports
cast diagnose --json
```

---

## Maintenance

## cast watchdog

Run the wrapper integrity watchdog as a long-lived foreground process. Periodically checks that the git wrapper inside each sandbox has not been tampered with.

### Synopsis

```
cast watchdog [--interval SECONDS]
```

### Options

| Option | Description |
|--------|-------------|
| `--interval` | Poll interval in seconds (default: 10) |

### Behavior

- Verifies sbx backend is available before starting
- Runs integrity checks at the configured interval
- Detects and logs wrapper tamper events to the decision log
- Handles SIGINT and SIGTERM for clean shutdown

### Examples

```bash
# Run with default 10-second interval
cast watchdog

# Custom interval
cast watchdog --interval 30
```

---

## cast refresh-creds

Push API keys from host environment to sbx-managed secrets.

### Synopsis

```
cast refresh-creds [name]
cast refresh-creds --last
cast refresh-creds --all
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (optional, auto-detects from current directory) |

### Options

| Option | Description |
|--------|-------------|
| `--last`, `-l` | Target the last attached sandbox |
| `--all` | Refresh all running sandboxes |

### Behavior

- Reads API keys from host environment (ANTHROPIC_API_KEY, GITHUB_TOKEN, OPENAI_API_KEY)
- Pushes to sbx via `sbx secret set -g`
- No separate direct/isolation mode distinction

### Examples

```bash
# Refresh credentials for a specific sandbox
cast refresh-creds repo-feature-branch

# Refresh last attached sandbox
cast refresh-creds --last

# Refresh all running sandboxes
cast refresh-creds --all

# Auto-detect from current directory
cast refresh-creds
```

---

## cast git-mode

Toggle a sandbox's git config between host and sandbox path modes.

### Synopsis

```
cast git-mode [name] --mode <host|sandbox>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `name` | Sandbox name (optional, auto-detects from worktree) |

### Options

| Option | Description |
|--------|-------------|
| `--mode host` | Set `core.worktree` to real host path (for IDE tools) |
| `--mode sandbox` | Set `core.worktree` to `/git-workspace` (for proxy-routed git) |

### Examples

```bash
# Switch to host mode for IDE work
cast git-mode repo-feature-branch --mode host

# Switch back to sandbox mode
cast git-mode repo-feature-branch --mode sandbox

# Auto-detect sandbox from current directory
cast git-mode --mode host
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
| `SANDBOX_VERBOSE` | Enable verbose output (shows sbx commands) | `0` |
| `SANDBOX_ASSUME_YES` | Skip confirmations | `0` |
| `SANDBOX_NONINTERACTIVE` | Suppress all interactive prompts (for CI); implies `SANDBOX_ASSUME_YES` behavior | `0` |
| `ANTHROPIC_API_KEY` | Anthropic API key (pushed to sbx) | - |
| `GITHUB_TOKEN` | GitHub token (pushed to sbx) | - |
| `GH_TOKEN` | Fallback to `GITHUB_TOKEN` (gh keychain) | - |
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude Code OAuth token | - |
| `OPENAI_API_KEY` | OpenAI API key (pushed to sbx) | - |
| `TAVILY_API_KEY` | Tavily API key (search) | - |
| `PERPLEXITY_API_KEY` | Perplexity API key (search) | - |
| `ZHIPU_API_KEY` | Required for `--with-zai` | - |
| `GIT_API_SECRETS_PATH` | HMAC secrets directory | `/run/secrets/sandbox-hmac` |
| `FOUNDRY_DATA_DIR` | Git safety data directory | `/var/lib/foundry-git-safety` |

Gemini CLI uses OAuth credentials stored under `~/.gemini/` (from `gemini auth`). Codex update checks and analytics are disabled by default via `~/.codex/config.toml`.

### Debugging

```bash
# Enable debug output
SANDBOX_DEBUG=1 cast list

# Enable verbose output (shows sbx subprocess commands)
SANDBOX_VERBOSE=1 cast start mybox
```
