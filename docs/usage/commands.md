# Command Reference

Complete reference for all `cast` commands.

## cast new

Create a new sandbox from a repository.

### Synopsis

```
cast new <repo> [branch] [from-branch] [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `repo` | GitHub repo (owner/repo) or full URL |
| `branch` | Branch to checkout or create (optional) |
| `from-branch` | Base branch when creating new branch (optional) |

### Options

| Option | Description |
|--------|-------------|
| `--mount`, `-v` | Mount host path: `host:container[:ro]` |
| `--copy`, `-c` | Copy host path once: `host:container` |
| `--network`, `-n` | Network isolation mode: `full`, `limited`, `host-only`, `none` |

### Examples

```bash
# Clone and checkout main (creates auto-named branch)
cast new owner/repo

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
```

### Behavior

1. Clones repository as bare repo (if not already cloned)
2. Creates git worktree with specified branch
3. Sets up Claude Code configuration
4. Starts Docker container
5. Attaches to tmux session inside container

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
- Syncs credentials from host to container
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
- Home directory contents are lost (tmpfs)

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
- Image is tagged as `ai-dev-sandbox:latest`

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
  DOCKER_IMAGE       ai-dev-sandbox:latest
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
| `SANDBOX_NETWORK_MODE` | Default network mode | `full` |
| `SANDBOX_ALLOWED_DOMAINS` | Extra domains for limited mode (comma-separated) | - |
| `ANTHROPIC_API_KEY` | Passed to containers | - |
| `GITHUB_TOKEN` | Passed to containers | - |
| `GEMINI_API_KEY` | Passed to containers | - |
| `OPENAI_API_KEY` | Passed to containers | - |

### Debugging

```bash
# Enable debug output
SANDBOX_DEBUG=1 cast list

# Enable verbose output
SANDBOX_VERBOSE=1 cast start mybox
```
