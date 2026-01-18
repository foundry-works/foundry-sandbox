# Foundry Sandbox

Ephemeral worktree-based development environments for AI-assisted coding with Claude Code.

## Setup

### 1. Build the Docker image

```bash
./sandbox.sh build
```

### 2. Add the alias

Add to your `~/.bashrc` or `~/.bashrc.d/sandbox.sh`:

```bash
alias sb='/path/to/foundry-sandbox/sandbox.sh'
```

Optional shortcut aliases for frequently-used repos:

```bash
alias sbf='sb new owner/repo-one'
alias sbc='sb new owner/repo-two'
```

### 3. Enable bash completion (optional)

Source the completion script in your shell config:

```bash
source /path/to/foundry-sandbox/completion.bash
```

## Usage

```bash
# Create a new sandbox for a repo
sb new owner/repo

# Create with a copy of another local repo
sb new owner/repo --copy ~/GitHub/other-repo:/other-repo

# List active sandboxes
sb list

# Attach to a running sandbox
sb attach sandbox-name

# Stop/start/destroy sandboxes
sb stop sandbox-name
sb start sandbox-name
sb destroy sandbox-name
sb destroy sandbox-name --yes

# Status for one or all sandboxes
sb status
sb status sandbox-name
sb status --json
sb list --json

# Config and environment checks
sb config
sb config --json

# Combined info
sb info
sb info --json

# Prune orphaned configs
sb prune
sb prune --json

# Show help
sb help
```

## Debugging

Set these env vars when running `sb` for more output:

```bash
SANDBOX_DEBUG=1 sb list
SANDBOX_VERBOSE=1 sb start sandbox-name
```

## Documentation

For detailed documentation, see the [docs/](docs/) directory:

- [Getting Started](docs/getting-started.md) - Installation and first sandbox
- [Architecture](docs/architecture.md) - Technical design and diagrams
- [Security: Threat Model](docs/security/threat-model.md) - What we protect against
- [Security: Safety Layers](docs/security/safety-layers.md) - Defense in depth
- [Command Reference](docs/usage/commands.md) - All commands explained
- [Workflows](docs/usage/workflows.md) - Common patterns and recipes
- [Contributing](docs/development/contributing.md) - For contributors

## How it works

- Clones repos as bare git repositories to `~/.sandboxes/repos/`
- Creates worktrees for each sandbox in `~/.sandboxes/worktrees/`
- Runs each sandbox in an isolated Docker container
- Includes security guardrails (shell overrides, sudoers allowlist, read-only root)
- Pre-installed AI tools: Claude Code, Gemini CLI, OpenCode
