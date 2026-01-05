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
alias sbf='sb new tylerburleigh/foundry-mcp'
alias sbc='sb new tylerburleigh/claude-foundry'
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

# Show help
sb help
```

## How it works

- Clones repos as bare git repositories to `~/.sandboxes/repos/`
- Creates worktrees for each sandbox in `~/.sandboxes/worktrees/`
- Runs each sandbox in an isolated Docker container
- Automatically launches Claude Code inside the container
