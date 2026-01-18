# Getting Started

This guide walks you through installing Foundry Sandbox and creating your first isolated development environment.

## Prerequisites

- **Docker** - Container runtime ([install guide](https://docs.docker.com/get-docker/))
- **Git** - Version control
- **Bash** - Shell (Linux/macOS default, WSL2 on Windows)
- **tmux** - Terminal multiplexer (usually pre-installed)

Verify your setup:

```bash
docker --version   # Docker version 20.10+
git --version      # git version 2.x+
tmux -V            # tmux 3.x+
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/foundry-sandbox.git
cd foundry-sandbox
```

### 2. Build the Docker Image

```bash
./sandbox.sh build
```

This builds an Ubuntu 24.04-based image with:
- Node.js 22.x, Go 1.23, Python 3
- Claude Code, Gemini CLI, OpenCode pre-installed
- GitHub CLI (`gh`)
- Development tools (ripgrep, fd, fzf, vim, jq)
- Safety guardrails (shell overrides, sudoers allowlist)

### 3. Add the Alias

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
alias sb='/path/to/foundry-sandbox/sandbox.sh'
```

Then reload your shell:

```bash
source ~/.bashrc
```

### 4. Enable Bash Completion (Optional)

```bash
# Add to ~/.bashrc
source /path/to/foundry-sandbox/completion.bash
```

This enables tab completion for commands and sandbox names.

## Creating Your First Sandbox

### From a GitHub Repository

```bash
sb new owner/repo
```

This will:
1. Clone the repository as a bare repo (if not already cloned)
2. Create a git worktree with a timestamped branch name
3. Start a Docker container with the worktree mounted
4. Attach you to a tmux session inside the container

### From an Existing Branch

```bash
sb new owner/repo feature-branch
```

### Create a New Branch

```bash
sb new owner/repo my-new-feature main
```

Creates `my-new-feature` branch starting from `main`.

### With Network Restrictions (Optional)

```bash
# Limited network (only github, npm, pypi, AI APIs)
sb new owner/repo feature --network=limited

# No network at all
sb new owner/repo offline-work --network=none
```

See [Security > Safety Layers](security/safety-layers.md) for details on network modes.

## Working in Your Sandbox

Once attached, you're in a bash shell inside the container at `/workspace` (your code).

### Run an AI Assistant

```bash
# Claude Code
claude

# Or with skip-permissions mode (for trusted operations)
cdsp    # alias for: claude --dangerously-skip-permissions

# Gemini CLI
gemini

# OpenCode
opencode
```

### Navigate and Edit

```bash
# Your code is at /workspace
cd /workspace
ls -la

# Standard tools available
vim file.py
git status
npm install
```

### Exit the Sandbox

```bash
# Detach from tmux (keeps sandbox running)
# Press: Ctrl+b, then d

# Or exit the shell (also detaches)
exit
```

## Managing Sandboxes

### List All Sandboxes

```bash
sb list
```

### Attach to a Running Sandbox

```bash
sb attach sandbox-name

# Or use fzf selector (if no name provided)
sb attach
```

### Stop a Sandbox

```bash
sb stop sandbox-name
```

Stops the container but preserves the worktree. Restart with `sb start`.

### Destroy a Sandbox

```bash
sb destroy sandbox-name
```

Removes the container, worktree, and associated configs. You'll be prompted to confirm.

```bash
# Skip confirmation
sb destroy sandbox-name --yes
```

## Environment Variables

Set these before running `sb` for API access inside containers:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export GITHUB_TOKEN="ghp_..."
export GEMINI_API_KEY="..."
export OPENAI_API_KEY="sk-..."
```

These are passed into containers automatically.

## Next Steps

- [Architecture](architecture.md) - Understand how sandboxes work
- [Security](security/threat-model.md) - Learn about the safety guarantees
- [Commands](usage/commands.md) - Full command reference
- [Workflows](usage/workflows.md) - Common patterns and recipes
