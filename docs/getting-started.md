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

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

This installs to `~/.foundry-sandbox` and:
- Adds the `cast` alias to your shell
- Enables tab completion
- Builds the Docker image (Ubuntu 24.04-based with Node.js, Go, Python, Claude Code, Gemini CLI, Codex CLI, OpenCode, Cursor Agent, and safety guardrails)

After installation, reload your shell:

```bash
source ~/.bashrc  # or ~/.zshrc
```

### Manual Install

If you prefer manual installation:

```bash
# Clone
git clone https://github.com/foundry-works/foundry-sandbox.git ~/.foundry-sandbox

# Add to ~/.bashrc or ~/.zshrc
echo "alias cast='~/.foundry-sandbox/sandbox.sh'" >> ~/.bashrc
echo "source ~/.foundry-sandbox/completion.bash" >> ~/.bashrc

# Reload and build
source ~/.bashrc
cast build
```

## Creating Your First Sandbox

### From a GitHub Repository

```bash
cast new owner/repo
```

This will:
1. Clone the repository as a bare repo (if not already cloned)
2. Create a git worktree with a timestamped branch name
3. Start a Docker container with the worktree mounted
4. Attach you to a tmux session inside the container

### From an Existing Branch

```bash
cast new owner/repo feature-branch
```

### Create a New Branch

```bash
cast new owner/repo my-new-feature main
```

Creates `my-new-feature` branch starting from `main`.

### With Network Restrictions (Optional)

```bash
# Limited network (only github, npm, pypi, AI APIs)
cast new owner/repo feature --network=limited

# No network at all
cast new owner/repo offline-work --network=none
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

# Codex CLI
codex

# OpenCode
opencode

# Cursor Agent
cursor
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
cast list
```

### Attach to a Running Sandbox

```bash
cast attach sandbox-name

# Or use fzf selector (if no name provided)
cast attach
```

### Stop a Sandbox

```bash
cast stop sandbox-name
```

Stops the container but preserves the worktree. Restart with `cast start`.

### Destroy a Sandbox

```bash
cast destroy sandbox-name
```

Removes the container, worktree, and associated configs. You'll be prompted to confirm.

```bash
# Skip confirmation
cast destroy sandbox-name --yes
```

## Environment Variables

Set these before running `cast` for API access inside containers:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export GITHUB_TOKEN="ghp_..."
export OPENAI_API_KEY="sk-..."
# For Gemini CLI, run: gemini auth (OAuth creds in ~/.gemini/ are copied to container)
```

These are passed into containers automatically.

## Next Steps

- [Architecture](architecture.md) - Understand how sandboxes work
- [Security](security/threat-model.md) - Learn about the safety guarantees
- [Commands](usage/commands.md) - Full command reference
- [Workflows](usage/workflows.md) - Common patterns and recipes
