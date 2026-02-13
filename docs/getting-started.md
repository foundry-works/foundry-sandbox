# Getting Started

This guide walks you through installing Foundry Sandbox and creating your first isolated development environment.

## Prerequisites

- **Docker** - Container runtime ([install guide](https://docs.docker.com/get-docker/))
- **Git** - Version control
- **Bash** - Shell (Linux/macOS default, WSL2 on Windows)
- **tmux** - Terminal multiplexer (usually pre-installed)
- **Python** - 3.10+

Verify your setup:

```bash
docker --version    # Docker version 20.10+
git --version       # git version 2.x+
tmux -V             # tmux 3.x+
python3 --version   # Python 3.10+
```

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

This installs to `~/.foundry-sandbox` and:
- Adds the `cast` alias to your shell
- Enables tab completion
- Builds the Docker image (Ubuntu 24.04-based with Node.js, Go, Python, Claude Code, Gemini CLI, Codex CLI, OpenCode, and safety guardrails)

After installation, reload your shell:

```bash
source ~/.bashrc  # or ~/.zshrc
```

The `cast` CLI is installed automatically by `install.sh` via `pip install -e .` (using the entry point defined in `pyproject.toml`).

### PyPI package

`foundry-sandbox` is published on PyPI and provides the `cast` Python entry point:

```bash
pipx install foundry-sandbox
# or
pip install foundry-sandbox
```

Important: full sandbox operation still requires repository runtime assets (`docker-compose.yml`, `docker-compose.credential-isolation.yml`, `unified-proxy/`, `stubs/`). Use the installer above (or clone the repo and run `pip install -e .`) for a complete setup.

## Creating Your First Sandbox

Run `cast new` with no arguments to launch the guided setup (gum if available, read-based fallback).

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

For advanced options like `--network`, `--mount`, and `--sparse`, see [Commands](usage/commands.md).

## Working in Your Sandbox

Once attached, you're in a bash shell inside the container at `/workspace` (your code).

### Run an AI Assistant

```bash
claude      # Claude Code
gemini      # Gemini CLI
codex       # Codex CLI
opencode    # OpenCode
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

## Environment Variables

```bash
# GitHub - use gh CLI (recommended)
gh auth login
# Token is pulled from keychain automatically (GH_TOKEN -> GITHUB_TOKEN)

# Or export token directly (required for private repos or write ops)
export GITHUB_TOKEN="ghp_..."

# Claude Code - get token via: claude setup-token
export CLAUDE_CODE_OAUTH_TOKEN="..."

# For Gemini CLI, run: gemini auth
# For Codex CLI, run: codex login
```

These are passed into containers automatically.

Public repositories can be used without a GitHub token, but requests may be rate limited. Private repos and push operations require a token.

### CI / Non-Interactive Mode

Set `SANDBOX_NONINTERACTIVE=1` to suppress all interactive prompts. When enabled, confirmations default to "yes" and selection prompts use the first option. This is useful for CI pipelines and scripted workflows.

```bash
SANDBOX_NONINTERACTIVE=1 cast destroy sandbox-name
```

## Next Steps

- [Architecture](architecture.md) - Understand how sandboxes work
- [Security Overview](security/index.md) - Security architecture quick reference
- [Sandbox Threats](security/sandbox-threats.md) - Learn about the safety guarantees
- [Commands](usage/commands.md) - Full command reference
- [Workflows](usage/workflows.md) - Common patterns and recipes
