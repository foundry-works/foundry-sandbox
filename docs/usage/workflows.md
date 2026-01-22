# Common Workflows

This guide covers common patterns for using Foundry Sandbox effectively.

## Feature Development Workflow

### Start New Feature

```bash
# Create sandbox with new branch from main
cast new owner/repo feature-login main

# Inside sandbox, start AI assistant
claude
```

### Work on the Feature

```bash
# Let Claude Code implement the feature
# All changes are isolated to the sandbox's worktree

# Check your work
git diff
git status
```

### Push and Create PR

```bash
# Inside sandbox
git add -A
git commit -m "Add login feature"
git push -u origin feature-login

# Create PR using gh
gh pr create --title "Add login feature" --body "..."
```

### Clean Up

```bash
# Exit sandbox (Ctrl+b, then d to detach tmux)
exit

# Destroy when done
cast destroy repo-feature-login --yes
```

---

## PR Review Workflow

Review a pull request in an isolated environment.

### Checkout the PR

```bash
# Create sandbox from PR branch
cast new owner/repo pr-123-feature
```

### Inside the Sandbox

```bash
# Fetch the PR branch
git fetch origin pull/123/head:pr-123
git checkout pr-123

# Run tests
npm test

# Review with AI assistance
claude
# Ask: "Review this PR for potential issues"
```

### Leave Comments

```bash
# Use gh to comment
gh pr comment 123 --body "Found an issue in auth.js:42..."

# Or review
gh pr review 123 --comment --body "LGTM"
```

### Clean Up

```bash
cast destroy repo-pr-123-feature --yes
```

---

## Multiple Sandboxes for Same Repo

Work on multiple features simultaneously without branch switching.

### Create Multiple Sandboxes

```bash
# Feature 1
cast new owner/repo feature-auth main

# Feature 2 (in another terminal)
cast new owner/repo feature-ui main

# Bug fix
cast new owner/repo fix-login-bug main
```

### List and Switch

```bash
# See all sandboxes
cast list

# Attach to specific one
cast attach repo-feature-auth
```

### Each Sandbox is Independent

- Separate git worktrees
- Separate Claude configs
- Separate containers
- Changes in one don't affect others

---

## Using Custom Mounts

Mount additional directories from your host into the sandbox.

### Read-Only Data

```bash
# Mount models directory read-only
cast new owner/repo feature --mount /path/to/models:/models:ro
```

### Shared Data Directory

```bash
# Mount writable data directory
cast new owner/repo feature --mount /data/datasets:/datasets
```

### Multiple Mounts

```bash
cast new owner/repo feature \
  --mount /data:/data \
  --mount /models:/models:ro \
  --mount ~/.aws:/home/ubuntu/.aws:ro
```

---

## Using File Copies

Copy files into the container once at creation time. Useful for configs that shouldn't change.

### Copy Configuration

```bash
cast new owner/repo feature --copy ~/configs/app.json:/workspace/config.json
```

### Copy Reference Data

```bash
cast new owner/repo feature --copy /path/to/fixtures:/test-data
```

### Mounts vs Copies

| Use Mounts When | Use Copies When |
|-----------------|-----------------|
| Data changes frequently | Data is static |
| Need real-time sync | Don't want host changes to affect sandbox |
| Large datasets (avoid duplication) | Small files (configs, fixtures) |
| Need write access back to host | Sandbox-specific modifications OK |

---

## Installing SSH-Based Plugins

Use SSH agent forwarding when you need Git-over-SSH (e.g., private repos).

```bash
# Enable SSH agent forwarding
cast new owner/repo feature --with-ssh
```

---

## Using Different AI Tools

The sandbox comes with multiple AI coding assistants pre-installed.

### Claude Code

```bash
# Default usage
claude

# Skip permissions (for trusted repos)
cdsp    # alias for: claude --dangerously-skip-permissions

# Resume previous session
cdspr   # alias for: claude --dangerously-skip-permissions --resume
```

### Gemini CLI

```bash
# Requires: run `gemini auth` on host first
gemini
```

### Codex CLI

```bash
# Requires OPENAI_API_KEY
codex
```

### OpenCode

```bash
# Requires OPENAI_API_KEY
opencode
```

### Cursor Agent

```bash
# Requires CURSOR_API_KEY
cursor
```

### Setting API Keys

On your host (before creating sandbox):

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."

# For Gemini CLI, run: gemini auth

# Now create sandbox
cast new owner/repo feature
```

API keys are passed via environment variables. Set them in your shell profile or `.env` file:

```bash
export CLAUDE_CODE_OAUTH_TOKEN="..."   # Get via: claude setup-token
export CURSOR_API_KEY="key-..."
export TAVILY_API_KEY="..."
# Note: Gemini uses OAuth via ~/.gemini/ (run `gemini auth` on host)
```

See `.env.example` for all supported keys.

---

## Quick Iterations Workflow

When you need fast feedback loops with AI assistance.

### Create, Work, Destroy Pattern

```bash
# Quick experiment
cast new owner/repo experiment-1 main
# ... work ...
cast destroy repo-experiment-1 --yes

# Another attempt
cast new owner/repo experiment-2 main
# ... work ...
```

### Preserve Work You Like

Before destroying, push changes:

```bash
# Inside sandbox
git push origin experiment-branch

# Then destroy
cast destroy repo-experiment-branch --yes
```

---

## Debugging a Production Issue

Safely investigate issues without touching production code.

### Create Isolated Environment

```bash
# Clone the exact production version
cast new owner/repo debug-issue-123 production
```

### Add Debug Tooling

```bash
# Inside sandbox
sudo apt-get install strace
pip install debugpy
```

### Investigate

```bash
# Run with AI assistance
claude
# Ask: "Help me debug why users can't login. Here's the error log..."
```

### Clean Up (Important!)

```bash
# Don't forget to destroy - this had production config
cast destroy repo-debug-issue-123 --yes
```

---

## Working with Private Repositories

### GitHub Authentication

Ensure `GITHUB_TOKEN` is set on your host:

```bash
export GITHUB_TOKEN="ghp_..."
cast new private-org/private-repo feature
```

### SSH Access

```bash
# Forward your local SSH agent
cast new owner/repo feature --with-ssh
```

### SSH Keys (Alternative)

```bash
# Mount SSH keys read-only
cast new owner/repo feature --mount ~/.ssh:/home/ubuntu/.ssh:ro
```

---

## Network Isolation Workflow

Control network access for sensitive work or offline development.

### Restricted Network for Sensitive Code

```bash
# Only allow essential services (github, npm, pypi, AI APIs)
cast new owner/repo sensitive-feature --network=limited

# Inside sandbox, test that restrictions work
curl https://github.com  # works
curl https://random-site.com  # blocked
```

### Completely Offline Development

```bash
# No network at all
cast new owner/repo offline-work --network=none

# Inside sandbox, everything is blocked
curl https://anything.com  # fails
```

### Runtime Network Switching

```bash
# Start with full network
cast new owner/repo feature --network=full

# Inside container, restrict later
sudo network-mode limited

# Check current status
sudo network-mode status

# Add a custom domain if needed
sudo network-mode allow custom-api.example.com

# Switch back to full when needed
sudo network-mode full
```

### Host-Only for Local Services

```bash
# Allow only local network (for local databases, APIs)
cast new owner/repo local-dev --network=host-only

# Inside sandbox
curl http://localhost:8080  # works (if service running on host)
curl https://external.com   # blocked
```

### Custom Domain Whitelist

```bash
# Add extra domains to the limited mode whitelist
export SANDBOX_ALLOWED_DOMAINS="internal-api.company.com,cache.myorg.net"
cast new owner/repo feature --network=limited

# These domains will be allowed in addition to defaults
```

---

## Advanced Plugin Configuration

### OpenCode Foundry

The [opencode-foundry](https://github.com/foundry-works/opencode-foundry) skills are automatically synced on sandbox start. By default, the repo is cloned to `~/.sandboxes/vendor/opencode-foundry`.

```bash
# Use a local checkout instead
export SANDBOX_OPENCODE_FOUNDRY_PATH=~/dev/opencode-foundry

# Or override the GitHub source
export SANDBOX_OPENCODE_FOUNDRY_REPO=https://github.com/your-org/opencode-foundry.git
export SANDBOX_OPENCODE_FOUNDRY_BRANCH=develop
```

Skills are synced into `~/.config/opencode/skills` and the OpenCode config is merged from `install/assets/opencode-global.json` without overwriting existing settings.

### OpenCode Plugins

For npm-based OpenCode plugins:

```bash
# Prefetch npm plugins on sandbox creation (downloads to ~/.cache/opencode)
export SANDBOX_OPENCODE_PREFETCH_NPM_PLUGINS=1

# Or disable npm plugins entirely (use only local plugins)
export SANDBOX_OPENCODE_DISABLE_NPM_PLUGINS=1

# Use a local plugin directory
export SANDBOX_OPENCODE_PLUGIN_DIR=~/dev/opencode-plugins
```

---

## Tips and Best Practices

### Name Your Branches Descriptively

```bash
# Good - describes the work
cast new owner/repo add-oauth-google main
cast new owner/repo fix-memory-leak main

# Less helpful
cast new owner/repo test1 main
```

### Use cast list Often

```bash
# See what you have running
cast list
```

### Clean Up Finished Work

```bash
# Don't let sandboxes accumulate
cast destroy old-sandbox --yes

# Or prune orphaned configs
cast prune -f
```

### Debugging Issues

```bash
SANDBOX_DEBUG=1 cast list          # Debug logging
SANDBOX_VERBOSE=1 cast start name  # Verbose output
```

### Network Whitelist

Add custom domains to the limited network whitelist:

```bash
export SANDBOX_ALLOWED_DOMAINS="api.example.com,internal.corp.com"
cast new owner/repo --network=limited
```
