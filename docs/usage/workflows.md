# Common Workflows

This guide covers common patterns for using Foundry Sandbox effectively.

## Feature Development Workflow

### Start New Feature

```bash
# Create sandbox with new branch from main
sb new owner/repo feature-login main

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
sb destroy repo-feature-login --yes
```

---

## PR Review Workflow

Review a pull request in an isolated environment.

### Checkout the PR

```bash
# Create sandbox from PR branch
sb new owner/repo pr-123-feature
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
sb destroy repo-pr-123-feature --yes
```

---

## Multiple Sandboxes for Same Repo

Work on multiple features simultaneously without branch switching.

### Create Multiple Sandboxes

```bash
# Feature 1
sb new owner/repo feature-auth main

# Feature 2 (in another terminal)
sb new owner/repo feature-ui main

# Bug fix
sb new owner/repo fix-login-bug main
```

### List and Switch

```bash
# See all sandboxes
sb list

# Attach to specific one
sb attach repo-feature-auth
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
sb new owner/repo feature --mount /path/to/models:/models:ro
```

### Shared Data Directory

```bash
# Mount writable data directory
sb new owner/repo feature --mount /data/datasets:/datasets
```

### Multiple Mounts

```bash
sb new owner/repo feature \
  --mount /data:/data \
  --mount /models:/models:ro \
  --mount ~/.aws:/home/ubuntu/.aws:ro
```

---

## Using File Copies

Copy files into the container once at creation time. Useful for configs that shouldn't change.

### Copy Configuration

```bash
sb new owner/repo feature --copy ~/configs/app.json:/workspace/config.json
```

### Copy Reference Data

```bash
sb new owner/repo feature --copy /path/to/fixtures:/test-data
```

### Mounts vs Copies

| Use Mounts When | Use Copies When |
|-----------------|-----------------|
| Data changes frequently | Data is static |
| Need real-time sync | Don't want host changes to affect sandbox |
| Large datasets (avoid duplication) | Small files (configs, fixtures) |
| Need write access back to host | Sandbox-specific modifications OK |

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
# Requires GEMINI_API_KEY
gemini
```

### OpenCode

```bash
# Requires OPENAI_API_KEY
opencode
```

### Setting API Keys

On your host (before creating sandbox):

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="..."
export OPENAI_API_KEY="sk-..."

# Now create sandbox
sb new owner/repo feature
```

Or create `~/.api_keys` on the host (sourced in sandbox):

```bash
# ~/.api_keys
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="..."
```

---

## Quick Iterations Workflow

When you need fast feedback loops with AI assistance.

### Create, Work, Destroy Pattern

```bash
# Quick experiment
sb new owner/repo experiment-1 main
# ... work ...
sb destroy repo-experiment-1 --yes

# Another attempt
sb new owner/repo experiment-2 main
# ... work ...
```

### Preserve Work You Like

Before destroying, push changes:

```bash
# Inside sandbox
git push origin experiment-branch

# Then destroy
sb destroy repo-experiment-branch --yes
```

---

## Debugging a Production Issue

Safely investigate issues without touching production code.

### Create Isolated Environment

```bash
# Clone the exact production version
sb new owner/repo debug-issue-123 production
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
sb destroy repo-debug-issue-123 --yes
```

---

## Working with Private Repositories

### GitHub Authentication

Ensure `GITHUB_TOKEN` is set on your host:

```bash
export GITHUB_TOKEN="ghp_..."
sb new private-org/private-repo feature
```

### SSH Keys (Alternative)

```bash
# Mount SSH keys read-only
sb new owner/repo feature --mount ~/.ssh:/home/ubuntu/.ssh:ro
```

---

## Network Isolation Workflow

Control network access for sensitive work or offline development.

### Restricted Network for Sensitive Code

```bash
# Only allow essential services (github, npm, pypi, AI APIs)
sb new owner/repo sensitive-feature --network=limited

# Inside sandbox, test that restrictions work
curl https://github.com  # works
curl https://random-site.com  # blocked
```

### Completely Offline Development

```bash
# No network at all
sb new owner/repo offline-work --network=none

# Inside sandbox, everything is blocked
curl https://anything.com  # fails
```

### Runtime Network Switching

```bash
# Start with full network
sb new owner/repo feature

# Inside container, restrict later
sudo network-mode limited

# Check current status
network-mode

# Add a custom domain if needed
sudo network-mode allow custom-api.example.com

# Switch back to full when needed
sudo network-mode full
```

### Host-Only for Local Services

```bash
# Allow only local network (for local databases, APIs)
sb new owner/repo local-dev --network=host-only

# Inside sandbox
curl http://localhost:8080  # works (if service running on host)
curl https://external.com   # blocked
```

### Custom Domain Whitelist

```bash
# Add extra domains to the limited mode whitelist
export SANDBOX_ALLOWED_DOMAINS="internal-api.company.com,cache.myorg.net"
sb new owner/repo feature --network=limited

# These domains will be allowed in addition to defaults
```

---

## Tips and Best Practices

### Name Your Branches Descriptively

```bash
# Good - describes the work
sb new owner/repo add-oauth-google main
sb new owner/repo fix-memory-leak main

# Less helpful
sb new owner/repo test1 main
```

### Use sb list Often

```bash
# See what you have running
sb list
```

### Clean Up Finished Work

```bash
# Don't let sandboxes accumulate
sb destroy old-sandbox --yes

# Or prune orphaned configs
sb prune -f
```

### Debugging Issues

```bash
# Enable debug output
SANDBOX_DEBUG=1 sb attach mybox

# Check sandbox status
sb status mybox
```
