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
# Exit sandbox
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
- Separate sandboxes
- Changes in one don't affect others

---

## Using Different AI Tools

The sandbox comes with multiple AI coding assistants pre-installed.

### Claude Code

```bash
# Default usage
claude

# Skip permissions (for trusted repos)
claudedsp    # alias for: claude --dangerously-skip-permissions
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
codexdsp    # alias for: codex --dangerously-bypass-approvals-and-sandbox
```

### OpenCode

```bash
# Uses zai-coding-plan provider (run: opencode auth login)
opencode
```

### Setting API Keys

Set API keys on your host before creating a sandbox — they are passed into the sandbox automatically. See [Commands: Environment Variables](commands.md#environment-variables) for the full reference.

---

## Quick Iterations Workflow

When you want to try multiple approaches quickly.

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

Ensure `GITHUB_TOKEN` is set on your host (or use `gh auth login`):

```bash
export GITHUB_TOKEN="ghp_..."
cast new private-org/private-repo feature
```

Public repos can be accessed without a token, but private repos and push operations require one. Credentials are injected by sbx and never enter the sandbox.

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
```

### Diagnose Issues

```bash
# Collect diagnostic information for support
cast diagnose

# Run the wrapper integrity watchdog
cast watchdog --interval 10
```
