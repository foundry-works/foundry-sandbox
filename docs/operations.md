# Operations Runbook

This guide covers operational procedures for managing sbx sandboxes and the foundry-git-safety service.

## Contents

**Runbooks:**
- [Sandbox Lifecycle Operations](#sandbox-lifecycle-operations)
- [Git Safety Server Management](#git-safety-server-management)
- [HMAC Secret Rotation](#hmac-secret-rotation)
- [Git Wrapper Re-injection](#git-wrapper-re-injection)
- [Emergency Procedures](#emergency-procedures)

**Troubleshooting:**
- [Sandbox Issues](#sandbox-issues)
- [Git Safety Issues](#git-safety-issues)
- [Credential Issues](#credential-issues)
- [Network Issues](#network-issues)

## Sandbox Lifecycle Operations

### Listing Sandboxes

```bash
# List all sandboxes with status
cast list

# JSON output
cast list --json

# Raw sbx output
sbx ls
```

### Starting a Stopped Sandbox

```bash
cast start <name>

# Or directly via sbx
sbx run <name>
```

`cast start` also verifies the git safety server is running and re-injects the git wrapper if missing.

### Stopping a Running Sandbox

```bash
cast stop <name>

# Or directly via sbx
sbx stop <name>
```

The worktree and host-side state are preserved.

### Removing a Sandbox

```bash
cast destroy <name>           # With confirmation
cast destroy <name> --force   # Skip confirmation
cast destroy <name> --keep-worktree  # Keep worktree on disk
```

Destroy also unregisters the sandbox from the git safety server and cleans up the worktree, bare repo branch, and config directory.

### Removing All Sandboxes

```bash
cast destroy-all              # With double confirmation
cast destroy-all --keep-worktree
```

### Diagnostics

```bash
sbx diagnose                  # Run sbx diagnostics
cast config                   # Show configuration and system checks
```

## Git Safety Server Management

The `foundry-git-safety` server runs on the host as a daemon, handling git operations for all sandboxes.

### Server Lifecycle

```bash
# Start (automatic on cast new)
foundry-git-safety start

# Check status
foundry-git-safety status

# Stop
foundry-git-safety stop

# Validate configuration
foundry-git-safety validate

# Run in foreground (debugging)
foundry-git-safety start --foreground

# Custom port
foundry-git-safety start --port 8084
```

### Checking Registered Sandboxes

Sandbox registrations are stored as JSON files on the host:

```bash
# List registered sandboxes
ls /var/lib/foundry-git-safety/sandboxes/

# View a specific sandbox's registration
cat /var/lib/foundry-git-safety/sandboxes/<name>.json

# List HMAC secrets
ls /run/secrets/sandbox-hmac/
```

### Configuration

Git safety is configured via `foundry.yaml` in the workspace root. See [Configuration](configuration.md#git-safety-configuration) for the full schema.

```bash
# Validate the configuration
foundry-git-safety validate
```

## HMAC Secret Rotation

Each sandbox has a unique HMAC secret (64 hex chars) used to authenticate git operations between the sandbox's git wrapper and the git safety server.

### When to Rotate

- Suspected secret compromise
- Routine security hygiene
- After a security incident

### Rotation Procedure

**Step 1: Generate a new secret**

```bash
NEW_SECRET=$(openssl rand -hex 32)
```

**Step 2: Update the server-side secret**

```bash
echo -n "${NEW_SECRET}" > /run/secrets/sandbox-hmac/<name>
chmod 600 /run/secrets/sandbox-hmac/<name>
```

**Step 3: Update the worktree-side secret**

```bash
echo -n "${NEW_SECRET}" > ~/.sandboxes/worktrees/<name>/.foundry/hmac-secret
chmod 600 ~/.sandboxes/worktrees/<name>/.foundry/hmac-secret
```

The sbx file sync will propagate the updated secret into the running sandbox.

**Step 4: Restart the git safety server**

```bash
foundry-git-safety stop
foundry-git-safety start
```

### Post-Rotation Verification

```bash
# Verify git operations still work from the sandbox
sbx exec <name> -- git -C /workspace status

# Check for auth errors in logs
journalctl -u foundry-git-safety | grep -i "invalid.*signature\|auth.*fail" | tail -10
```

### Bulk Rotation (All Sandboxes)

```bash
for secret_file in /run/secrets/sandbox-hmac/*; do
  NAME=$(basename "$secret_file")
  NEW_SECRET=$(openssl rand -hex 32)

  # Update server side
  echo -n "${NEW_SECRET}" > "$secret_file"
  chmod 600 "$secret_file"

  # Update worktree side (if sandbox has a worktree)
  WORKTREE_PATH=$(jq -r '.worktree_path // empty' ~/.sandboxes/claude-config/"${NAME}"/metadata.json 2>/dev/null)
  if [ -n "$WORKTREE_PATH" ] && [ -d "$WORKTREE_PATH/.foundry" ]; then
    echo -n "${NEW_SECRET}" > "${WORKTREE_PATH}/.foundry/hmac-secret"
    chmod 600 "${WORKTREE_PATH}/.foundry/hmac-secret"
  fi
done

# Restart git safety server
foundry-git-safety stop && foundry-git-safety start
```

## Git Wrapper Re-injection

If the git wrapper is missing or damaged inside a sandbox, re-inject it:

```bash
# Verify wrapper presence
sbx exec <name> -- which git
# Should return /usr/local/bin/git

# If missing or incorrect, re-inject via cast start
cast start <name>  # cast start re-injects automatically

# Manual re-injection
# (The wrapper script is at stubs/git-wrapper-sbx.sh in the project)
WRAPPER_CONTENT=$(cat stubs/git-wrapper-sbx.sh)
sbx exec <name> -u root -- tee /usr/local/bin/git <<< "$WRAPPER_CONTENT"
sbx exec <name> -u root -- chmod 755 /usr/local/bin/git
```

### Persisting the Wrapper Across Resets

`sbx reset` destroys the sandbox filesystem, including the injected wrapper. To persist it:

```bash
# After setting up a sandbox, save it as a template
sbx template save <name> my-template

# Create future sandboxes from the template
sbx template load my-template
```

## Emergency Procedures

### Complete Reset

Use when a sandbox is in an unrecoverable state:

```bash
# Remove the sandbox
sbx rm <name>

# Clean up host-side state
cast destroy <name> --force

# Recreate
cast new <repo> <branch>
```

### Git Safety Server Won't Start

```bash
# Check if port is in use
ss -tlnp | grep 8083

# Kill any stale process
kill $(lsof -t -i:8083) 2>/dev/null

# Try starting in foreground for error messages
foundry-git-safety start --foreground

# Validate configuration
foundry-git-safety validate
```

### Sandbox Unresponsive

```bash
# Check sandbox status
sbx ls

# Try graceful stop
sbx stop <name>

# Run diagnostics
sbx diagnose

# Last resort: remove and recreate
sbx rm <name>
cast new <repo> <branch>
```

## Troubleshooting

### Sandbox Issues

**Sandbox creation fails:**

```bash
# Verify sbx is installed
sbx --version

# Check available resources
sbx diagnose

# Check worktree exists
ls -la ~/.sandboxes/worktrees/<name>
```

**Sandbox won't start:**

```bash
# Check status
sbx ls | grep <name>

# Run diagnostics
sbx diagnose

# Try removing and recreating
sbx rm <name>
cast new <repo> <branch>
```

### Git Safety Issues

**Git commands fail inside sandbox:**

```bash
# 1. Verify git safety server is running
foundry-git-safety status

# 2. Verify wrapper is installed
sbx exec <name> -- which git
# Should return /usr/local/bin/git

# 3. Check HMAC secret exists on both sides
ls /run/secrets/sandbox-hmac/<name>
ls ~/.sandboxes/worktrees/<name>/.foundry/hmac-secret

# 4. Test git operation directly
sbx exec <name> -- git -C /workspace status
```

**Branch isolation errors:**

```bash
# Check sandbox registration
cat /var/lib/foundry-git-safety/sandboxes/<name>.json

# Verify branch metadata is correct
# The file should contain: sandbox_branch, from_branch, repos, allow_pr
```

**Git fetch hangs:**

```bash
# Check for stale lock files in the bare repo
ls ~/.sandboxes/repos/*/*/*/repo.git/.fetch-lock 2>/dev/null

# Remove stale locks
find ~/.sandboxes/repos/ -name '.fetch-lock' -delete
```

### Credential Issues

**API calls fail from sandbox:**

```bash
# Verify secrets are stored on host
sbx secret list

# Re-push credentials
cast refresh-creds <name>

# Or set individually
echo "$ANTHROPIC_API_KEY" | sbx secret set -g anthropic
```

**GitHub token not working:**

```bash
# Check if token is set
echo "$GITHUB_TOKEN" | sbx secret set -g github

# Verify from inside sandbox (should be placeholder)
sbx exec <name> -- env | grep GH_TOKEN
# Should show: proxy-managed
```

### Network Issues

**Requests blocked unexpectedly:**

```bash
# Check network policy
sbx policy status

# Add a domain if needed
sbx policy allow network example.com

# Check if domain is in the policy
sbx policy list
```

**Cannot reach git safety server from sandbox:**

```bash
# The git safety server is accessed via the sbx HTTP proxy
# Verify the proxy is working
sbx exec <name> -- curl --proxy http://gateway.docker.internal:3128 http://host.docker.internal:8083/health

# If this fails, check sbx proxy status
sbx diagnose
```

## See Also

- [Architecture](architecture.md) — System design
- [Configuration](configuration.md) — Git safety and network policy settings
- [Security Model](security/security-model.md) — Threat model and defenses
- [ADR-008](adr/008-sbx-migration.md) — sbx migration decision
