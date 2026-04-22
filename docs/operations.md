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

Destroy also unregisters the sandbox from the git safety server and cleans up the worktree, sandbox branch, and config directory.

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
foundry-git-safety start --port 9090
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
echo -n "${NEW_SECRET}" > /run/foundry/hmac-secret
chmod 600 /run/foundry/hmac-secret
```

The secret is read from tmpfs at runtime — no file sync propagation needed.

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

  # Update sandbox side (tmpfs)
  echo -n "${NEW_SECRET}" > /run/foundry/hmac-secret
  chmod 600 /run/foundry/hmac-secret
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
# (The wrapper script is at foundry_sandbox/assets/git-wrapper-sbx.sh in the project)
WRAPPER_CONTENT=$(cat foundry_sandbox/assets/git-wrapper-sbx.sh)
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

# 3. Check HMAC secret exists
ls /run/foundry/hmac-secret

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
# Check for stale lock files in the repo
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
- [Security Audit §5.6](security/audit-5.6.md) — Detailed security audit findings
- [ADR-008](adr/008-sbx-migration.md) — sbx migration decision

---

## Performance Baselines

### Methodology

Performance baselines are measured using `scripts/bench-git-safety.sh` against a single sandbox on a reference machine. Each operation is executed 20 times after 3 warm-up iterations. Results report p50 (median) and p95 latencies.

### Microbenchmark Results

The following are measured by `foundry-git-safety/tests/unit/test_performance.py` on the test machine:

| Operation | Threshold | Meets |
|-----------|-----------|-------|
| HMAC signature compute | < 1ms | Yes |
| HMAC signature verify | < 1ms | Yes |
| Nonce store check | < 100us | Yes |
| Rate limiter check | < 50us | Yes |
| Counter increment | < 10us | Yes |
| Prometheus render (100 series) | < 100ms | Yes |
| Decision log write throughput | >= 1000/sec | Yes |
| Decision log rotation | < 100ms | Yes |
| Authenticated request throughput | >= 50 req/s | Yes |

### Full Stack Baselines (requires live sbx)

| Operation | p50 | p95 | Notes |
|-----------|-----|-----|-------|
| git status | TBD | TBD | Local, no network |
| git log -10 | TBD | TBD | Local, no network |
| git fetch | TBD | TBD | Network round-trip via sbx proxy |
| git push | TBD | TBD | Full push path with validation |
| git clone | TBD | TBD | Cold start, full initialization |

Run `scripts/bench-git-safety.sh` to populate the table above.

### Known Performance Considerations

1. **No connection pooling in proxies**: Each proxied request (user services, deep policy, GitHub filter) opens a fresh `http.client.HTTPSConnection`. Consider connection pooling for high-throughput scenarios.
2. **Synchronous decision log**: Each git operation writes to the decision log synchronously with `flush()`. Under high throughput (>1000 ops/sec) this becomes the bottleneck.
3. **File-based metadata**: Sandbox metadata is loaded from disk on every request (no cache). Adds ~0.1-0.5ms per request.
4. **Single lock contention**: `metrics._MetricsRegistry._lock`, `RateLimiter._lock`, and `NonceStore._lock` are single `threading.Lock` instances. Under high concurrency (>100 req/sec) these may contend.

### How to Reproduce

```bash
# Run microbenchmark tests
pytest foundry-git-safety/tests/unit/test_performance.py -v -m slow

# Run full-stack benchmark (requires live sbx)
./scripts/bench-git-safety.sh
```

---

## Chaos Recovery Procedures

### sbx Daemon Crash

If the sbx daemon crashes while sandboxes are running:

1. **Sandbox state**: Running sandboxes are preserved by the hypervisor
2. **Git wrapper**: Will fail with connection errors until the daemon recovers
3. **Recovery**: `sbx` auto-restarts on next command; sandboxes reconnect
4. **Verify**: `cast list` to check sandbox status, `sbx diagnose` for details

### Git Safety Server Crash

If the foundry-git-safety server crashes:

1. **During git operation**: The wrapper's curl call times out (30s max) and returns exit code 1
2. **No partial writes**: Git push is atomic at the protocol level; a crash mid-push leaves the remote unchanged
3. **Recovery**: Server restarts via `foundry-git-safety start` or systemd
4. **Verify**: `foundry-git-safety status` and `cast diagnose`

### Network Partition

If the sandbox loses connectivity to the host:

1. **Wrapper behavior**: curl times out after `--max-time 30` and returns exit code 28
2. **Recovery**: Network restores automatically when partition ends; no sandbox restart needed
3. **Verify**: `sbx exec <name> -- curl -sf http://host.docker.internal:8083/health`

### Corrupted sbx reset

If `sbx reset` is interrupted:

1. **Sandbox state**: May be in a degraded state; `sbx ls` may show errors
2. **Recovery**: `cast destroy --force` to clean up, then `cast new` to recreate
3. **Wrapper**: Will be re-injected on next `cast start` (or present from template)

---

## HMAC Rotation Verification

After rotating HMAC secrets, run the automated verification:

```bash
pytest foundry-git-safety/tests/security/test_hmac_rotation.py -v -m security
```

This validates:
- Old secrets are rejected after rotation
- New secrets are accepted
- Nonce stores are cleared (no replay across rotation boundary)
- Rate limiter state is preserved
- Bulk rotation works for all sandboxes
