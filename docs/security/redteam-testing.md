# Red Team Security Testing

The redteam test suite validates sandbox isolation by running security checks from **inside** a running sandbox. It tests the actual security boundaries that protect the host, credentials, and git history from a compromised or misbehaving AI agent.

Running these tests on the host (outside a sandbox) produces many false failures because the isolation mechanisms (HMAC secrets, proxy routing, read-only root FS, etc.) only exist inside the microVM.

## Prerequisites

- `cast` CLI installed and configured
- `foundry-git-safety[server]` installed
- `sbx` runtime available (`sbx ls` works)
- At least one API key configured (for network proxy validation)

## Quick Start

```bash
# 1. Create a sandbox from the current repo and branch
cast new . sbx --name redteam-test --agent shell

# 2. Run the tests inside it
sbx exec redteam-test -- bash -c \
  "bash /home/tyler/GitHub/foundry-sandbox/tests/redteam/runner.sh"

# 3. Clean up
cast destroy redteam-test -f -y
```

The test script path inside the sandbox mirrors the host path because the repo is bind-mounted at its original location.

## Running Individual Modules

Each module tests a specific security domain. Run one in isolation:

```bash
sbx exec redteam-test -- bash -c \
  "bash /home/tyler/GitHub/foundry-sandbox/tests/redteam/runner.sh --module 04-git-security"
```

Available modules:

| Module | Tests |
|--------|-------|
| `01-credentials-env` | Environment variable credential leakage |
| `02-credentials-files` | File-based credential hunting |
| `03-credential-injection` | Proxy-level injection (no real keys in VM) |
| `04-git-security` | Git hook hardening, shadow isolation, marketplace access |
| `05-container-escape` | Docker socket, cloud metadata, host ports |
| `06-github-api` | GitHub API deep policy enforcement |
| `07-tls-filesystem` | TLS trust, filesystem write restrictions, capabilities |
| `08-credential-patterns` | High-entropy scans, GCP keys, SSH keys |
| `09-self-merge` | Self-merge and self-approval prevention |
| `10-readonly-fs` | Read-only root FS, writable tmpfs, HMAC secret |
| `11-workflow-push` | Workflow file push blocking (requires shadow mode) |
| `12-merge-early-exit` | Merge blocking at earliest policy stage |
| `13-package-install` | pip/npm user-mode installs, system install denial |

## Structured Output

The runner supports machine-readable output formats:

```bash
# TAP format
sbx exec redteam-test -- bash -c \
  "bash /home/tyler/GitHub/foundry-sandbox/tests/redteam/runner.sh \
   --output-format tap --output-dir /tmp/results"

# JUnit XML
sbx exec redteam-test -- bash -c \
  "bash /home/tyler/GitHub/foundry-sandbox/tests/redteam/runner.sh \
   --output-format junit --output-dir /tmp/results"
```

## Deep Policy Setup

Most GitHub API tests route requests through the deep-policy proxy, which requires HMAC authentication. The proxy must be running with deep policy enabled:

```bash
# Check if git-safety is running
foundry-git-safety status

# Restart with deep policy (needed after code changes to policy rules)
foundry-git-safety stop
foundry-git-safety start --deep-policy

# Verify the GitHub service is loaded (should show rule_count > 0)
curl -s http://localhost:8083/deep-policy/health
```

The sandbox auto-starts the git-safety server with `--deep-policy` during `cast new`, but if the server was already running without that flag, you'll need to restart it manually before creating the sandbox.

## Interpreting Results

### Pass

The security control works as expected. Example:

```
  ✓ PASS: HMAC secret present on persistent storage (64 bytes)
  ✓ PASS: core.hooksPath is /dev/null
```

### Fail

A security control is not working. Investigate whether the issue is in the sandbox infrastructure, policy rules, or test logic:

```
  ✗ FAIL: Docker socket accessible - potential escape vector
  ✗ FAIL: Wrote 600MB to /tmp (tmpfs limit not enforced)
```

Infrastructure failures (Docker socket, cloud metadata, tmpfs limits) require sbx configuration changes, not code changes.

### Warning

The test could not determine a clear pass or fail. This often happens when network responses are ambiguous (e.g., a 404 from GitHub for a fake PR). Warnings should be reviewed but may be acceptable in certain configurations.

## Common Issues

### "HMAC secret not found"

The git-safety server isn't running or didn't provision the sandbox. Ensure:

1. `foundry-git-safety status` reports running
2. The sandbox was created with `cast new` (which provisions the HMAC secret)

### "Git safety environment variables missing"

The `GIT_API_HOST` / `GIT_API_PORT` env vars are injected via `/var/lib/foundry/git-safety.env`. This file is created during `cast new` provisioning. If missing, destroy and recreate the sandbox.

### Tests pass on host but fail in sandbox (or vice versa)

This is expected. The host has real credentials, writable root FS, and no proxy — many tests will fail on the host that pass inside the sandbox, and vice versa. Always run inside a sandbox for accurate results.

### Deep policy returns 404 for all requests

The deep-policy proxy isn't loaded. Restart the git-safety server with `--deep-policy` and recreate the sandbox.
