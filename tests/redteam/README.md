# Red Team Security Tests

Adversarial security tests that run **inside** an sbx sandbox to validate isolation boundaries.

## Running

### 1. Create a provisioned sandbox

```bash
# Use cast to create a sandbox with git-safety fully provisioned:
cast new --name redteam-test --agent shell .

# Or if you need a specific branch:
cast new --name redteam-test --agent shell . my-branch main
```

The sandbox must be created via `cast new` (not `sbx create` directly) to ensure the git wrapper, HMAC secrets, and git-safety server are all properly provisioned.

### 2. Run the tests

```bash
# Run all modules from inside the sandbox:
sbx exec redteam-test -- bash -c './tests/redteam/runner.sh'

# Enable full git shadow mode tests:
sbx exec redteam-test -- bash -c 'export GIT_SHADOW_ENABLED=1 && ./tests/redteam/runner.sh'

# Run a single module:
sbx exec redteam-test -- bash -c './tests/redteam/runner.sh --module 04-git-security'

# TAP/JUnit output:
sbx exec redteam-test -- bash -c './tests/redteam/runner.sh --output-format tap --output-dir /tmp/results'
```

### 3. Clean up

```bash
cast destroy redteam-test
```

## Active Modules (14)

| # | Module | Category | Description |
|---|--------|----------|-------------|
| 01 | `credentials-env` | Credential isolation | Scans env vars for leaked API keys |
| 02 | `credentials-files` | Credential isolation | Checks filesystem for credential files |
| 03 | `credential-injection` | Credential isolation | sbx proxy-level injection, HMAC auth, user-services proxy |
| 04 | `git-security` | Git safety | Hooks, shadow isolation, wrapper, HMAC auth, marketplace access |
| 05 | `container-escape` | VM boundary | VM isolation, lateral movement, metadata service, mount inspection |
| 06 | `github-api` | Git safety | GitHub API deep policy, blocked operations, service isolation |
| 07 | `tls-filesystem` | FS/capability | TLS trust, filesystem write restrictions, capability verification |
| 08 | `credential-patterns` | Credential isolation | Additional pattern scanning (Slack tokens, private keys, GCP SA) |
| 09 | `self-merge` | Git safety | Self-merge and self-approval prevention |
| 10 | `readonly-fs` | FS boundary | Read-only root FS, tmpfs, workspace mount, git wrapper |
| 11 | `workflow-push` | Git safety | `.github/workflows/` push blocking |
| 12 | `merge-early-exit` | Git safety | Early-exit merge blocking before identity checks |
| 13 | `package-install` | Boundary testing | pip/npm install paths, sudo blocking |
| 14 | `foundry-yaml-tamper` | Config integrity | foundry.yaml artifact immutability, gate exposure, template leakage |

## Retired Modules (7)

Removed in 0.21.0 — tested the deleted unified-proxy/mitmproxy network stack:

- `dns-filtering` — DNS filtering via compose dnsmasq
- `network-isolation` — HTTP_PROXY/HTTPS_PROXY bypass testing
- `proxy-egress` — Proxy hostname allowlist testing
- `direct-ip-egress` — `--noproxy` direct-IP bypass testing
- `proxy-admin` — Mitmproxy web UI accessibility
- `network-bypass` — Proxy blocking, gateway_token, direct DNS
- `ip-encoding-bypass` — Proxy policy engine IP-encoded URL blocking

Network egress control is now covered by `sbx policy` and the chaos test suite.

## Prerequisites

- Sandbox created via `cast new` (provisions git wrapper, HMAC auth, and git-safety registration)
- `foundry-git-safety` server running on the host (auto-started by `cast new`)
- Set `GIT_SHADOW_ENABLED=1` for full git shadow mode tests (modules 04, 11)
- `sbx` may mount the workspace at `/workspace` or at the host path ("direct mount") — `cast new` detects the correct path automatically
