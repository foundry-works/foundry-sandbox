# Red Team Security Tests

Adversarial security tests that run **inside** an sbx sandbox to validate isolation boundaries.

## Running

```bash
# Inside a running sandbox:
./tests/redteam-sandbox.sh

# Or directly:
./tests/redteam/runner.sh

# Run a single module:
./tests/redteam/runner.sh --module 09-git-security

# TAP/JUnit output:
./tests/redteam/runner.sh --output-format tap --output-dir /tmp/results
```

## Active Modules (13)

| # | Module | Category | Description |
|---|--------|----------|-------------|
| 01 | `credentials-env` | Credential isolation | Scans env vars for leaked API keys |
| 02 | `credentials-files` | Credential isolation | Checks filesystem for credential files |
| 08 | `credential-injection` | Credential isolation | sbx proxy-level injection, HMAC auth, user-services proxy |
| 09 | `git-security` | Git safety | Hooks, shadow isolation, wrapper, HMAC auth, marketplace access |
| 10 | `container-escape` | VM boundary | VM isolation, lateral movement, metadata service, mount inspection |
| 11 | `github-api` | Git safety | GitHub API deep policy, blocked operations, service isolation |
| 12 | `tls-filesystem` | FS/capability | TLS trust, filesystem write restrictions, capability verification |
| 13 | `credential-patterns` | Credential isolation | Additional pattern scanning (Slack tokens, private keys, GCP SA) |
| 15 | `self-merge` | Git safety | Self-merge and self-approval prevention |
| 16 | `readonly-fs` | FS boundary | Read-only root FS, tmpfs, workspace mount, git wrapper |
| 17 | `workflow-push` | Git safety | `.github/workflows/` push blocking |
| 19 | `merge-early-exit` | Git safety | Early-exit merge blocking before identity checks |
| 20 | `package-install` | Boundary testing | pip/npm install paths, sudo blocking |

## Retired Modules (7)

Removed in 0.21.0 — tested the deleted unified-proxy/mitmproxy network stack:

- `03-dns-filtering` — DNS filtering via compose dnsmasq
- `04-network-isolation` — HTTP_PROXY/HTTPS_PROXY bypass testing
- `05-proxy-egress` — Proxy hostname allowlist testing
- `06-direct-ip-egress` — `--noproxy` direct-IP bypass testing
- `07-proxy-admin` — Mitmproxy web UI accessibility
- `14-network-bypass` — Proxy blocking, gateway_token, direct DNS
- `18-ip-encoding-bypass` — Proxy policy engine IP-encoded URL blocking

Network egress control is now covered by `sbx policy` and the chaos test suite.

## Prerequisites

- Live sbx sandbox with git wrapper installed at `/usr/local/bin/git`
- `foundry-git-safety` server running on the host
- Set `GIT_SHADOW_ENABLED=1` for full git shadow mode tests (modules 09, 17)
