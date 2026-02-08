# Security Architecture

Foundry Sandbox implements defense in depth with multiple security controls. This document distinguishes between **security pillars** (kernel/Docker-enforced, cannot bypass from inside container) and **operational conveniences** (helpful but bypassable).

## Overview

```
                    ┌─────────────────────────────────────┐
                    │         SECURITY PILLARS            │
                    │     (cannot bypass from inside)     │
                    ├─────────────────────────────────────┤
                    │                                     │
AI Command ────────►│  ┌─────────────────────────────┐   │
                    │  │   Read-only Filesystem      │   │
                    │  │   (Docker read_only: true)  │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │   Network Isolation         │   │
                    │  │   (Docker + dnsmasq + ipt)  │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │   Sudoers Allowlist         │   │
                    │  │   (Linux kernel)            │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │   Credential Isolation      │   │
                    │  │   (unified-proxy)           │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │   Branch Isolation          │   │
                    │  │   (git_operations)          │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │   Git Safety                │   │
                    │  │   (git_policies)            │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    └─────────────────────────────────────┘
```

---

## Security Pillars

These controls are enforced by the kernel, Docker, or external architecture. They **cannot be bypassed** from inside the container.

### Read-only Filesystem

**Enforced by:** Docker (`read_only: true` in base mode)

**Implementation:** `docker-compose.yml` (base), `docker-compose.credential-isolation.yml` (override)

**Base mode** (`docker-compose.yml`):
```yaml
services:
  dev:
    read_only: true
```

**Credential isolation mode** overrides this to `read_only: false` because the root entrypoint needs to configure DNS via iptables and write `/etc/resolv.conf`. This is an accepted risk with mitigations:
- Non-root user (uid 1000 via gosu) limits write scope
- Network isolation (`internal: true`) prevents data exfiltration
- Tmpfs `/home` means writes don't persist across restarts
- The worktree `/workspace/.git` is hidden via bind mount to `/dev/null`

See [Container Filesystem Write Capability](sandbox-threats.md#container-filesystem-write-capability) in the threat model for the full analysis.

**What it blocks (in base mode):**
- `rm -rf /` via any method (including `/bin/rm`)
- Writing to system directories
- Modifying installed packages
- Any filesystem mutation outside tmpfs mounts

**Tmpfs exceptions (writable):**
- `/tmp` - Temporary files
- `/var/tmp` - More temporary files
- `/run` - Runtime state
- `/var/cache/apt` - Package cache
- `/home/ubuntu` - User home (ephemeral, resets on restart)

**Bypass:** Cannot be bypassed from inside the container in base mode. In credential isolation mode, writes to non-tmpfs paths are possible but mitigated by non-root user and network isolation.

### Network Isolation

**Enforced by:** Docker networking + dnsmasq + iptables

**Implementation:** `safety/network-firewall.sh`, `safety/network-mode`

**How it works:**
- Internal Docker network (`internal: true`) - no default gateway
- ICC (inter-container communication) disabled
- DNS routed through unified-proxy (enabled by default)
- iptables rules for defense-in-depth

**Network Modes:**

| Mode | Description | Use Case |
|------|-------------|----------|
| `limited` | Whitelist only (default) | Normal development |
| `host-only` | Local network only | Isolated development |
| `none` | Loopback only | Maximum isolation |

**Default whitelist (limited mode):**
- GitHub (github.com, api.github.com, raw.githubusercontent.com)
- AI APIs (Anthropic, OpenAI, Google Gemini)
- Research APIs (Tavily, Perplexity, Semantic Scholar)

Additional domains via `SANDBOX_ALLOWED_DOMAINS` environment variable.

**Bypass:** Cannot be bypassed from inside the container. Requires host-level network configuration changes.

**Reference:** [Network Isolation](network-isolation.md)

### Sudoers Allowlist

**Enforced by:** Linux kernel

**Implementation:** `/etc/sudoers.d/allowlist`

**Source:** `safety/sudoers-allowlist`

**Allowed commands:**
- Package management: `sudo apt-get update`, `sudo apt-get install *`
- Service management: `sudo service * start/stop/restart/status`

Everything else is denied—no fallback `PASSWD:ALL` line.

**Extending the allowlist:**

```bash
# Example: Allow npm and pip
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/npm *
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/pip *
```

Then rebuild: `cast build`

**Bypass:** Cannot be bypassed from userspace. The kernel enforces sudoers rules.

### Credential Isolation

**Enforced by:** Unified-proxy architecture (when enabled)

**Implementation:** `docker-compose.credential-isolation.yml`

**How it works:**

The sandbox contains **zero real credentials**:

| Credential | Where it lives | What sandbox sees |
|------------|----------------|-------------------|
| GITHUB_TOKEN / GH_TOKEN | Unified Proxy container | Nothing (empty) |
| ANTHROPIC_API_KEY | Unified Proxy container | `CREDENTIAL_PROXY_PLACEHOLDER` |
| OPENAI_API_KEY | Unified Proxy container | `CREDENTIAL_PROXY_PLACEHOLDER` |
| Other API keys | Unified Proxy container | `CREDENTIAL_PROXY_PLACEHOLDER` |
| GIT_CREDENTIAL_TOKEN | Unified Proxy subprocess env only | Nothing (never exposed) |

- Real credentials never enter sandbox containers
- Sandboxes are registered with the proxy via container registration
- Unified proxy injects real credentials into outbound requests
- AI cannot exfiltrate credentials that don't exist in its environment

**What this means:**
- Environment variable inspection yields only placeholders
- Memory scraping yields nothing useful
- Exfiltration attempts get placeholder values, not real secrets

**Bypass:** Cannot be bypassed without compromising the unified-proxy container itself (which runs outside the sandbox).

**Reference:** [Credential Isolation](credential-isolation.md)

---

## Operational Controls

### Operator Approval (TTY-based)

**Enforced by:** TTY check in `/opt/operator/bin/operator-approve`

**How it works:**
- Wrapper checks if stdin is a TTY (`[ -t 0 ]`)
- AI assistants run commands via subprocess without a TTY → Approval denied
- Human operators type in a terminal with a TTY → Can type "approve" to proceed

**When to use:**
- Destructive operations that are sometimes necessary
- Commands that cannot be protected by other layers
- Operations that benefit from human review

**Bypass:** Cannot be bypassed from non-interactive contexts (AI subprocesses). Requires an actual TTY connection.

---

## Appendix: UX Conveniences

> **Note:** These features provide helpful warnings but are **not security controls**. They can be trivially bypassed and should not be relied upon for security.

### Credential Redaction

**Purpose:** Defense in depth. Masks secrets and sensitive values in command output to prevent accidental exposure.

**Implementation:** Shell function wrapper that filters output through pattern matching.

**What it masks:**
- API keys and tokens (patterns like `sk-*`, `key-*`, bearer tokens)
- Environment variable values containing sensitive keywords
- Common secret patterns in logs and output

**Bypass methods:**
```bash
cat ~/.config/secrets.json    # Read files directly
python -c "import os; print(os.environ)"  # Different interpreter
```

**Why keep it:** Reduces accidental exposure in logs and terminal output, but real credential protection requires credential isolation.

---

## Summary Table

| Control | Enforced By | Bypassable? | Purpose |
|---------|-------------|-------------|---------|
| Read-only filesystem | Docker/kernel | No (from container) | Prevent filesystem writes |
| Network isolation | Docker/dnsmasq/iptables | No (from container) | Control network egress |
| Sudoers allowlist | Linux kernel | No (from userspace) | Restrict sudo commands |
| Credential isolation | Unified-proxy architecture | No (without proxy compromise) | Protect credentials |
| Operator approval | TTY check | No (from non-interactive) | Human-in-the-loop |
| Branch isolation | git_operations + branch_isolation.py | No (from container) | Prevent cross-sandbox git access |
| Git safety | git_policies.py + github-api-filter.py | No (from container) | Protected branches, force-push blocking, API controls |
| Credential redaction | Shell functions | **Yes** | Defense in depth |

---

## Testing the Pillars

### Read-only Filesystem

```bash
# Attempt direct write
/bin/rm -rf /usr
# Expected: "Read-only file system" error

# Verify tmpfs is writable
touch /tmp/test && rm /tmp/test
# Expected: Success
```

### Network Isolation

```bash
# Check current mode
sudo network-mode status

# Verify blocked domain (in limited mode)
curl -v https://example.com 2>&1 | grep -E "(Connection refused|timed out)"
# Expected: Connection failure
```

### Sudoers Allowlist

```bash
# Allowed command
sudo apt-get update
# Expected: Success

# Blocked command
sudo rm /tmp/test
# Expected: "user is not allowed to execute" error
```

### Operator Approval

```bash
# Interactive (will prompt)
/opt/operator/bin/operator-approve echo "test"

# Non-interactive (will fail)
echo "test" | /opt/operator/bin/operator-approve echo "test"
# Expected: Approval denied
```

---

## Next Steps

- [Sandbox Threats](sandbox-threats.md) - What we're protecting against
- [Credential Isolation](credential-isolation.md) - Credential isolation threat model
- [Network Isolation](network-isolation.md) - Detailed network architecture
- [Security Overview](index.md) - Quick reference
