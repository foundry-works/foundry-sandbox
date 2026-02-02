# Safety Layers

Foundry Sandbox implements defense in depth with multiple safety layers. This document explains each layer's purpose, implementation, and limitations.

## Overview

```
AI Command ──► Layer 1 (Shell Override)
                    │
                    ├─ Blocked pattern ──► DENIED (friendly message)
                    │
                    ▼
              Layer 2 (Credential Redaction)
                    │
                    └─ Masks secrets in output (defense in depth)
                    │
                    ▼
              Layer 3 (Operator Approval)  ◄── requires TTY
                    │
                    ├─ No TTY (AI) ──► DENIED
                    ├─ TTY + "approve" ──► ALLOWED
                    │
                    ▼
              Layer 4 (Sudoers)
                    │
                    ├─ Not in allowlist ──► DENIED
                    └─ In allowlist ──► ALLOWED
                    │
                    ▼
              Layer 5 (Network Isolation)  ◄── optional
                    │
                    ├─ Not in whitelist ──► DENIED (connection refused)
                    └─ In whitelist ──► ALLOWED
                    │
                    ▼
              Layer 6 (Read-only Root)
                    │
                    └─ Write to / ──► DENIED (filesystem error)
```

## Layer 6: Read-Only Root Filesystem

**Purpose:** Last line of defense. Even if all other layers fail, the filesystem blocks writes.

**Implementation:** `docker-compose.yml`

```yaml
services:
  dev:
    read_only: true
```

**What it blocks:**
- `rm -rf /` via any method
- Writing to system directories
- Modifying installed packages
- Any filesystem mutation outside tmpfs mounts

**Bypass:** Cannot be bypassed from inside the container. Would require modifying docker-compose.yml on the host.

## Layer 1: Shell Function Overrides

**Purpose:** First line of defense. Provides friendly "BLOCKED" messages to help a non-adversarial AI avoid accidental destructive commands.

**Implementation:** `/etc/profile.d/shell-overrides.sh`

**Location in repo:** `safety/shell-overrides.sh`

### Blocked Patterns

**rm command:**
```bash
rm() {
    local args="$*"
    # Check for recursive + force flags
    if [[ "$args" =~ -[rf]*r[rf]* ]] || [[ "$args" =~ -[rf]*f[rf]*.*-r ]]; then
        for arg in "$@"; do
            case "$arg" in
                /|~|"$HOME"|.|..)
                    echo "BLOCKED: rm -rf on protected path: $arg"
                    return 1 ;;
            esac
        done
    fi
    command rm "$@"
}
```

Blocks: `rm -rf /`, `rm -rf ~`, `rm -rf .`, `rm -rf ..`
Allows: `rm -rf ./node_modules`, `rm file.txt`

**git command:**
```bash
git() {
    case "$1" in
        reset)
            if [[ "$*" =~ --hard ]]; then
                echo "BLOCKED: git reset --hard requires operator approval"
                return 1
            fi ;;
        clean)
            if [[ "$*" =~ -[a-zA-Z]*f ]]; then
                echo "BLOCKED: git clean -f requires operator approval"
                return 1
            fi ;;
        push)
            if [[ "$*" =~ --force ]] && [[ ! "$*" =~ --force-with-lease ]]; then
                echo "BLOCKED: git push --force requires operator approval"
                return 1
            fi ;;
    esac
    command git "$@"
}
```

Blocks:
- `git reset --hard` (discards uncommitted changes)
- `git clean -f` (deletes untracked files)
- `git push --force` (overwrites remote history)

Allows:
- `git push --force-with-lease` (safer force push)
- `git reset` (soft reset)
- `git clean -n` (dry run)

### Limitations

Shell functions can be bypassed:

```bash
/bin/rm -rf /           # Direct path to binary
command rm -rf /        # Bash builtin bypass
\rm -rf /               # Backslash escape
env rm -rf /            # Via env command
$(which rm) -rf /       # Via command substitution
```

**This is intentional.** Layer 1 is for UX, not security. It catches accidental use while still allowing humans to override when needed. The read-only filesystem (Layer 0) prevents actual damage.

## Layer 2: Credential Redaction

**Purpose:** Defense in depth. Masks secrets and sensitive values in command output to prevent accidental exposure.

**Implementation:** Shell function wrapper that filters output through pattern matching.

**What it masks:**
- API keys and tokens (patterns like `sk-*`, `key-*`, bearer tokens)
- Environment variable values containing sensitive keywords
- Common secret patterns in logs and output

**Bypass:** Can be bypassed by reading files directly or using commands that don't go through the shell wrapper. This is intentional—the layer provides defense in depth, not security.

## Layer 3: Operator Approval Wrapper

**Purpose:** Human-in-the-loop for sensitive operations. Requires interactive confirmation from a TTY.

**Implementation:** `/opt/operator/bin/operator-approve`

**Location in repo:** `safety/operator-approve`

### How It Works

```bash
#!/bin/bash
set -euo pipefail

COMMAND="$*"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  OPERATOR APPROVAL REQUESTED"
echo "═══════════════════════════════════════════════════════"
echo "  Command: $COMMAND"
echo ""

# Check if stdin is interactive (tty)
if [ -t 0 ]; then
    read -p "  Type 'approve' to execute: " RESPONSE
    echo ""
    if [ "$RESPONSE" = "approve" ]; then
        exec "$@"
    else
        echo "  Operation cancelled."
        exit 1
    fi
else
    echo "  ERROR: This operation requires interactive approval."
    echo "  A human operator must run this command in a terminal."
    echo ""
    exit 1
fi
```

### Key Insight: TTY Detection

The critical security mechanism is `[ -t 0 ]` which checks if stdin is a TTY (terminal).

- **AI assistants** run commands via subprocess without a TTY → Approval denied
- **Human operators** type in a terminal with a TTY → Can approve

### Usage

The wrapper is at `/opt/operator/bin/operator-approve`, which is NOT in the AI's PATH. To use it:

```bash
/opt/operator/bin/operator-approve git reset --hard HEAD
```

This prompts: `Type 'approve' to execute:`

If a human types `approve`, the command runs. If it's an AI (no TTY), the request is automatically denied.

### When to Use

Use operator approval for commands that:
1. Are destructive but sometimes necessary
2. Cannot be protected by other layers
3. Benefit from human review

## Layer 4: Sudoers Allowlist

**Purpose:** Kernel-enforced restriction on sudo commands. Cannot be bypassed from userspace.

**Implementation:** `/etc/sudoers.d/allowlist`

**Location in repo:** `safety/sudoers-allowlist`

### Allowed Commands

```
# Package management (safe)
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/apt-get update
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/apt-get install *

# Service management (safe)
ubuntu ALL=(ALL) NOPASSWD: /usr/sbin/service * start
ubuntu ALL=(ALL) NOPASSWD: /usr/sbin/service * stop
ubuntu ALL=(ALL) NOPASSWD: /usr/sbin/service * restart
ubuntu ALL=(ALL) NOPASSWD: /usr/sbin/service * status

# NO fallback line - everything else is denied
```

### What This Means

```bash
sudo apt-get update          # ALLOWED
sudo apt-get install vim     # ALLOWED
sudo service nginx start     # ALLOWED
sudo rm -rf /                # DENIED (not in allowlist)
sudo chmod 777 /             # DENIED
sudo anything-else           # DENIED
```

### Why No Fallback

Traditional sudoers files often end with:
```
ubuntu ALL=(ALL) PASSWD:ALL
```

This allows any command with a password. We omit this entirely. If a command isn't explicitly in the allowlist, it's denied with no password prompt.

### Extending the Allowlist

To allow additional commands, add them to `safety/sudoers-allowlist` and rebuild the image:

```bash
# Example: Allow npm and pip
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/npm *
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/pip *
```

Then: `cast build`

## Layer 5: Network Isolation

**Purpose:** Optional network restrictions. Limits outbound connections to whitelisted domains or local network only.

**Implementation:** iptables rules applied at container startup

**Location in repo:** `safety/network-firewall.sh`, `safety/network-mode`

### Network Modes

| Mode | Description |
|------|-------------|
| `limited` | Whitelist only (github, npm, pypi, AI APIs) **(default)** |
| `host-only` | Local network only (Docker gateway, private subnets) |
| `none` | Complete block (loopback only) |

### Creating with Network Mode

```bash
# Limited to whitelist (default)
cast new owner/repo feature

# Local network only
cast new owner/repo feature --network=host-only

# No network
cast new owner/repo feature --network=none
```

### Runtime Switching

Inside the container, you can switch modes without restarting:

```bash
# Check current mode
sudo network-mode status

# Switch to limited
sudo network-mode limited

# Switch to host-only
sudo network-mode host-only
```

Note: Runtime domain additions are disabled for security. To allow additional domains, set `SANDBOX_ALLOWED_DOMAINS` on the host before creating the sandbox.

### Default Whitelist (Limited Mode)

The limited mode allows access to:

- **GitHub**: github.com, api.github.com, raw.githubusercontent.com
- **NPM**: registry.npmjs.org
- **PyPI**: pypi.org, files.pythonhosted.org
- **Go**: proxy.golang.org, sum.golang.org
- **AI APIs**: api.anthropic.com, api.openai.com, generativelanguage.googleapis.com
- **Docker Hub**: registry-1.docker.io, auth.docker.io

Additional domains can be whitelisted via `SANDBOX_ALLOWED_DOMAINS` environment variable:

```bash
export SANDBOX_ALLOWED_DOMAINS="custom-api.example.com,internal.mycompany.com"
cast new owner/repo feature --network=limited
```

### Limitations

- `none` mode at creation time uses Docker's true network isolation (no eth0 interface)
- Runtime-switched `none` mode simulates isolation via iptables (eth0 exists but blocked)
- For maximum security, use `--network=none` at creation time

## Layer Summary

| Layer | Purpose | Enforced By | Bypassable? |
|-------|---------|-------------|-------------|
| 1 | Friendly UX warnings | Shell functions | Yes (intentionally) |
| 2 | Credential redaction | Shell functions | Yes (defense in depth) |
| 3 | Human approval | TTY check | No (from non-interactive) |
| 4 | Sudo restrictions | Kernel | No (from userspace) |
| 5 | Network isolation | iptables/Docker | No (from container) |
| 6 | Block filesystem writes | Docker/kernel | No (from container) |

## Testing the Layers

### Test Layer 1 (Shell Overrides)

```bash
# Should block with message
rm -rf /
# Output: BLOCKED: rm -rf on protected path: /

git reset --hard
# Output: BLOCKED: git reset --hard requires operator approval
```

### Test Layer 3 (Operator Approval)

```bash
# Interactive (will prompt)
/opt/operator/bin/operator-approve echo "test"

# Non-interactive (will fail)
echo "test" | /opt/operator/bin/operator-approve echo "test"
```

### Test Layer 4 (Sudoers)

```bash
# Should work
sudo apt-get update

# Should fail (not in allowlist)
sudo rm /tmp/test
# Output: Sorry, user ubuntu is not allowed to execute '/bin/rm /tmp/test'
```

### Test Layer 6 (Read-only Root)

```bash
# Bypass Layer 1 and try to write
/bin/rm -rf /usr
# Output: rm: cannot remove '/usr/...': Read-only file system
```

## Next Steps

- [Threat Model](threat-model.md) - What we're protecting against
- [Architecture](../architecture.md) - System overview
