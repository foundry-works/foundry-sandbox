# Threat Model

This document defines what Foundry Sandbox protects against, why these protections exist, and how they're implemented.

## What We're Protecting

### Assets at Risk

| Asset | Risk Level | Protection |
|-------|------------|------------|
| Host filesystem | Critical | Read-only root, container isolation |
| Git history | High | Shell overrides block destructive commands |
| Production credentials | High | Sandboxes don't have access by default |
| Other projects | Medium | Sandboxes are isolated from each other |
| System stability | Medium | Resource limits, no root access |

### Threat Actors

The primary "threat actor" is not malicious - it's **AI coding assistants** that may:

1. **Hallucinate dangerous commands** - An AI might suggest `rm -rf /` or `git reset --hard` without understanding the consequences
2. **Act without full context** - The AI may not know it's in a sandbox vs. production
3. **Make honest mistakes** - Just like humans, but potentially faster and at scale
4. **Follow user instructions too literally** - "Clean up the repo" could be interpreted destructively

This is not about defending against intentional attacks. It's about providing guardrails for well-intentioned but error-prone automation.

## Attack Surfaces

### 1. Bash Command Execution

AI assistants execute bash commands. Any command the AI runs could potentially:
- Delete files (`rm`, `git clean`)
- Overwrite history (`git reset --hard`, `git push --force`)
- Modify system state (`sudo rm`, package removal)

**Mitigation:** Defense in depth (shell overrides, operator approval, sudoers allowlist, network isolation, read-only root)

### 2. Git Operations

Git commands can destroy work:
- `git reset --hard` - Discards uncommitted changes
- `git clean -f` - Deletes untracked files
- `git push --force` - Overwrites remote history (affects collaborators)

**Mitigation:** Shell function overrides intercept these patterns with friendly warnings

### 3. Sudo Escalation

If the AI gains sudo access, it could bypass container restrictions:
- `sudo rm -rf /` - Delete everything writable
- `sudo chmod` - Modify file permissions
- Install malicious packages

**Mitigation:** Strict sudoers allowlist permits only safe commands (apt-get install, service management)

### 4. Container Escape

Theoretical: AI exploits Docker vulnerability to access host system.

**Mitigation:** We rely on Docker's security model. This is outside our threat model - if Docker is compromised, sandbox protections don't help.

## Why These Protections?

### Mistake Recovery Should Be Easy

When an AI makes a mistake (it will), recovery should be:
- **Obvious** - Clear error messages explain what happened
- **Reversible** - Worktrees can be destroyed and recreated
- **Contained** - Damage limited to the sandbox

### Defense in Depth

No single layer is foolproof:

```
AI Command
    │
    ▼
Layer 1: Shell Override ─────┐
    │                        │ (can be bypassed
    ▼                        │  with /bin/rm)
Layer 2: Operator Approval ──┤
    │                        │ (human must be
    ▼                        │  present)
Layer 3: Sudoers Allowlist ──┤
    │                        │ (kernel enforced,
    ▼                        │  cannot bypass)
Layer 4: Network Isolation ──┤
    │                        │ (iptables/Docker,
    ▼                        │  optional)
Layer 0: Read-only Root ─────┘
    │                        │ (filesystem level,
    ▼                        │  cannot bypass)
  ALLOWED or DENIED
```

Each layer catches what the previous layer might miss.

### UX Over Security Theater

Layer 1 (shell overrides) is explicitly **not a security boundary**. It can be bypassed by:

```bash
/bin/rm -rf /          # Direct path
command rm -rf /       # Builtin bypass
\rm -rf /              # Escape character
env rm -rf /           # Environment bypass
```

We keep it because:
1. It catches **accidental** use of dangerous commands
2. It provides **helpful error messages** to the AI
3. The AI is unlikely to intentionally bypass it

The real security comes from Layers 2 and 3, plus the read-only filesystem.

## What We Don't Protect Against (By Default)

### Network Access

By default, sandboxes use limited network access (whitelist only). You can change the mode using the `--network` flag:

```bash
# Limited to whitelist (default)
cast new owner/repo feature

# Local network only (Docker gateway, private subnets)
cast new owner/repo feature --network=host-only

# No network at all
cast new owner/repo feature --network=none
```

The limited mode restricts network access to essential services (github, npm, pypi, AI APIs) while blocking all other outbound connections. To allow additional domains, set `SANDBOX_ALLOWED_DOMAINS` on the host before creating the sandbox.

**Recommendation:** Use the default `--network=limited` mode for all development to restrict access to only necessary services while still allowing git push, npm install, and AI API calls.

### Malicious Users

If a human intentionally wants to destroy data, they can:
- `docker exec` into the container with root
- Remove the sandbox directory from the host
- Use operator approval to allow dangerous commands

**Rationale:** This isn't a security product. It's a safety net for AI-assisted development.

### Credential Theft

If API keys are passed into the sandbox, the AI can read and use them. We don't prevent:
- Reading environment variables
- Exfiltrating credentials over the network

**Rationale:** API keys are required for AI tools to function. Users should use scoped tokens where possible.

## Design Principles

1. **Fail safe** - When in doubt, block the operation
2. **Prefer UX** - Friendly messages over cryptic errors
3. **Assume good intent** - Protect against accidents, not attacks
4. **Minimize friction** - Safe operations should "just work"
5. **Recoverability** - Destroying and recreating sandboxes is cheap

## Next Steps

- [Safety Layers](safety-layers.md) - Implementation details for each layer
- [Architecture](../architecture.md) - How the system fits together
