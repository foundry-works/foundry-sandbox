# Threat Model

This document defines what Foundry Sandbox protects against, why these protections exist, and how they're implemented.

## Documentation Map

| If you want to... | See... |
|-------------------|--------|
| Understand what threats exist and how they're addressed | This document |
| Learn how each security pillar works | [Security Architecture](security-architecture.md) |
| Understand credential isolation in depth | [Credential Isolation](credential-isolation.md) |
| Configure network modes and domains | [Network Isolation](network-isolation.md) |
| Get a quick security overview | [Security Overview](index.md) |

---

## What We're Protecting

### Assets at Risk

| Asset | Risk Level | Protection |
|-------|------------|------------|
| Host filesystem | Critical | Read-only root, container isolation |
| Git history | High | Read-only filesystem, gateway force-push blocking |
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

---

## Security Pillar Quick Reference

Each pillar blocks specific threat categories. For implementation details, see [Security Architecture](security-architecture.md).

| Pillar | What It Blocks | What It Doesn't Block |
|--------|----------------|----------------------|
| **Read-only Filesystem** | Filesystem writes, system modification, persistent malware | Writes to tmpfs mounts (/tmp, /home/ubuntu) |
| **Network Isolation** | Unauthorized egress, direct external access, DNS exfiltration | Traffic to allowed domains (GitHub, AI APIs) |
| **Sudoers Allowlist** | Arbitrary sudo commands, privilege escalation | Allowed commands (apt-get install, service management) |
| **Credential Isolation** | Credential theft, API key exfiltration, env var scraping | Authorized API calls via proxy |
| **CAP_NET_RAW Dropped** | IP spoofing, ARP poisoning, raw packet sniffing, L2 attacks | Normal TCP/UDP networking |

---

## Threat Landscape

### Threat-to-Defense Matrix

| Threat | Primary Defense | Secondary Defense | Details |
|--------|-----------------|-------------------|---------|
| Filesystem destruction | Read-only Filesystem | Sudoers Allowlist | [Filesystem Threats](#1-filesystem-destruction) |
| Local git destruction | Read-only Worktree | Shell Overrides (UX) | [Git Threats](#2-git-operations) |
| Remote git destruction | Gateway (force-push blocking) | Shell Overrides (UX) | [Git Threats](#2-git-operations) |
| Credential theft | Credential Isolation | Network Isolation | [Credential Threats](#3-credential-theft) |
| Supply chain attacks | Credential Isolation | Network + CAP_NET_RAW | [Supply Chain](#4-supply-chain-attacks) |
| Lateral movement | Network (ICC=false) | CAP_NET_RAW dropped | [Lateral Movement](#5-lateral-movement) |
| Session hijacking | IP binding | CAP_NET_RAW dropped | [Session Attacks](#6-session-token-attacks) |
| DNS exfiltration | Network (dnsmasq) | Domain allowlist | [DNS Exfiltration](#7-dns-exfiltration) |
| Sudo escalation | Sudoers Allowlist | Read-only Filesystem | [Sudo Escalation](#8-sudo-escalation) |

---

### 1. Filesystem Destruction

AI assistants execute bash commands. Any command the AI runs could potentially delete files, overwrite history, or modify system state.

**Attack Vectors:**
- `rm -rf /` or `rm -rf .`
- `git clean -f` - Deletes untracked files
- `sudo rm` - Bypasses user permissions

**Defense Layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Read-only Filesystem | All writes fail with "Read-only file system" error |
| Secondary | Sudoers Allowlist | `sudo rm` is not permitted |
| UX | Shell Overrides | Friendly "BLOCKED" messages for `rm` commands |

**Why This Works:** Even if the AI bypasses shell overrides (via `/bin/rm` or `command rm`), the read-only filesystem stops all writes. See [Read-only Filesystem](security-architecture.md#read-only-filesystem) for implementation.

---

### 2. Git Operations

Git commands can destroy work that may be unrecoverable. We distinguish between **local** destruction (affects your worktree) and **remote** destruction (affects collaborators).

**Attack Vectors:**

| Attack | Scope | Impact |
|--------|-------|--------|
| `git reset --hard` | Local | Discards uncommitted changes |
| `git clean -f` | Local | Deletes untracked files |
| `git checkout -- <file>` | Local | Discards file changes |
| `git push --force` | Remote | Overwrites remote history (affects collaborators) |

**Defense Layers:**

*Local git destruction:*

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Read-only Worktree | Worktree files cannot be modified—`git reset --hard` silently fails |
| UX | Shell Overrides | Intercepts patterns with friendly warnings (bypassable) |

*Remote git destruction:*

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Gateway | Can reject force pushes based on policy |
| UX | Shell Overrides | Intercepts `git push --force` patterns (bypassable) |

**Why This Works:** For local destruction, the read-only filesystem is the actual security control—even if shell overrides are bypassed (via `/usr/bin/git` or `command git`), writes fail. For remote destruction, the gateway can enforce force-push blocking. Shell overrides are explicitly [not a security boundary](security-architecture.md#shell-overrides)—they provide helpful UX but can be trivially bypassed. See [Read-only Filesystem](security-architecture.md#read-only-filesystem) for implementation details.

---

### 3. Credential Theft

A compromised sandbox could attempt to steal credentials and exfiltrate them.

**Attack Vectors:**
- Reading environment variables (`$GITHUB_TOKEN`, `$ANTHROPIC_API_KEY`)
- Searching filesystem for `.env` files or config with secrets
- Memory scraping of processes
- Intercepting network traffic to capture credentials in transit

**Defense Layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Credential Isolation | Real credentials never enter sandbox |
| Secondary | Network Isolation | Cannot exfiltrate to unauthorized destinations |
| UX | Credential Redaction | Masks secrets in command output |

**Why This Works:** Sandboxes receive placeholder values (`CREDENTIAL_PROXY_PLACEHOLDER`) instead of real API keys. The gateway/proxy containers hold real credentials and inject them into outbound requests. Even if code reads the environment, it gets nothing useful. See [Credential Isolation](credential-isolation.md) for the complete architecture.

---

### 4. Supply Chain Attacks

Malicious npm packages, Python libraries, or other dependencies may contain code that attempts credential theft or data exfiltration.

**Attack Vectors:**
- Package postinstall scripts that read environment variables
- Dependencies that phone home with system information
- Typosquatting packages with malicious payloads
- Compromised maintainer accounts pushing malicious updates

**Defense Layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Credential Isolation | Package reads placeholder values, not real credentials |
| Secondary | Network Isolation | Cannot exfiltrate to unauthorized domains |
| Tertiary | CAP_NET_RAW dropped | Cannot use raw sockets to bypass network controls |

**Why This Works:** When a malicious package runs `process.env.ANTHROPIC_API_KEY`, it gets `CREDENTIAL_PROXY_PLACEHOLDER`. When it tries to send this to `evil.com`, network isolation blocks the request. Even if it attempts raw packet crafting to bypass network rules, CAP_NET_RAW is dropped. See [Supply Chain Attack Scenario](credential-isolation.md#scenario-1-malicious-npm-package-in-sandbox-supply-chain-attack) in the credential isolation threat model for a detailed walkthrough.

---

### 5. Lateral Movement

One compromised sandbox could attempt to attack or access another sandbox running on the same host.

**Attack Vectors:**
- Direct container-to-container network connections
- ARP spoofing to intercept traffic meant for other containers
- IP spoofing to impersonate another container
- DNS rebinding to redirect traffic

**Defense Layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | ICC=false | Docker blocks L3/L4 traffic between containers |
| Secondary | CAP_NET_RAW dropped | Cannot create raw sockets for L2 attacks |
| Tertiary | IP binding | Sessions bound to originating container IP |

**Why This Works:** Docker's ICC (Inter-Container Communication) setting blocks TCP/UDP between containers at the network layer. However, ICC doesn't block Layer 2 (Ethernet) traffic. Dropping CAP_NET_RAW prevents creation of raw sockets needed for ARP spoofing or packet crafting. See [Lateral Movement Scenario](credential-isolation.md#scenario-3-compromised-container-attempts-lateral-movement) in the credential isolation threat model for details.

---

### 6. Session Token Attacks

Attackers could attempt to steal session tokens and use them from other locations.

**Attack Vectors:**
- Reading session token from `/run/secrets/gateway_token`
- Network sniffing to capture tokens in transit
- IP spoofing to bypass session IP binding
- Waiting for session reuse from different context

**Defense Layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | IP binding | Sessions only valid from originating container IP |
| Secondary | CAP_NET_RAW dropped | Cannot spoof source IP addresses |
| Tertiary | TTL expiration | Sessions expire after 24h inactivity, 7d absolute |
| Network | ICC=false | Cannot access other containers to reuse their sessions |

**Why This Works:** Even if an attacker obtains a session token, it's bound to the container's IP address. Using it from another location fails validation. IP spoofing would require CAP_NET_RAW, which is dropped. See [Session Token Scenario](credential-isolation.md#scenario-4-session-token-theft-and-reuse) in the credential isolation threat model for the complete analysis.

---

### 7. DNS Exfiltration

Data can be encoded in DNS queries and sent to attacker-controlled nameservers.

**Attack Vectors:**
- Encoding data in DNS subdomains: `secret-data.evil.com`
- Using DNS TXT records for bidirectional communication
- Leveraging DNS-over-HTTPS to bypass monitoring

**Defense Layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | dnsmasq | All DNS routed through gateway |
| Secondary | Domain allowlist | Only allowed domains resolve |
| Tertiary | Internal network | No direct access to external DNS servers |

**Why This Works:** The gateway runs dnsmasq which intercepts all DNS queries. Only domains on the allowlist resolve. Attempts to query `evil.com` return NXDOMAIN. Direct access to external DNS (8.8.8.8) is blocked by network isolation. See [Network Isolation](network-isolation.md) for configuration.

---

### 8. Sudo Escalation

If the AI gains unrestricted sudo access, it could bypass container restrictions.

**Attack Vectors:**
- `sudo rm -rf /` - Delete everything writable
- `sudo chmod` - Modify file permissions
- `sudo apt-get remove` - Remove security tooling
- Installing malicious packages with elevated privileges

**Defense Layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Sudoers Allowlist | Only whitelisted commands permitted |
| Secondary | Read-only Filesystem | Even with sudo, can't write to read-only mounts |

**Why This Works:** The sudoers allowlist permits only safe commands (`sudo apt-get install *`, `sudo service * start/stop/restart/status`). There's no fallback `PASSWD:ALL` line. Even if a command were somehow permitted, the read-only filesystem would block destructive writes. See [Sudoers Allowlist](security-architecture.md#sudoers-allowlist) for the implementation.

---

## Why These Protections?

### Mistake Recovery Should Be Easy

When an AI makes a mistake (it will), recovery should be:
- **Obvious** - Clear error messages explain what happened
- **Reversible** - Worktrees can be destroyed and recreated
- **Contained** - Damage limited to the sandbox

### Defense in Depth

No single control is sufficient. Security comes from multiple overlapping layers:

1. **Credential Isolation** ensures secrets never enter the sandbox
2. **Network Isolation** blocks unauthorized egress even if code tries to exfiltrate
3. **Read-only Filesystem** prevents persistent damage even if commands execute
4. **Sudoers Allowlist** restricts privilege escalation even for allowed sudo use
5. **CAP_NET_RAW dropped** closes Layer 2 attack vectors that bypass higher-level controls

Each layer catches what others might miss. See [Security Architecture](security-architecture.md) for the complete model.

### UX Over Security Theater

Shell overrides (Layer 1) are explicitly **not a security boundary**. They can be bypassed by:

```bash
/bin/rm -rf /          # Direct path
command rm -rf /       # Builtin bypass
\rm -rf /              # Escape character
env rm -rf /           # Environment bypass
```

We keep them because:
1. They catch **accidental** use of dangerous commands
2. They provide **helpful error messages** to the AI
3. The AI is unlikely to intentionally bypass them

The real security comes from the pillars (read-only filesystem, network isolation, credential isolation, sudoers allowlist).

---

## Explicit Non-Goals and Accepted Risks

The following are explicitly outside our threat model.

### Intentional Human Actions

If a human intentionally wants to destroy data, they can:
- `docker exec` into the container with root
- Remove the sandbox directory from the host
- Use operator approval to allow dangerous commands
- Modify `docker-compose.yml` to disable protections

**Rationale:** This isn't a security product protecting against malicious users. It's a safety net for AI-assisted development. The human operator is trusted.

### Container Escape Vulnerabilities

If an attacker exploits a Docker or kernel vulnerability to escape the container, sandbox protections don't help.

**Rationale:** We rely on Docker's security model. Container escape is an infrastructure-level concern outside this implementation's scope. Mitigation is through infrastructure patching and host hardening.

### Authorized Network Traffic

Sandboxes can send data to allowed services (GitHub, AI APIs). A compromised sandbox could:
- Push malicious code to an authorized repository
- Send data to AI APIs (within rate limits)
- Download packages that may be malicious

**Rationale:** Network isolation blocks unauthorized destinations. For authorized services, the trust model assumes the sandbox is doing legitimate development work. Repository-level protections (branch protection, code review) provide the next layer of defense.

### Disabled Credential Isolation

If credential isolation is disabled (`--no-isolate-credentials`), the AI can read real environment variables containing credentials.

**Rationale:** Credential isolation is opt-out for compatibility. When disabled, the user accepts that credentials may be exposed. See [Credential Isolation](credential-isolation.md) for why you should keep it enabled.

---

## Design Principles

1. **Fail safe** - When in doubt, block the operation
2. **Prefer UX** - Friendly messages over cryptic errors
3. **Assume good intent** - Protect against accidents, not attacks
4. **Minimize friction** - Safe operations should "just work"
5. **Recoverability** - Destroying and recreating sandboxes is cheap

---

## Next Steps

- [Security Architecture](security-architecture.md) - Security pillars and defense layers
- [Credential Isolation](credential-isolation.md) - Gateway architecture and threat model
- [Network Isolation](network-isolation.md) - Network modes and configuration
- [Security Overview](index.md) - Security architecture quick reference
