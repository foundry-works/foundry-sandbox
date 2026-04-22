# Security Model

This document defines the complete security model: **what threats exist**, **how each defense works**, and **hardening details** — organized by security pillar so each concept appears once.

## Trust Boundary Architecture

```
+-------------------+     +-------------------+
|   AI Assistant    |     |    Orchestrator   |
|   (untrusted)     |     |    (trusted)      |
+--------+----------+     +--------+----------+
         |                         |
         v                         v
+---------------------------+    +------------------------------+
|      SBX MICROVM          |    |         HOST                  |
|    (separate kernel)       |    |                               |
|                            |    |  foundry-git-safety           |
|  +--------------------+   |    |  ┌──────────────────────────┐ |
|  | Network Policy      |   |    |  │ Git API Server (:8083)  │ |
|  +--------------------+   |    |  │ Deep policy sidecar      │ |
|  +--------------------+   |    |  │ Policy enforcement       │ |
|  | .git hidden         |   |    |  └──────────────────────────┘ |
|  +--------------------+   |    |                               |
|  +--------------------+   |    |  sbx proxy (credential inject)|
|  | No real creds       |   |    |                               |
|  +--------------------+   |    |  [ALL CREDENTIALS stored on   |
|                            |    |   host, injected at network   |
|  gateway.docker.internal:3128   |   level by sbx proxy]        |
|  (all traffic via proxy)  |    |                               |
+---------------------------+    +------------------------------+
         |                                    |
         +------- via sbx proxy ------+-------+
                                     |
                              +------+------+
                              | External    |
                              | APIs        |
                              | (GitHub,    |
                              |  Anthropic, |
                              |  etc.)      |
                              +-------------+
```

## What We're Protecting

### Assets at Risk

| Asset | Risk Level | Protection |
|-------|------------|------------|
| Host filesystem | Critical | MicroVM isolation (separate kernel) |
| Git history | High | foundry-git-safety force-push blocking |
| Production credentials | High | sbx credential injection (never enter VM) |
| Other projects | Medium | Branch isolation (deny-by-default ref validation, output filtering) |
| System stability | Medium | sbx resource management |

### Threat Actors

The primary "threat actor" is not malicious - it's **AI coding assistants** that may:

1. **Hallucinate dangerous commands** - An AI might suggest `rm -rf /` or `git reset --hard` without understanding the consequences
2. **Act without full context** - The AI may not know it's in a sandbox vs. production
3. **Make honest mistakes** - Just like humans, but potentially faster and at scale
4. **Follow user instructions too literally** - "Clean up the repo" could be interpreted destructively

This is not about defending against intentional attacks. It's about providing safety limits for well-intentioned but error-prone automation.

---

## Quick Reference

### Pillar Summary

| Pillar | What It Blocks | What It Doesn't Block |
|--------|----------------|----------------------|
| **MicroVM Isolation** | Filesystem writes to host, kernel-level sandbox escape | Writes inside the sandbox VM (ephemeral) |
| **Network Policy** | Unauthorized egress, direct external access | Traffic to allowed domains (GitHub, AI APIs) |
| **Credential Injection** | Credential theft, API key exfiltration, env var scraping | Authorized API calls via sbx proxy |
| **Branch Isolation** | Cross-sandbox branch access, unauthorized ref checkout, branch listing leaks | Access to well-known branches (main, master, develop, etc.) and tags |
| **Git Safety** | Force pushes to protected branches, branch/tag deletion, dangerous GitHub API operations, PR merges, CI/CD pipeline modifications on push | Git operations on sandbox's own branch; commits/pushes to non-restricted files |

### Threat-to-Defense Matrix

| Threat | Primary Defense | Secondary Defense | Details |
|--------|-----------------|-------------------|---------|
| Filesystem destruction | MicroVM Isolation | Ephemeral VM state | [MicroVM Isolation](#microvm-isolation) |
| Local git destruction | Ephemeral worktree + git shadow mode | — | [Git Safety](#git-safety) |
| Remote git destruction | foundry-git-safety (force-push blocking) | — | [Git Safety](#git-safety) |
| Credential theft | Credential Injection (sbx) | Network Policy | [Credential Injection](#credential-injection) |
| Supply chain attacks | Credential Injection | Network Policy | [Credential Injection](#credential-injection) |
| Lateral movement | Network Policy (sbx) | MicroVM isolation | [Network Policy](#network-policy) |
| Cross-sandbox branch access | Branch Isolation | Output filtering | [Branch Isolation](#branch-isolation) |
| Git wrapper removal | Accepted risk | Template-based injection, monitoring | [Accepted Risks](#git-wrapper-removal) |

---

## Security Pillars

### MicroVM Isolation

**Enforced by:** Docker sbx (separate kernel per sandbox)

**Threats:** AI assistants execute bash commands that could delete files, overwrite history, or modify system state — `rm -rf /`, `git clean -f`, `sudo rm`.

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | MicroVM isolation | Separate kernel; sandbox cannot access host filesystem |
| Secondary | Ephemeral VM state | Changes inside VM don't persist across `sbx reset` |
| Tertiary | File sync boundary | Only workspace directory is synced between host and VM |

**How it differs from containers:**

| Aspect | Docker Container | sbx MicroVM |
|--------|-----------------|-------------|
| Kernel | Shared with host | Separate kernel per VM |
| Filesystem access | Bind mounts, potential escape | Workspace sync only |
| Network | Bridge/NAT, configurable | All traffic via `gateway.docker.internal:3128` |
| Escape difficulty | Container escape exploits | Requires VM escape (kernel-level) |
| Resource isolation | cgroups | Hypervisor-level |

**Bypass:** Requires a VM escape vulnerability (kernel-level exploit), which is significantly harder than container escape.

**Kernel-separation assertion:** `cast diagnose` verifies that each running sandbox has a different kernel from the host by comparing `uname -r` on both sides. If the kernels are identical, the sandbox may have fallen back to container mode (no kernel isolation), and the diagnose output reports a `WARN` status. Sandboxes with different kernels report `OK`. Per-sandbox failures (e.g., sandbox stopped) do not fail the overall diagnose run.

---

### Network Policy

**Enforced by:** Docker sbx (`sbx policy` commands)

**Threats:** Unauthorized network access, data exfiltration, access to internal services.

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | sbx network proxy | All traffic routed through `gateway.docker.internal:3128` |
| Secondary | Network policy profiles | Domain-level allow/deny rules |
| Tertiary | No direct host access | Sandboxes cannot reach arbitrary host ports |

**Network policy profiles:**

| Profile | Description | Use Case |
|---------|-------------|----------|
| `balanced` | Allow common dev domains (default) | Normal development |
| `allow-all` | No restrictions | Troubleshooting |
| `deny-all` | Block all external traffic | Maximum isolation |

**Default allowed domains (balanced profile):**
- GitHub (github.com, api.github.com)
- AI APIs (Anthropic, OpenAI, Google Gemini)

Additional domains via `sbx policy allow network <spec>`.

**Key constraint:** Sandboxes cannot reach arbitrary host ports. All host-bound traffic routes through the sbx HTTP proxy. The git safety server is accessible only through the proxy at `host.docker.internal:8083`.

**Bypass:** Cannot be bypassed from inside the sandbox. Requires host-level configuration changes.

**Testing:**

```bash
# From sandbox: verify network policy active
sbx policy status

# From sandbox: verify blocked domain (balanced mode)
curl -v https://example.com 2>&1 | grep -E "(Connection refused|timed out)"
# Expected: Connection failure
```

---

### Credential Injection

**Enforced by:** Docker sbx (host-side credential management)

**Threats:** Credential theft via environment variable scraping, filesystem search, memory scraping, or network interception. Supply chain attacks via malicious npm packages or Python libraries that attempt credential theft or data exfiltration.

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | sbx credential injection | Real credentials never enter VM |
| Secondary | Network Policy | Cannot exfiltrate to unauthorized destinations |
| UX | Credential Redaction | Masks secrets in command output |

**Implementation:** `sbx secret set -g <service>`

API keys are stored on the host via `sbx secret set -g` and injected into HTTP request headers by sbx's host-side proxy. The sandbox environment never contains real API keys. The `GH_TOKEN` variable is set to `proxy-managed` (a placeholder).

```
Host: sbx secret set -g anthropic  ← stores ANTHROPIC_API_KEY on host
Sandbox: agent makes API call      ← sbx proxy injects key into HTTP header
```

#### Credential Exposure Matrix

| Credential | Host (sbx) | Sandbox VM |
|------------|------------|------------|
| GITHUB_TOKEN / GH_TOKEN | Yes | `proxy-managed` (placeholder) |
| ANTHROPIC_API_KEY | Yes | Not set |
| OPENAI_API_KEY | Yes | Not set |
| Other API Keys | Yes | Not set |

The host holds all real credentials via sbx. Sandboxes never see real values.

**Bypass:** Cannot be bypassed without compromising the host system.

---

### Branch Isolation

**Enforced by:** `foundry-git-safety` server (branch_isolation module)

**Threats:** Cross-sandbox branch access — one sandbox accessing, modifying, or seeing another sandbox's branches.

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Deny-by-default ref validation | Git commands can only reference allowed branches |
| Secondary | SHA reachability | SHA args verified as ancestors of allowed branches |
| Tertiary | Output filtering | Branch listings hide other sandboxes' branches |
| Fail-safe | Missing metadata check | No branch identity = no git operations |

**Implementation:**

1. **Deny-by-default ref validation** — For commands that reference branches (checkout, switch, fetch, pull, merge, rebase, cherry-pick), the validator checks that all ref arguments are allowed: the sandbox's own branch, well-known branches (main, master, develop, production, release/*, hotfix/*), and tags
2. **SHA reachability enforcement** — SHA arguments are validated to ensure they are ancestors of allowed branches, preventing access to commits on other sandboxes' branches
3. **Output filtering** — Commands that list refs (`git branch`, `for-each-ref`, `ls-remote`, `show-ref`, `log --decorate`) have their output filtered to hide disallowed branches
4. **Fail-closed** — Sandboxes without branch identity metadata cannot execute git operations

---

### Git Safety

**Enforced by:** `foundry-git-safety` server (policies, security_policies modules)

**Threats:** Force push to protected branches, branch/tag deletion, PR merge (REST and GraphQL), CI/CD pipeline modification via pushed files.

**Defense layers (remote git destruction):**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Git API server (foundry-git-safety) | Blocks force pushes to protected branches, blocks all branch/tag deletions |
| Secondary | Protected branch enforcement | Blocks ALL direct pushes to main/master/release/production (not just force pushes) |

**Defense layers (PR merge prevention):**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Early-exit `is_merge_request()` | Unconditional check before any further processing |
| Secondary | GitHub API blocklist | Redundant fallback in `foundry-git-safety`'s deep policy sidecar (when enabled) |

Merge endpoints blocked: REST `PUT /repos/*/pulls/*/merge` and `*/auto-merge`, GraphQL `mergePullRequest` and `enablePullRequestAutoMerge` mutations.

**Defense layers (CI/CD pipeline protection):**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Push-time file validation | `check_push_files()` enumerates changed files and rejects pushes modifying blocked patterns |
| Secondary | Commit-time file validation | `check_file_restrictions()` on staged files gives early feedback before push |
| Tertiary | Path traversal prevention | Paths containing `..` after normalization are rejected |
| Fail-safe | Fail-closed on diff failure | If `git diff` fails, the push is rejected |

Blocked patterns are defined in `foundry.yaml` (e.g., `.github/workflows/`, `Makefile`). Warned patterns (e.g., `package.json`, `Dockerfile`) are logged or rejected depending on `warn_action` setting.

**Pattern semantics:**

| Pattern form | Matching behavior | Example |
|---|---|---|
| Ends with `/` | Directory prefix match — blocks any file under that directory | `.github/workflows/` blocks `.github/workflows/ci.yml` |
| Contains `*` or `?` | Glob match via `fnmatch` against both the basename and the full relative path | `requirements-*.txt` matches `requirements-dev.txt` at any depth |
| Bare name (no `/`, no glob) | Basename match — blocks any file at any depth with that exact name | `Makefile` blocks `Makefile` and `subdir/Makefile` |

See [Configuration: Push File Restrictions](../configuration.md#push-file-restrictions) for the YAML format.

#### Git Shadow Mode

All git operations from sandboxes are proxied through the `foundry-git-safety` server on the host. The sandbox does not have direct access to the git repository.

**How it works:**

1. **Git wrapper intercepts commands** — `foundry_sandbox/assets/git-wrapper-sbx.sh` is installed at `/usr/local/bin/git`, taking precedence over `/usr/bin/git`. For any git command under the workspace, the wrapper proxies the request to the git safety server
2. **HMAC-SHA256 authentication** — Each request is signed with a per-sandbox HMAC secret (64 hex chars). The signature covers the HTTP method, path, request body hash, timestamp, and a random nonce to prevent replay attacks
3. **Policy enforcement** — Before executing any command, the git API applies policy checks: command allowlist validation, branch isolation, protected branch enforcement, file restriction checks, and rate limiting
4. **Network routing** — The wrapper sends requests through the sbx HTTP proxy (`gateway.docker.internal:3128`) to `host.docker.internal:8083`

**What the server enforces:**

| Policy | Effect |
|--------|--------|
| HMAC authentication | Rejects unauthenticated requests |
| Command allowlist | Only explicitly allowed git commands run |
| Branch deletion blocking | `git push` that would delete any branch or tag is rejected |
| Force-push blocking | Non-fast-forward pushes to protected branches are rejected |
| File restriction check | Pushes modifying blocked file patterns are rejected |
| Rate limiting | Per-sandbox burst and sustained rate limits |

**Hardening — input validation:**

- **Path normalization:** URL paths are normalized before any policy check
- **Regex fullmatch:** Pattern matching uses `re.fullmatch()` to prevent partial-match bypass
- **Git identity sanitization:** Git user names and emails are sanitized to remove control characters
- **Diff argument order:** `git diff` arguments use explicit `--` separator and controlled ordering to prevent argument injection

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

### Credential Redaction (UX convenience)

> **Note:** This is a helpful warning, **not a security control**. It can be trivially bypassed and should not be relied upon for security.

Masks secrets and sensitive values in command output to reduce accidental exposure. Real credential protection requires sbx credential injection.

---

## Explicit Non-Goals and Accepted Risks

The following are explicitly outside our threat model.

### Intentional Human Actions

If a human intentionally wants to destroy data, they can use `sbx exec --user root` to modify the sandbox, remove the sandbox directory from the host, or disable git safety.

**Rationale:** This isn't a security product protecting against malicious users. It's a safety net for AI-assisted development. The human operator is trusted.

### MicroVM Escape Vulnerabilities

If an attacker exploits a hypervisor or kernel vulnerability to escape the microVM, sandbox protections don't help.

**Rationale:** We rely on sbx's security model. VM escape is an infrastructure-level concern outside this implementation's scope. MicroVM isolation provides stronger boundaries than containers.

### Authorized Network Traffic

Sandboxes can send data to allowed services (GitHub, AI APIs). A compromised sandbox could push malicious code to an authorized repository, send data to AI APIs, or download malicious packages.

**Rationale:** Network policy blocks unauthorized destinations. For authorized services, the trust model assumes the sandbox is doing legitimate development work. Repository-level protections (branch protection, code review) provide the next layer of defense.

### Git Wrapper Removal

The agent has root access inside the microVM and can remove `/usr/local/bin/git`, falling back to the unrestricted `/usr/bin/git`.

**Mitigations:**
1. Build the wrapper into a custom sbx template (`cast preset save` or `sbx template save`) so it persists across resets
2. Monitor wrapper presence and re-inject if removed
3. Accepted as documented risk in the threat model

See [Phase 0 Report](../sbx-phase0-report.md#agent-removal-resistance) for validation details.

### Git Safety Server State

Rate limiters, nonce replay stores, and sandbox registrations are stored in memory and on the host filesystem. A compromised host could modify these.

**Mitigations:**
- HMAC secrets are stored with mode 0600 (owner-only)
- Sandbox registration files are validated on each request
- The git safety server runs as a non-privileged process

### Proxy-Side Attack Surface

The git safety server runs `git` subprocesses on untrusted input from sandboxes. A memory-safety bug in git could allow code execution on the host.

**Mitigations:**

| # | Control | Effect |
|---|---------|--------|
| 1 | Pack size bounded (100MB) | Limits attack surface to bounded input |
| 2 | Subprocess timeout | Kills hung or exploited git processes |
| 3 | Minimal subprocess environment | Git subprocesses run with a stripped environment |
| 4 | Fail-closed on any error | Parse failures, timeouts, or unexpected exit codes all reject the operation |

### Attack Scenarios

| Scenario | Attack | Outcome |
|----------|--------|---------|
| **Supply chain** (malicious npm package) | Package reads env vars, attempts direct HTTPS, DNS exfiltration | Gets nothing useful — no real credentials in VM; all traffic routed through sbx proxy |
| **AI token probing** | AI-generated code searches filesystem and memory for tokens | Finds nothing — real credentials never enter the VM |
| **Lateral movement** | Compromised sandbox attempts to reach host services | Blocked — all traffic routed through sbx proxy; no direct host access |
| **Git wrapper removal** | Agent removes `/usr/local/bin/git` | Falls back to unrestricted `/usr/bin/git`; mitigated by template-based injection and monitoring |

---

## Design Principles

1. **Fail safe** - When in doubt, block the operation
2. **Prefer UX** - Friendly messages over cryptic errors
3. **Assume good intent** - Protect against accidents, not attacks
4. **Minimize friction** - Safe operations should "just work"
5. **Recoverability** - Destroying and recreating sandboxes is cheap

## Security Assumptions

This security model assumes:

1. **sbx is trusted** — MicroVM escape vulnerabilities are out of scope
2. **Host is secure** — Host-level security is a prerequisite
3. **foundry-git-safety is trusted** — The git safety server runs on the host as a trusted component

If any of these assumptions are violated, the security properties may not hold.

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers
3. Include steps to reproduce and potential impact
4. Allow time for a fix before public disclosure

---

## Summary Table

| Control | Enforced By | Bypassable? | Purpose |
|---------|-------------|-------------|---------|
| MicroVM isolation | sbx / Docker | No (from sandbox) | Separate kernel, host filesystem protection |
| Network policy | sbx proxy | No (from sandbox) | Control network egress |
| Credential injection | sbx secrets | No (without host compromise) | Protect credentials |
| Branch isolation | foundry-git-safety | No (from sandbox) | Prevent cross-sandbox git access |
| Git safety | foundry-git-safety | No (from sandbox) | Protected branches, force-push blocking, API controls |
| Git wrapper | File-based injection | **Yes** (agent can remove) | Intercept git operations for policy enforcement |
| Credential redaction | Shell functions | **Yes** | Reduce accidental exposure |

## Testing

Security measures are covered by:

- **Unit tests** — `foundry-git-safety/tests/unit/` (619 tests across 15 files)
- **Integration tests** — `foundry-git-safety/tests/integration/` (46 tests)
- **Security invariant tests** — `foundry-git-safety/tests/security/` (41 tests)
- **Red team modules** — `tests/redteam/` (9 active modules):
  - Credential isolation: env scanning (01), file scanning (02), credential patterns (13)
  - Git safety: hooks/shadow/wrapper (09), GitHub API deep-policy (11), self-merge prevention (15), workflow push blocking (17), early-exit merge blocking (19)
  - Package installation: pip/npm boundary testing (20)
- **Chaos modules** — `tests/chaos/` (4 modules): daemon kill, server kill, network partition, corrupted reset

Note: 7 compose-era redteam modules were retired in 0.21.0 (DNS filtering, proxy egress, network isolation, IP encoding bypass, proxy admin, container escape, TLS/filesystem). 4 modules are deferred pending live sbx validation (see `tests/redteam/README.md`).

### Manual Verification

**Network policy:**

```bash
# Check sbx policy status
sbx policy status

# From sandbox: verify blocked domain
curl -v https://example.com 2>&1 | grep -E "(Connection refused|timed out)"
# Expected: Connection failure
```

**Credential isolation:**

```bash
# From sandbox: verify real credentials not exposed
env | grep -i anthropic  # Should return nothing
echo $GH_TOKEN  # Should be "proxy-managed" or empty
```

**Git safety:**

```bash
# From host: verify git safety server running
foundry-git-safety status

# From host: verify sandbox registered
ls /var/lib/foundry-git-safety/sandboxes/

# From sandbox: verify git wrapper active
which git  # Should return /usr/local/bin/git
```

**Git wrapper presence:**

```bash
# From host: verify wrapper installed in sandbox
sbx exec <name> -- head -1 /usr/local/bin/git
# Expected: "#!/usr/bin/env bash" (wrapper header)
```

## See Also

- [Architecture](../architecture.md) — System design and component interactions
- [Configuration](../configuration.md) — `foundry.yaml` configuration
- [ADR-008: sbx Migration](../adr/008-sbx-migration.md) — Decision record
