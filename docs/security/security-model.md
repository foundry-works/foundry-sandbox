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
|    SANDBOX CONTAINER      |    |    UNIFIED PROXY CONTAINER   |
|                           |    |    (separate container)      |
|  +--------------------+   |    |                              |
|  | Network Isolation  |   |    |  [ALL CREDENTIALS:          |
|  +--------------------+   |    |   GITHUB_TOKEN, API_KEYS]   |
|  +--------------------+   |    |                              |
|  | .git hidden        |   |    |  • Credential injection     |
|  +--------------------+   |    |  • Git API server (:8083)   |
|  +--------------------+   |    |  • DNS filter (mitmproxy)   |
|  | No real creds      |   |    |  • Policy engine            |
|  +--------------------+   |    |                              |
|                           |    +-------------+----------------+
| credential-isolation net ◄├────┤             |
+---------------------------+    |             v
                                 |    +-------------------+
                                 |    |  External APIs    |
                                 |    |  (GitHub, etc)    |
                                 |    +-------------------+
                                 |    proxy-egress network
                                 +-----------------------------+
```

## What We're Protecting

### Assets at Risk

| Asset | Risk Level | Protection |
|-------|------------|------------|
| Host filesystem | Critical | Read-only root, container isolation |
| Git history | High | Read-only filesystem, unified-proxy force-push blocking |
| Production credentials | High | Sandboxes don't have access by default |
| Other projects | Medium | Branch isolation (deny-by-default ref validation, output filtering), separate Docker networks |
| System stability | Medium | Resource limits, no root access |

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
| **Read-only Filesystem** | Filesystem writes, system modification, persistent malware | Writes to tmpfs mounts (/tmp, /home/ubuntu) |
| **Network Isolation** | Unauthorized egress, direct external access, DNS exfiltration, IP spoofing/ARP poisoning (CAP_NET_RAW dropped), direct-IP requests (all encodings blocked) | Traffic to allowed domains (GitHub, AI APIs); normal TCP/UDP networking |
| **Sudoers Allowlist** | Arbitrary sudo commands, privilege escalation | Allowed commands (apt-get install, service management) |
| **Credential Isolation** | Credential theft, API key exfiltration, env var scraping | Authorized API calls via gateway/proxy |
| **Branch Isolation** | Cross-sandbox branch access, unauthorized ref checkout, branch listing leaks | Access to well-known branches (main, master, develop, etc.) and tags |
| **Git Safety** | Force pushes to protected branches, branch/tag deletion, dangerous GitHub API operations, PR merges (REST and GraphQL), CI/CD pipeline modifications on push | Git operations on sandbox's own branch; commits/pushes to non-restricted files |

### Threat-to-Defense Matrix

| Threat | Primary Defense | Secondary Defense | Details |
|--------|-----------------|-------------------|---------|
| Filesystem destruction | Read-only Filesystem | Sudoers Allowlist | [Read-only Filesystem](#read-only-filesystem) |
| Local git destruction | Ephemeral worktree + git shadow mode | — | [Git Safety](#git-safety) |
| Remote git destruction | Unified proxy (force-push blocking) | — | [Git Safety](#git-safety) |
| Credential theft | Credential Isolation | Network Isolation | [Credential Isolation](#credential-isolation) |
| Supply chain attacks | Credential Isolation | Network + CAP_NET_RAW | [Credential Isolation](#credential-isolation) |
| Lateral movement | Network (ICC=false) | CAP_NET_RAW dropped | [Network Isolation](#network-isolation) |
| Cross-sandbox branch access | Branch Isolation | Output filtering | [Branch Isolation](#branch-isolation) |
| Session hijacking | IP binding | CAP_NET_RAW dropped | [Credential Isolation](#credential-isolation) |
| DNS exfiltration | Network (DNS filter) | Domain allowlist | [Network Isolation](#network-isolation) |
| Sudo escalation | Sudoers Allowlist | Read-only Filesystem | [Sudoers Allowlist](#sudoers-allowlist) |
| IP encoding bypass (SSRF) | IP literal detection (regex + inet_aton) | Domain allowlist | [Network Isolation](#network-isolation) |
| PR merge (REST + GraphQL) | Early-exit merge blocking | GitHub API blocklist (defense-in-depth) | [Git Safety](#git-safety) |
| CI/CD pipeline modification | Push-time file validation | Commit-time file validation | [Git Safety](#git-safety) |
| Proxy pack parsing exploit | Pack size limit + timeout | Fail-closed, isolated tempdir | [Accepted Risks](#proxy-side-attack-surface) |

---

## Security Pillars

### Read-only Filesystem

**Enforced by:** Docker (`read_only: true`)

**Threats:** AI assistants execute bash commands that could delete files, overwrite history, or modify system state — `rm -rf /`, `git clean -f`, `sudo rm`.

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Read-only Filesystem | All writes fail with "Read-only file system" error |
| Secondary | Sudoers Allowlist | `sudo rm` is not permitted |

**Implementation:**

`docker-compose.yml` (base) sets `read_only: true`. Credential isolation mode inherits this from the base compose file. DNS configuration is handled at compose level via `dns:` and `extra_hosts:` directives (Docker 29+ makes `/etc/resolv.conf` read-only). The root entrypoint (`entrypoint-root.sh`) only configures iptables DNS firewall rules and drops privileges via `gosu` — it does not need a writable root filesystem.

Additional protections:
- Non-root user (uid 1000 via gosu) after iptables setup
- Network isolation (`internal: true`) prevents data exfiltration
- Tmpfs `/home` means writes don't persist across restarts
- The worktree `/workspace/.git` is hidden via `/dev/null` bind mount + tmpfs overlay

**Tmpfs exceptions (writable):**
- `/tmp` - Temporary files
- `/var/tmp` - More temporary files
- `/run` - Runtime state
- `/var/cache/apt` - Package cache
- `/home/ubuntu` - User home (ephemeral, resets on restart)

**Hardening — symlink boundary checks:** File operations that reference paths within the workspace or sandbox directories validate that the resolved path (after symlink resolution) stays within the expected boundary. This prevents symlink-based traversal where a sandbox creates a symlink pointing outside its workspace.

**Bypass:** Cannot be bypassed from inside the container in base mode. In credential isolation mode, writes to non-tmpfs paths are possible but mitigated by non-root user and network isolation.

**Testing:**

```bash
# Attempt direct write
/bin/rm -rf /usr
# Expected: "Read-only file system" error

# Verify tmpfs is writable
touch /tmp/test && rm /tmp/test
# Expected: Success
```

---

### Network Isolation

**Enforced by:** Docker networking + mitmproxy DNS addon + iptables

**Threats:** Lateral movement between containers, DNS exfiltration, IP encoding bypass (SSRF).

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary (lateral movement) | ICC=false | Docker blocks L3/L4 traffic between containers |
| Primary (DNS exfiltration) | DNS filter | All DNS routed through unified-proxy |
| Secondary | CAP_NET_RAW dropped | Cannot create raw sockets for L2 attacks |
| Tertiary | IP binding | Sessions bound to originating container IP |
| Tertiary | Domain allowlist | Only allowed domains resolve |
| Quaternary | Internal network | No direct access to external DNS servers |

**Implementation:**

- Internal Docker network (`internal: true`) — no default gateway
- ICC (inter-container communication) disabled
- DNS routed through unified-proxy (enabled by default)
- iptables rules as an additional filtering layer (`safety/network-firewall.sh`, `safety/network-mode`)

**Network modes:**

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

**Hardening — IP literal detection:** All forms of IP address encoding in hostnames are blocked before domain allowlist evaluation:

| Encoding | Example | Detection |
|---|---|---|
| Dotted decimal | `1.2.3.4` | Regex |
| IPv6 brackets | `[::1]` | Regex |
| Octal | `0177.0.0.1` | Regex |
| Hexadecimal | `0x7f000001` | Regex |
| Integer | `2130706433` | Regex |
| Mixed | `0x7f.0.0.01` | `socket.inet_aton()` fallback |

Detection is implemented in the policy engine's `is_ip_literal()` function and duplicated in Squid ACLs for defense-in-depth.

**Hardening — circuit breaker (fail-closed):** The circuit breaker transitions to OPEN state when upstream error rate exceeds the threshold. In OPEN state, requests are rejected with a JSON error response rather than being forwarded — an unhealthy upstream does not cause requests to bypass the proxy.

**Bypass:** Cannot be bypassed from inside the container. Requires host-level network configuration changes.

**Testing:**

```bash
# Check current mode
sudo network-mode status

# Verify blocked domain (in limited mode)
curl -v https://example.com 2>&1 | grep -E "(Connection refused|timed out)"
# Expected: Connection failure
```

---

### Sudoers Allowlist

**Enforced by:** Linux kernel

**Threats:** Arbitrary sudo commands that bypass container restrictions — `sudo rm -rf /`, `sudo chmod`, `sudo apt-get remove`.

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Sudoers Allowlist | Only whitelisted commands permitted |
| Secondary | Read-only Filesystem | Even with sudo, can't write to read-only mounts |

**Implementation:** `/etc/sudoers.d/allowlist` (source: `safety/sudoers-allowlist`)

**Allowed commands (no wildcards — every argument is enumerated):**
- Package management: `sudo apt-get update` (install is **not** allowed — install dev tools at image build time)
- Service management: `sudo service postgresql|redis-server start|stop|restart|status`
- Network mode switching: `sudo network-mode status|limited|host-only|none|list|help`
- Network firewall: `sudo network-firewall.sh`
- DNS configuration: `sudo tee /etc/resolv.conf`

Everything else is denied — no fallback `PASSWD:ALL` line. All sudo I/O is audit-logged to `/var/log/sudo-audit.log`.

**Extending the allowlist:** Edit `safety/sudoers-allowlist` with explicit command paths (no wildcards), then rebuild: `cast build`

**Bypass:** Cannot be bypassed from userspace. The kernel enforces sudoers rules.

**Testing:**

```bash
# Allowed command
sudo apt-get update
# Expected: Success

# Blocked command
sudo rm /tmp/test
# Expected: "user is not allowed to execute" error
```

---

### Credential Isolation

**Enforced by:** Unified-proxy architecture (when enabled)

**Threats:** Credential theft via environment variable scraping, filesystem search, memory scraping, or network interception. Supply chain attacks via malicious npm packages or Python libraries that attempt credential theft or data exfiltration.

**Defense layers:**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Credential Isolation | Real credentials never enter sandbox |
| Secondary | Network Isolation | Cannot exfiltrate to unauthorized destinations |
| Tertiary | CAP_NET_RAW dropped | Cannot use raw sockets to bypass network controls |
| UX | Credential Redaction | Masks secrets in command output |

**Implementation:** `docker-compose.credential-isolation.yml`

Sandbox containers hold zero real credentials — only placeholder values. The unified proxy (a separate container) holds all real tokens and injects them into outbound requests. Container registration binds each sandbox to its IP address.

```
+------------------+     +------------------------------+     +------------------+
|    Sandbox       |     |       Unified Proxy          |     |  External APIs   |
|    (dev)         |     |                              |     |  (GitHub, Anthro- |
|                  |---->|  API Gateways (9848-9852)    |---->|   pic, OpenAI,   |
|  [placeholders]  |     |  Squid SNI filter (:8080)    |     |   Gemini, etc.)  |
|                  |     |  mitmproxy (:8081, optional)  |     |                  |
|                  |     |  DNS filter (:53)            |     |                  |
|                  |     |  [ALL CREDS]                 |     |                  |
+------------------+     +------------------------------+     +------------------+
```

Even if code reads the environment, it gets nothing useful — `ANTHROPIC_API_KEY` returns `CREDENTIAL_PROXY_PLACEHOLDER`.

#### Credential Exposure Matrix

| Credential | Unified Proxy | Sandbox |
|------------|---------------|---------|
| GITHUB_TOKEN / GH_TOKEN | Yes | No (empty) |
| ANTHROPIC_API_KEY | Yes | Placeholder |
| OPENAI_API_KEY | Yes | Placeholder |
| GOOGLE_API_KEY | Yes | Placeholder |
| Other API Keys | Yes | Placeholder |
| FOUNDRY_PROXY_GIT_TOKEN | Yes (subprocess env only) | No (never exposed) |

The unified proxy holds all real credentials. Sandboxes never see real values.

**Hardening — placeholder filtering:** Sandbox-supplied headers containing placeholder credential markers (`CRED_PROXY_`, `CREDENTIAL_PROXY_PLACEHOLDER`) are stripped before forwarding to upstream APIs. Filtering uses `startswith()` rather than substring matching to prevent false positives on legitimate values.

**Hardening — token-only and username-only auth rejection:** Git credential helper responses that provide only a `username` without a `password`, or only a `password`/`token` without a `username`, are rejected. Partial credential detection prevents credential confusion attacks where a sandbox supplies one half of a credential pair to influence how the proxy constructs the other.

**Hardening — container identity validation:** Requests to API gateways must have a valid container identity resolved from the source IP via the container registry. Requests from unregistered IPs receive a 403 response. The `IdentityMiddleware` runs first in the middleware stack. A null or empty `container_id` is explicitly rejected.

**Bypass:** Cannot be bypassed without compromising the unified-proxy container itself.

---

### Branch Isolation

**Enforced by:** `branch_isolation.py` module in the unified-proxy

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
4. **Fail-closed** — Sandboxes without branch identity metadata in their container registration cannot execute git operations

---

### Git Safety

**Enforced by:** `git_policies.py`, `security_policies.py`, unified-proxy git API server

**Threats:** Force push to protected branches, branch/tag deletion, PR merge (REST and GraphQL), CI/CD pipeline modification via pushed files.

**Defense layers (remote git destruction):**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Git proxy (unified-proxy) | Blocks force pushes to protected branches, blocks all branch/tag deletions |
| Secondary | Protected branch enforcement | Blocks ALL direct pushes to main/master/release/production (not just force pushes) |
| Tertiary | Bot mode restrictions | In bot mode, pushes restricted to `sandbox/*` branches only |

**Defense layers (PR merge prevention):**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Early-exit `is_merge_request()` | Unconditional check before any domain matching, credential injection, or policy evaluation |
| Secondary | GitHub API blocklist (Step 3) | Redundant fallback — same patterns checked again in `_check_github_blocklist()` |
| Tertiary | GitHub API gateway policy | Merge blocking duplicated at the gateway layer for defense-in-depth |

Merge endpoints blocked: REST `PUT /repos/*/pulls/*/merge` and `*/auto-merge`, GraphQL `mergePullRequest` and `enablePullRequestAutoMerge` mutations.

**Defense layers (CI/CD pipeline protection):**

| Layer | Control | Effect |
|-------|---------|--------|
| Primary | Push-time file validation | `check_push_files()` enumerates changed files and rejects pushes modifying blocked patterns |
| Secondary | Commit-time file validation | `check_file_restrictions()` on staged files gives early feedback before push |
| Tertiary | Path traversal prevention | Paths containing `..` after normalization are rejected |
| Fail-safe | Fail-closed on diff failure | If `git diff` fails, the push is rejected |

Blocked patterns are defined in `config/push-file-restrictions.yaml` (e.g., `.github/workflows/`, `Makefile`). Warned patterns (e.g., `package.json`, `Dockerfile`) are logged or rejected depending on `warn_action` setting.

**Pattern semantics:**

| Pattern form | Matching behavior | Example |
|---|---|---|
| Ends with `/` | Directory prefix match — blocks any file under that directory (`path.startswith(pattern)`) | `.github/workflows/` blocks `.github/workflows/ci.yml` |
| Contains `*` or `?` | Glob match via `fnmatch` against both the basename and the full relative path | `requirements-*.txt` matches `requirements-dev.txt` at any depth |
| Bare name (no `/`, no glob) | Basename match — blocks any file at any depth with that exact name | `Makefile` blocks `Makefile` and `subdir/Makefile` |

**Blocked vs. warned patterns:**

- **`blocked_patterns`** — Always reject the push. No override.
- **`warned_patterns`** — Behavior depends on `warn_action`:
  - `"log"` — Log a warning but allow the push (suitable for initial rollout or monitoring)
  - `"reject"` — Block the push (same as blocked patterns)

See [Configuration: Push File Restrictions](../configuration.md#push-file-restrictions) for the YAML format, default patterns, and customization instructions.

#### Git Shadow Mode

In credential isolation mode, sandboxes cannot directly access the `.git` directory or run git commands against the local repository. Instead, all git operations are proxied through the unified-proxy's git API server.

**How it works:**

1. **`.git` is hidden** — The worktree's `.git` file (a gitdir pointer) is bind-mounted to `/dev/null` in docker-compose, then overlaid with a 1KB tmpfs in `entrypoint-root.sh`. The sandbox sees an empty directory via both `ls` and `stat`, with no `/dev/null` fingerprint. If the tmpfs overlay fails, the `/dev/null` bind mount remains as a fallback
2. **Git wrapper intercepts commands** — `stubs/git-wrapper.sh` is mounted at `/usr/local/bin/git`, taking precedence over `/usr/bin/git`. For any git command under `/workspace`, the wrapper proxies the request to the git API server
3. **Git API server** — The unified-proxy runs a git API endpoint on port 8083 that receives JSON-encoded git commands, validates them, and executes them against the bare repository
4. **HMAC-SHA256 authentication** — Each request is signed with a per-sandbox HMAC secret. The signature covers the HTTP method, path, request body hash, timestamp, and a random nonce to prevent replay attacks
5. **Policy enforcement** — Before executing any command, the git API applies the same policy checks as the HTTPS proxy: repo authorization, force-push blocking, branch deletion blocking, and bot mode branch restrictions

**What the proxy enforces:**

| Policy | Effect |
|--------|--------|
| Repo authorization | Container can only access repos listed in its registration metadata |
| Branch deletion blocking | `git push` that would delete any branch or tag is rejected |
| Force-push blocking | Non-fast-forward pushes to protected branches are rejected |
| Bot mode | When `auth_mode=bot`, pushes restricted to `sandbox/*` branches |
| Push size limits | Pushes exceeding 100MB are rejected (413 response) |
| Malformed payload rejection | Pushes with unparseable pkt-line headers are rejected (fail closed) |

#### Git HTTPS Credential Injection

For remote git operations (`git push`, `git pull`), the unified-proxy injects `FOUNDRY_PROXY_GIT_TOKEN` into HTTPS requests to GitHub. The sandbox never receives the real GitHub token — it is held exclusively by the proxy container and injected at the network level during credential interception.

**Hardening — input validation:**

- **Path normalization:** URL paths are normalized before any policy check — strip query/fragment, URL-decode once, reject double-encoding (`%` still present), resolve `..` via `posixpath.normpath`, collapse `//` → `/`, strip trailing slash. Shared between the GitHub gateway and the mitmproxy policy engine via `security_policies.normalize_path()`.
- **Regex fullmatch:** Pattern matching uses `re.fullmatch()` instead of `re.match()` to prevent partial-match bypass.
- **Git identity sanitization:** Git user names and email addresses are sanitized to remove control characters (newlines, null bytes, ASCII control codes) before use in git operations, preventing header injection.
- **YAML serialization:** Configuration values are serialized with `yaml.dump()` instead of string interpolation to prevent YAML injection.
- **Diff argument order:** `git diff` arguments for push file restriction checks use explicit `--` separator and controlled argument ordering to prevent argument injection.

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

Masks secrets and sensitive values in command output to reduce accidental exposure. Filters API keys and tokens (patterns like `sk-*`, `key-*`, bearer tokens), environment variable values containing sensitive keywords, and common secret patterns in logs.

Real credential protection requires credential isolation.

---

## Explicit Non-Goals and Accepted Risks

The following are explicitly outside our threat model.

### Intentional Human Actions

If a human intentionally wants to destroy data, they can `docker exec` into the container with root, remove the sandbox directory from the host, use operator approval, or modify `docker-compose.yml` to disable protections.

**Rationale:** This isn't a security product protecting against malicious users. It's a safety net for AI-assisted development. The human operator is trusted.

### Container Escape Vulnerabilities

If an attacker exploits a Docker or kernel vulnerability to escape the container, sandbox protections don't help.

**Rationale:** We rely on Docker's security model. Container escape is an infrastructure-level concern outside this implementation's scope. Mitigation is through infrastructure patching and host hardening.

### Authorized Network Traffic

Sandboxes can send data to allowed services (GitHub, AI APIs). A compromised sandbox could push malicious code to an authorized repository, send data to AI APIs, or download malicious packages.

**Rationale:** Network isolation blocks unauthorized destinations. For authorized services, the trust model assumes the sandbox is doing legitimate development work. Repository-level protections (branch protection, code review) provide the next layer of defense.

### Disabled Credential Isolation

If credential isolation is disabled (`--no-isolate-credentials`), the AI can read real environment variables containing credentials.

**Rationale:** Credential isolation is opt-out for compatibility. When disabled, the user accepts that credentials may be exposed. Keep it enabled unless you have a specific compatibility need.

### Container Filesystem Write Capability

In credential isolation mode, the sandbox inherits `read_only: true` from the base compose file. DNS configuration is handled at compose level (`dns:`, `extra_hosts:`) and the root entrypoint only runs iptables rules before dropping privileges. `CAP_NET_ADMIN` is required for iptables but is only useful during root-phase initialization.

**Mitigations:** `read_only: true` inherited from base compose, non-root user (uid 1000 via gosu), network isolation (`internal: true`), tmpfs `/home`, `.git` hidden via `/dev/null` bind mount + tmpfs overlay.

### NET_ADMIN Capability

The sandbox container is granted `CAP_NET_ADMIN` for iptables DNS firewall rules. Privilege drop to uid 1000 via gosu occurs after iptables rules are set in `entrypoint-root.sh`. After privilege drop, the unprivileged user cannot modify iptables rules (requires effective uid 0). `CAP_NET_RAW` is separately dropped to prevent raw socket abuse.

### Mitmproxy CA Trust

The sandbox trusts the unified-proxy's mitmproxy CA certificate for HTTPS interception of providers that lack `*_BASE_URL` env var support (see [Architecture: Mitmproxy](../architecture.md#mitmproxy-conditional) for the current list). Major providers (Anthropic, OpenAI, GitHub) route through plaintext HTTP gateways and do not require MITM.

**Mitigations:** CA private key never enters the sandbox, sandbox only receives the public CA certificate, network isolation ensures only the unified-proxy can use this CA, CA generation is gated behind `ENABLE_MITM_FALLBACK` and MITM provider credential detection.

### Proxy-Side Attack Surface

The unified-proxy runs `git unpack-objects` on untrusted pack data received from the sandbox during push operations. A memory-safety bug in git's pack parser could allow code execution on the proxy host, potentially compromising all held credentials.

**Mitigations:**

| # | Control | Effect |
|---|---------|--------|
| 1 | Pack size bounded by `DEFAULT_MAX_PUSH_SIZE` (100MB) | Limits attack surface to bounded input |
| 2 | 10-second subprocess timeout | Kills hung or exploited git processes |
| 3 | Isolated temp directory | `unpack-objects` runs in a dedicated temporary object store |
| 4 | Minimal subprocess environment | Git subprocesses run with a stripped environment |
| 5 | Fail-closed on any error | Parse failures, timeouts, or unexpected exit codes all reject the push |

**Accepted risk rationale:** A pure-Python pack parser would be equally complex and less battle-tested than git's C implementation. The mitigations above bound the blast radius.

### In-Memory State Reset

Rate limiters, circuit breakers, and nonce replay stores reset on proxy restart.

**Mitigations:** Rate limiter reset only allows a brief burst before new limits take effect. Nonce replay protection is bounded by the HMAC timestamp window. Circuit breakers reset to closed (healthy) state, which is the safe default.

### Rate Limiting on Git Operations

Rate limiting on git operations and container registration limits are not implemented.

**Rationale:**
1. The proxy operates within a trusted orchestration environment. Container registration is only accessible from the orchestrator (Unix socket), not from sandboxed containers.
2. Resource exhaustion affects availability, not confidentiality/integrity, and can be mitigated at the infrastructure layer (container resource limits, orchestrator-level controls).
3. Rate limiting adds state management, clock dependencies, and configuration complexity that increases attack surface for the primary threats.
4. Upstream GitHub API already enforces rate limits per token.
5. Each sandbox is isolated — a sandbox exhausting resources only affects itself.

**Accepted risks:** A compromised orchestrator could register many containers (mitigated by: orchestrator is trusted). A single sandbox could make many git requests (mitigated by: GitHub rate limits, container resource limits). Registry could grow large (mitigated by: explicit unregistration on destroy, optional TTL-based cleanup).

### Custom Seccomp/AppArmor Profiles

Custom seccomp and AppArmor profiles are not specified in Dockerfiles.

**Rationale:**
1. Docker's default seccomp profile already blocks ~44 dangerous syscalls including `ptrace`, `mount`, `reboot`, `kexec_load`, `init_module`.
2. Container escape is a Docker/kernel infrastructure-level concern, not application-level.
3. AppArmor profiles must be installed on the Docker host — operational configuration outside this codebase's scope.
4. The primary threats (credential theft, unauthorized repository access) are mitigated by the proxy's authentication, network isolation, and allowlists — not syscall filtering.

**Accepted risks:** A kernel/Docker vulnerability could allow container escape (mitigated by: infrastructure patching). Exotic syscall-based attacks possible (mitigated by: Docker default seccomp, read-only filesystem, network isolation).

### Mutual TLS (mTLS) for Internal Traffic

Proxy-to-sandbox communication uses plaintext HTTP over Docker internal network, not mTLS.

**Rationale:**
1. The internal network prevents direct container-to-container traffic. iptables rules restrict egress. Only the unified proxy is reachable from sandboxes.
2. To intercept Docker bridge traffic, an attacker must have already compromised a container — at that point, mTLS wouldn't prevent credential access.
3. mTLS adds significant operational complexity: certificate generation per sandbox, distribution, rotation, revocation, and debugging in ephemeral containers.
4. Existing mitigations are sufficient: container registration with IP binding, explicit unregistration, network isolation via Docker bridge + iptables, read-only filesystem.

**Accepted risks:** Network-level MITM on Docker bridge (mitigated by: network isolation, attacker would need container escape first). Registration data interception in transit (mitigated by: IP binding, network isolation).

### Basic Auth Container Registration

When using Basic auth (git credential helper flow), the proxy identifies the container by its source IP address from the container registry, not by a shared secret. An attacker who can spoof the container's IP could impersonate it.

**Mitigations:** CAP_NET_RAW is dropped to prevent IP spoofing. Docker network isolation prevents cross-network IP spoofing. IP binding via container registry provides strong protection within isolated Docker networks. Registrations are managed by the orchestrator (trusted component). Explicit unregistration on sandbox destroy limits exposure window.

### Attack Scenarios

| Scenario | Attack | Outcome |
|----------|--------|---------|
| **Supply chain** (malicious npm package) | Package reads env vars, attempts direct HTTPS, DNS exfiltration, raw packet crafting | Gets placeholder values only; all exfiltration paths blocked by network isolation, DNS filter, and CAP_NET_RAW dropped |
| **AI token probing** | AI-generated code searches filesystem and memory for tokens | Finds only placeholder values — real credentials never enter the sandbox |
| **Lateral movement** | Compromised Sandbox A attempts to reach Sandbox B via direct connection, ARP/IP spoofing, or DNS rebinding | Blocked by separate isolated networks, CAP_NET_RAW dropped, and DNS filter |
| **Registration theft** | Attacker obtains registration details, attempts reuse from different location | Rejected by IP binding; registrations removed on destroy; new registration requires orchestrator (Unix socket) |

---

## Design Principles

1. **Fail safe** - When in doubt, block the operation
2. **Prefer UX** - Friendly messages over cryptic errors
3. **Assume good intent** - Protect against accidents, not attacks
4. **Minimize friction** - Safe operations should "just work"
5. **Recoverability** - Destroying and recreating sandboxes is cheap

## Security Assumptions

This security model assumes:

1. **Docker is trusted** — Container escape vulnerabilities are out of scope
2. **Orchestrator is trusted** — Container registration is a privileged operation
3. **Host is secure** — Host-level security is a prerequisite
4. **Network isolation works** — Docker networking and iptables are reliable

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
| Read-only filesystem | Docker/kernel | No (from container) | Prevent filesystem writes |
| Network isolation | Docker/mitmproxy/iptables | No (from container) | Control network egress |
| Sudoers allowlist | Linux kernel | No (from userspace) | Restrict sudo commands |
| Credential isolation | Unified-proxy architecture | No (without proxy compromise) | Protect credentials |
| Operator approval | TTY check | No (from non-interactive) | Human-in-the-loop |
| Branch isolation | git_operations + branch_isolation.py | No (from container) | Prevent cross-sandbox git access |
| Git safety | git_policies.py + security_policies.py | No (from container) | Protected branches, force-push blocking, API controls |
| Credential redaction | Shell functions | **Yes** | Reduce accidental exposure |

## Testing

Security measures are covered by:

- **Unit tests** — `tests/unit/test_policy_engine.py`, `tests/unit/test_github_gateway.py`, `tests/unit/test_gateway_middleware.py`
- **Push restriction tests** — `unified-proxy/tests/unit/test_push_file_restrictions.py`, `unified-proxy/tests/unit/test_commit_file_restrictions.py`
- **Red team modules** — `tests/redteam/modules/18-ip-encoding-bypass.sh`, `tests/redteam/modules/19-merge-early-exit.sh`
- **Integration tests** — `tests/integration/test_api_proxy.py`, `tests/security/test_credential_isolation.py`

### Manual Verification

**Network isolation:**

```bash
# Check network config
docker network inspect credential-isolation

# From sandbox: verify direct external access blocked
curl -v https://github.com 2>&1 | grep -E "(Connection refused|timed out)"

# From sandbox: verify proxy-routed access works
git clone https://github.com/owner/repo.git  # Should work

# From sandbox: verify DNS filtering
dig @8.8.8.8 github.com  # Should fail (blocked by iptables)
dig github.com  # Should work (uses unified-proxy DNS)
```

**Credential isolation:**

```bash
# From sandbox: verify real credentials not exposed
echo $GITHUB_TOKEN  # Should be empty
echo $ANTHROPIC_API_KEY  # Should be CREDENTIAL_PROXY_PLACEHOLDER

# From sandbox: verify credential injection works
git clone https://github.com/allowed/repo.git  # Should work
curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/v1/messages  # Should work via proxy
```

**Container registration:**

```bash
# From host: verify container is registered
docker exec <proxy-container> curl -s --unix-socket /var/run/proxy/internal.sock http://localhost/internal/containers
```

**CAP_NET_RAW (supply chain protection):**

```bash
# From sandbox: verify CAP_NET_RAW is dropped
cat /proc/self/status | grep CapEff
# Decode capabilities (requires capsh on host):
# capsh --decode=<hex_value>
# Should NOT include cap_net_raw (bit 13)

# From sandbox: verify raw socket creation fails
python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)"
# Should raise: PermissionError: [Errno 1] Operation not permitted
```

## See Also

- [Configuration: Push File Restrictions](../configuration.md#push-file-restrictions) — File restriction patterns
- [ADR-007: API Gateways](../adr/007-api-gateways.md) — Gateway architecture decision
