# Security Feature Gaps in foundry-sandbox

Comparative analysis against the [egg](https://github.com/anthropics/egg) sandbox
architecture. Focused on the **local developer using AI agents** use case — autonomous
agent workflow features (SDLC phases, multi-agent roles, contract systems) are excluded.

---

## GAP 1: MITM-Based Credential Injection (High Priority)

### Current State

foundry-sandbox uses mitmproxy to intercept **all** HTTPS traffic from sandboxes. The
proxy inspects requests, matches them to known API providers, and injects real
credentials (API keys, OAuth tokens) into headers before forwarding upstream.

This requires:
- Generating a mitmproxy CA certificate at proxy startup
  (`unified-proxy/entrypoint.sh:138-189`)
- Distributing the CA cert to sandboxes via a shared Docker volume (`mitm-certs:/certs:ro`)
- Configuring **six** environment variables in each sandbox to trust the CA:
  ```
  NODE_EXTRA_CA_CERTS=/certs/ca-certificates.crt
  REQUESTS_CA_BUNDLE=/certs/ca-certificates.crt
  SSL_CERT_FILE=/certs/ca-certificates.crt
  CURL_CA_BUNDLE=/certs/ca-certificates.crt
  GIT_SSL_CAINFO=/certs/ca-certificates.crt
  PIP_CERT=/certs/ca-certificates.crt
  ```

### What egg Does Instead

egg routes Anthropic API traffic through a plaintext HTTP gateway on the internal
Docker network. The sandbox sets `ANTHROPIC_BASE_URL=http://egg-gateway:9848`, so
Claude Code natively sends requests to the gateway over HTTP. The gateway injects
credentials and forwards to `api.anthropic.com` over HTTPS.

**No CA certificate is needed in the sandbox.** No MITM of any HTTPS connection.
`api.anthropic.com` is explicitly excluded from the Squid proxy allowlist — it
physically cannot be reached except through the gateway.

For GitHub, egg routes `git` and `gh` commands through gateway REST endpoints
(`/api/v1/git/execute`, `/api/v1/gh/execute`). The gateway holds the GitHub token and
injects it into git credential helpers at execution time. The credential helper is
written to a temp file, used for the single operation, and cleaned up immediately
(even on error via exception handling).

### Why This Matters

1. **Attack surface**: A CA certificate trusted by the sandbox is a powerful primitive.
   If the agent can somehow redirect network traffic (e.g., by manipulating `/etc/hosts`
   if it becomes writable, or via DNS rebinding), the CA cert could be used to intercept
   connections to arbitrary hosts. The CA private key lives on the proxy container, not
   the sandbox, so this requires proxy compromise — but it's still an unnecessary attack
   surface.

2. **Complexity**: Six env vars, atomic cert bundle writes, shared volumes, and combined
   CA bundles are a lot of moving parts. Each is a potential misconfiguration.

3. **Tool compatibility**: Some tools don't respect `SSL_CERT_FILE` or
   `REQUESTS_CA_BUNDLE`. Custom CA trust is a known source of breakage (e.g., Go
   binaries compiled with `CGO_ENABLED=0` ignore system certs).

### Proposed Implementation

For the **Anthropic API** (primary use case), adopt the `ANTHROPIC_BASE_URL` pattern:

1. Add an HTTP endpoint to the unified proxy (e.g., `:9848/v1/messages`) that:
   - Accepts plaintext HTTP requests from sandboxes on the internal network
   - Injects the real `ANTHROPIC_API_KEY` or OAuth token
   - Forwards to `api.anthropic.com` over HTTPS
   - Streams SSE responses back to the sandbox

2. Set `ANTHROPIC_BASE_URL=http://unified-proxy:9848` in sandbox environment.

3. Remove `api.anthropic.com` from the domain allowlist (force all traffic through
   the gateway endpoint).

For **other providers** (OpenAI, Google, Tavily, etc.), the same pattern can be
extended per-provider, or mitmproxy can remain as a fallback for providers that don't
support base URL override. This is a gradual migration — the highest-value target
(Anthropic) can be done first.

For **GitHub**, the existing git API server (`:8083`) already avoids MITM for git
operations. The remaining MITM surface is GitHub REST/GraphQL API calls made by `gh`
CLI, which could be routed through a gateway endpoint similar to egg's approach.

### Scope

- `unified-proxy/`: New HTTP relay endpoint
- `docker-compose.credential-isolation.yml`: Add `ANTHROPIC_BASE_URL` env var
- `config/allowlist.yaml`: Remove `api.anthropic.com`
- `unified-proxy/addons/credential_injector.py`: Remove Anthropic provider (keep others
  during transition)

---

## GAP 2: IP Encoding Bypass Prevention (Medium Priority)

### Current State

foundry-sandbox validates proxy IPs with a basic dotted-decimal regex in
`entrypoint-root.sh`:

```bash
if ! [[ "$PROXY_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
```

The domain allowlist (`config/allowlist.yaml`) is resolved to IPs at build time and
loaded into iptables. DNS filtering returns NXDOMAIN for non-allowlisted domains. But
if an agent constructs a request using a **direct IP address** in an alternative
encoding, it can bypass DNS filtering entirely:

- Octal: `0177.0.0.1` → 127.0.0.1
- Hex: `0x7f000001` → 127.0.0.1
- Integer: `2130706433` → 127.0.0.1
- Mixed: `0x7f.0.0.1`
- IPv6 brackets: `[::1]`

The iptables rules are the primary defense here — they block egress to IPs not in the
allowlist. However, the allowlist IPs are resolved from domain names, and iptables rules
match on standard decimal notation. An agent could potentially use encoded IPs to reach
an allowlisted IP on a different port, or exploit edge cases in how the kernel parses IP
addresses in iptables vs how curl/wget parse them.

### What egg Does

egg's Squid proxy has explicit ACL rules blocking all forms of direct IP access
(`gateway/squid.conf:54-66`):

```
acl direct_ipv4   url_regex ^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+
acl direct_ipv6   url_regex ^https?://\[
acl direct_ip_octal url_regex ^https?://0[0-7]+\.
acl direct_ip_hex   url_regex ^https?://0x[0-9a-fA-F]+
acl direct_ip_int   url_regex ^https?://[0-9]{9,10}(/|$|:)

http_access deny direct_ipv4
http_access deny direct_ipv6
http_access deny direct_ip_octal
http_access deny direct_ip_hex
http_access deny direct_ip_int
```

This blocks **all** direct-IP requests regardless of encoding. Combined with the
domain allowlist, traffic can only reach hosts that resolve from allowed domain names.

### Why This Matters

A local dev's sandbox likely has access to `localhost` services, Docker networks, and
internal infrastructure. An agent that can construct requests with encoded IPs could
potentially reach:

- Docker metadata service (169.254.169.254 in cloud, or local equivalents)
- Other containers on the Docker network
- Host services listening on 0.0.0.0
- Internal network services reachable from the host

The iptables rules mitigate most of this (they block egress to non-allowlisted IPs),
but the encoding bypass could interact with edge cases in iptables IP parsing.

### Proposed Implementation

Add IP-literal detection to the mitmproxy policy engine. In
`unified-proxy/addons/policy_engine.py`, before the domain allowlist check:

```python
import re

IP_PATTERNS = [
    re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"),   # Standard IPv4
    re.compile(r"^\["),                                    # IPv6 brackets
    re.compile(r"^0[0-7]+\."),                             # Octal
    re.compile(r"^0x[0-9a-fA-F]"),                         # Hex
    re.compile(r"^[0-9]{9,10}$"),                          # Integer
]

def is_ip_literal(host: str) -> bool:
    return any(p.match(host) for p in IP_PATTERNS)
```

Reject any request where the host matches an IP-literal pattern. This is a simple,
low-risk change that adds defense-in-depth on top of the existing iptables rules.

### Scope

- `unified-proxy/addons/policy_engine.py`: Add IP-literal detection in
  `normalize_host()` or request validation
- `tests/redteam/modules/`: Add test module for IP encoding bypass attempts

---

## GAP 3: Push-Time File Validation (Medium Priority)

### Current State

foundry-sandbox validates git push operations at the **protocol level**: protected
branches, force-push detection (pkt-line parsing), branch isolation, and push size
limits. It does **not** validate the **content** of what's being pushed — specifically,
which files are being modified.

An agent with push access to an allowed branch can modify any file in the repository,
including:

- `.github/workflows/*.yml` (CI/CD pipelines — code execution on merge)
- `Makefile`, `Justfile`, `Taskfile.yml` (build system — code execution on build)
- `.pre-commit-config.yaml` (hooks — code execution on commit)
- `pyproject.toml`, `package.json` (dependency specifications — supply chain)
- `.env.example`, `docker-compose.yml` (infrastructure configuration)
- `CODEOWNERS`, `.github/FUNDING.yml` (repository governance)

### What egg Does

egg validates changed files at both commit-time and push-time using its phase/role
system. The core idea is simple: enumerate the files being changed, check them against
a list of patterns, and reject if any are blocked. egg's implementation is complex
because it supports SDLC phases and multi-agent roles, but the underlying mechanism
is just pattern matching on file paths with path normalization to prevent traversal
bypasses.

### Why This Matters

For a local dev, the biggest risk from a compromised agent is **persistent
compromise** — modifications that survive the sandbox session and execute later:

1. **CI poisoning**: Agent modifies `.github/workflows/ci.yml` to exfiltrate secrets
   or run arbitrary code. The change looks innocuous in a large diff. When the PR is
   merged, the workflow runs with repository secrets.

2. **Build system attacks**: Agent adds a post-install script to `package.json` or a
   Makefile target that executes on the developer's machine outside the sandbox.

3. **Dependency confusion**: Agent adds a malicious dependency to `requirements.txt`
   or `package.json` that the dev installs outside the sandbox.

These attacks don't require escaping the sandbox — they weaponize the legitimate
code review and merge workflow.

### Proposed Implementation

Add a configurable file restriction system to the git API server. This doesn't need
egg's full phase/role system — a simpler blocked-patterns list is sufficient for the
local dev use case:

1. **Configuration** (`config/push-file-restrictions.yaml`):
   ```yaml
   blocked_patterns:
     - ".github/workflows/"
     - ".github/actions/"
     - "Makefile"
     - "Justfile"
     - ".pre-commit-config.yaml"
     - "CODEOWNERS"
   warn_patterns:
     - "package.json"
     - "pyproject.toml"
     - "requirements.txt"
     - "Gemfile"
     - "go.mod"
     - "Cargo.toml"
     - "docker-compose"
     - "Dockerfile"
   ```

2. **Enforcement** in `unified-proxy/git_api.py` or `git_operations.py`:
   - Before executing a push, run `git diff --name-only <remote>/<branch>..HEAD`
   - Check each file against blocked/warn patterns
   - Blocked files: reject the push with a clear error message
   - Warn files: log a warning (or reject, depending on config)
   - Fail-closed: if `git diff` fails, reject the push

3. **Path normalization**: Normalize paths before matching (strip `./`, `../`,
   collapse `//`). Reject any path containing `..` after normalization.

### Scope

- `config/push-file-restrictions.yaml`: New config file
- `unified-proxy/git_operations.py`: Add file validation before push execution
- `unified-proxy/git_api.py`: Wire in validation on push endpoint
- `tests/redteam/modules/`: Add test for workflow file push attempts

---

## GAP 4: Physical Absence vs Policy Enforcement for Merge (Low Priority)

### Current State

foundry-sandbox blocks merge operations via **policy rules** at multiple layers:

- `policy_engine.py`: Blocks `PUT /repos/*/pulls/*/merge` (GitHub REST)
- `github-api-filter.py`: Blocks `mergePullRequest` (GraphQL mutation)
- `branch_isolation.py`: Push isolation prevents merging into protected branches

These are effective, but they're **positive enforcement** — the code that handles
merges exists, and policy rules prevent it from being used. If a policy rule has a
regex bug or an edge case, the merge could go through.

### What egg Does

egg's gateway has **no merge endpoint**. The `check_merge_allowed()` method
unconditionally returns `False`:

```python
def check_merge_allowed(self, repo, pr_number) -> PolicyResult:
    """ALWAYS returns False - merging is not supported."""
    return PolicyResult(
        allowed=False,
        reason="Merge operations are not supported. Human must merge via GitHub UI."
    )
```

More importantly, there is no `/api/v1/gh/pr/merge` route in the gateway. The `gh`
wrapper script in the sandbox has no code path that could invoke a merge. The
capability is **physically absent** from the system.

### Why This Matters

The distinction between "blocked by policy" and "doesn't exist" matters for security
reasoning:

- Policy rules can have bugs (regex edge cases, encoding bypasses, race conditions)
- Policy rules must be maintained as the codebase evolves
- Absent capabilities require no maintenance and cannot have bugs

For merge specifically, the risk is that an agent merges its own PR, bypassing human
review. This is a high-impact action (code goes to production) that should require the
strongest possible guarantee.

### Proposed Implementation

This is partially addressed already — the git API server doesn't expose a merge
endpoint, and `gh` CLI merge commands are blocked by the GitHub API filter. The gap is
that the GitHub REST/GraphQL proxy still *routes* merge requests and relies on the
filter to block them.

To fully close this:

1. In `policy_engine.py`, move merge blocking from a pattern-based filter to an
   early-exit check that runs before any request routing:
   ```python
   MERGE_PATTERNS = [
       re.compile(r"/pulls/\d+/merge$"),
       re.compile(r"/pulls/\d+/auto-merge$"),
       re.compile(r"/merges$"),
   ]

   def is_merge_request(path: str, body: bytes) -> bool:
       if any(p.search(path) for p in MERGE_PATTERNS):
           return True
       if b"mergePullRequest" in body:
           return True
       return False
   ```

2. Check `is_merge_request()` as the **first** thing in the request handler, before
   any domain matching, credential injection, or policy evaluation. Return 403
   immediately.

### Scope

- `unified-proxy/addons/policy_engine.py`: Add early-exit merge check
- Minimal change, low risk

---

## GAP 5: Complete .git Metadata Elimination (Low Priority)

### Current State

foundry-sandbox hides `.git` by bind-mounting it to `/dev/null`:

```bash
# From entrypoint.sh (git shadow mode)
mount --bind /dev/null /workspace/.git
```

The agent sees `.git` as a character device (`/dev/null`). `cat .git` returns empty.
`git` commands are intercepted by a wrapper script that routes to the git API server.

However, the `.git` entry still exists in the filesystem as a device node. An agent
can determine that `.git` is `/dev/null` via `stat .git` or `ls -la .git`, which
reveals that git metadata is being hidden (information disclosure about the security
architecture).

### What egg Does

egg mounts `.git` as a tmpfs:

```yaml
# docker-compose.yml (inferred from architecture)
tmpfs:
  - /home/egg/repos/<repo>/.git:size=1k
```

The agent sees `.git` as an empty directory. `ls .git` returns nothing. `stat .git`
shows a normal directory. There's no indication that anything is being hidden —
it simply looks like a repository without any git metadata, which is unusual but
not suspicious in the same way.

### Why This Matters

This is a minor information disclosure issue. An agent that knows `.git` is
`/dev/null` knows it's in a sandbox with git security measures. This knowledge
doesn't directly enable exploitation, but it helps an adversarial agent understand
the security model and focus its escape attempts.

The practical impact is low — any agent sophisticated enough to exploit this
information would likely already know it's in a sandbox.

### Proposed Implementation

Change the bind mount from `/dev/null` to a tmpfs:

```bash
# In entrypoint-root.sh or entrypoint.sh
mount -t tmpfs -o size=1k,mode=755 tmpfs /workspace/.git
```

Or in docker-compose:

```yaml
tmpfs:
  - /workspace/.git:size=1k,mode=755
```

### Scope

- `entrypoint.sh` or `entrypoint-root.sh`: Change mount type
- OR `docker-compose.credential-isolation.yml`: Add tmpfs entry
- Minimal change, no functional impact

---

## GAP 6: Commit-Time File Validation (Low Priority)

### Current State

foundry-sandbox does not validate files at commit time. The git API server executes
`git commit` without inspecting which files are staged.

Push-time validation (GAP 3) catches restricted files before they leave the sandbox,
but commit-time validation adds defense-in-depth: catching violations early gives
the agent a chance to fix them rather than failing at push time with a large diff.

For the local dev case, push-time validation is the security boundary — the agent's
commits exist only in its local worktree until pushed. Commit-time validation is
strictly a developer experience improvement.

### Proposed Implementation

Reuse the same file restriction config and `check_file_restrictions()` function from
GAP 3. Add a call in the git API `commit` handler that enumerates staged files and
checks them against the blocked/warn patterns:

1. Before executing a commit, run `git diff --cached --name-only` to get staged files
2. Pass them through the same `check_file_restrictions()` used at push time
3. Blocked files: reject the commit with a clear error message
4. Fail-closed: if `git diff` fails, reject the commit

### Scope

- `unified-proxy/git_api.py`: Add staged file check to commit endpoint
- Reuses the same config and validation logic from GAP 3 — no new config files

---

## Summary

| # | Gap | Priority | Effort | Risk Reduced |
|---|-----|----------|--------|-------------|
| 1 | No-MITM credential injection | High | Medium | Eliminates CA cert attack surface |
| 2 | IP encoding bypass prevention | Medium | Low | Blocks IP-literal domain bypass |
| 3 | Push-time file validation | Medium | Medium | Prevents CI/build/dependency poisoning |
| 4 | Physical absence of merge | Low | Low | Stronger merge prevention guarantee |
| 5 | Complete .git elimination | Low | Low | Eliminates info disclosure |
| 6 | Commit-time file validation | Low | Low | Earlier feedback on violations |

### Implementation Order

1. **GAP 2** (IP encoding) — lowest effort, immediate defense-in-depth improvement
2. **GAP 4** (merge early-exit) — small change, stronger guarantee
3. **GAP 5** (.git tmpfs) — trivial change, cleaner isolation
4. **GAP 3** (push-time file validation) — medium effort, high value for local dev
5. **GAP 1** (no-MITM injection) — highest effort, highest architectural improvement
6. **GAP 6** (commit-time validation) — only after GAP 3, defense-in-depth

---

## Appendix: Areas Where foundry-sandbox Is Already Stronger

For completeness, egg lacks several features that foundry-sandbox implements:

- **iptables defense-in-depth**: foundry-sandbox has kernel-level network blocking at
  three layers (container, host, DOCKER-USER chain). egg relies solely on Squid proxy.
- **CAP_NET_RAW drop**: foundry-sandbox explicitly drops this capability, preventing
  IP spoofing, ARP poisoning, and raw socket sniffing. egg doesn't.
- **Read-only root filesystem**: foundry-sandbox uses `read_only: true` at the Docker
  level. egg doesn't.
- **Seccomp profile**: foundry-sandbox uses the default seccomp profile blocking ~44
  dangerous syscalls. egg doesn't configure one explicitly.
- **Restrictive sudoers**: foundry-sandbox allows only `apt-get install`, `service`,
  and `chown`. egg's sudoers is less restrictive.
- **Operator approval (TTY check)**: foundry-sandbox has a human-in-the-loop gate
  that blocks AI agents (no TTY) from dangerous operations. egg has no equivalent.
- **pkt-line protocol parsing**: foundry-sandbox inspects the git wire protocol to
  detect force pushes. egg blocks `--force` at the flag level, which is easier to
  bypass (e.g., `--force-with-lease`, refspec syntax `+refs/heads/...`).
- **SHA reachability enforcement**: foundry-sandbox validates that SHA arguments are
  ancestors of allowed branches. egg doesn't.
- **Branch output filtering**: foundry-sandbox filters `git branch`, `log --decorate`,
  etc. to hide disallowed branches. egg doesn't.
