# Credential Isolation: Gateway Sidecar

## Mission

Keep credentials out of sandbox containers by routing git operations through a gateway service that holds tokens, with sandbox running on Docker internal network with egress proxy.

## Objective

Implement credential isolation for AI agent sandboxes by:
1. Preventing dangerous credential directories from being mounted into containers
2. Providing a gateway service that proxies git operations with real credentials
3. Restricting sandbox network access to allowlisted domains via egress proxy
4. Blocking DNS exfiltration via controlled DNS resolution

## Threat Model

### Assets to Protect
- **GitHub tokens** (PAT, OAuth) - primary credential for git operations
- **Other API keys** - AI provider keys, registry tokens
- **Repository data** - prevent unauthorized access to repos outside session scope

### Attacker Model
- **Compromised AI agent** - arbitrary code execution inside sandbox container
- **Malicious repository code** - build scripts, post-checkout hooks
- **Network exfiltration attempts** - DNS tunneling, direct IP connections

### Trust Boundaries
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TRUSTED ZONE (Host)                                                          │
│ ┌─────────────────┐    Unix Socket     ┌─────────────────────────────────┐  │
│ │ Host CLI        │◄──────────────────►│ Gateway Service                 │  │
│ │ (sandbox.sh)    │    (0600 perms)    │ - Holds real GitHub token       │  │
│ └─────────────────┘                    │ - Creates/destroys sessions     │  │
│                                        │ - Validates container identity  │  │
│                                        └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                              │
                                              │ Docker internal network
                                              │ (session token auth)
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ SEMI-TRUSTED ZONE (Sandbox Container)                                        │
│ - Has scoped session token (GATEWAY_TOKEN env var)                           │
│ - Token bound to container IP + repo list                                    │
│ - NO access to real credentials                                              │
│ - NO direct external network access                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Mitigations by Threat

| Threat | Mitigation |
|--------|------------|
| Token theft from sandbox | Session tokens scoped to container IP + repos, not usable elsewhere |
| Token replay from other container | Gateway validates source IP matches session's container IP |
| Token exposure via /proc/environ | Token stored in tmpfs file, not env var |
| Token exposure via docker inspect | Token not in container environment, only in tmpfs mount |
| Cross-sandbox attacks | ICC disabled on sandbox network, containers isolated from each other |
| DNS exfiltration | All DNS forced through gateway dnsmasq, port 53 blocked elsewhere |
| Direct IP exfiltration | Internal-only network, no default bridge, iptables backup |
| Credential directory access | Mount blocklist with symlink resolution |
| Embedded creds in git config | Pre-flight validation of .git/config |

## Scope

### In Scope
- Dangerous path blocklist for mount validation
- Gateway service for git credential proxying (GitHub only for v1)
- Docker internal network configuration with enforced isolation
- Egress proxy with domain allowlist
- DNS isolation via dnsmasq
- Git URL rewriting in container images
- Session token management with container-bound tokens

### Out of Scope (YAGNI for v1)
- JWT with access/refresh tokens (simple session token sufficient)
- TLS on internal Docker network (Docker network isolation sufficient)
- Rate limiting (sandboxes aren't public APIs)
- Prometheus metrics (not essential for isolation)
- Multi-provider support (start with GitHub, add others when needed)
- **Git LFS support** - will fail with clear error message
- **Git submodules from external hosts** - only same-host submodules supported

## Architecture

```
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│  Sandbox Container      │     │  Gateway Service        │     │  Egress Proxy           │
│  (No credentials)       │     │  (Holds tokens)         │     │  (Allowlisted domains)  │
│                         │     │                         │     │                         │
│  git push ──────────────┼────►│  Proxies to upstream    │     │                         │
│  (via gateway URL)      │     │  with real credentials  │     │                         │
│                         │     │                         │     │                         │
│  HTTP requests ─────────┼─────┼─────────────────────────┼────►│  Domain allowlist       │
│  (via proxy)            │     │                         │     │                         │
└─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
      internal network                internal + external             internal + external
      (NO default network)            (both networks)                 (both networks)
```

### Network Enforcement Model

**Primary isolation**: Docker `internal: true` network with NO default network attached to sandbox.

**Enforcement layers (defense in depth)**:
1. **Docker network topology** - Sandbox ONLY on `sandbox_internal` network (no route to external)
2. **Inter-container isolation** - ICC (inter-container communication) disabled on sandbox network; sandboxes cannot reach each other
3. **Gateway/proxy as sole egress** - All traffic must flow through gateway or egress-proxy
4. **DNS lockdown** - Only gateway:53 reachable, all other DNS blocked
5. **Host iptables backup** - DOCKER-USER chain rules block sandbox container IPs from direct external egress

**Cross-sandbox isolation**:
- `sandbox_internal` network created with `com.docker.network.bridge.enable_icc=false`
- Each sandbox can only reach gateway and egress-proxy (explicitly allowed via iptables)
- Sandbox-to-sandbox traffic blocked at bridge level
- Prevents compromised sandbox from attacking other sandboxes or sniffing traffic

**DNS Bypass Prevention**:
- Block outbound port 53 (UDP/TCP) except to gateway IP
- Block known DoH endpoints at proxy level (dns.google, cloudflare-dns.com, etc.)
- Proxy rejects requests to IP literals (must use hostnames that resolve through dnsmasq)
- dnsmasq returns NXDOMAIN for non-allowlisted domains

### Session Token Lifecycle

**Creation**:
- Host CLI calls gateway `/session/create` over Unix socket
- Socket at `$SANDBOX_STATE_DIR/gateway.sock` with mode 0600, owned by user running sandbox
- Request includes: `{repos: ["owner/repo"], container_id: "abc123"}`
- Gateway generates per-session secret (32-byte random) and records:
  `{token: "...", session_secret: "...", container_id: "abc123", container_ip: "172.18.0.5", repos: [...], created_at: ..., expires_at: ...}`

**Binding** (multi-factor):
- Token bound to `{container_id, session_secret, container_ip, allowed_repos[], expires_at}`
- Gateway derives container IP from Docker network on session creation
- All requests validated:
  - Source IP must match session's container_ip
  - Token must match session token
  - Session must not be expired (TTL: 24 hours, refreshed on activity)
- Per-session secret stored in container alongside token (in `/run/secrets/gateway_secret`)
- Requests must include both token AND secret hash (HMAC of request path with secret)
- Prevents token-only replay if token is leaked

**Storage**:
- Token written to tmpfs-mounted secret file inside container: `/run/secrets/gateway_token`
- File permissions: 0400 (read-only by container user)
- Mount: `type=tmpfs` with `size=4k` (minimal, just holds token)
- NOT passed via environment variable (avoids `/proc/.../environ` exposure)
- NOT visible via `docker inspect` environment section
- Credential helper reads from file, not env var
- Gateway stores sessions in memory (lost on restart, acceptable for v1)

**TTL**:
- Session expires after 24 hours of inactivity
- Refreshed on each successful git operation
- Absolute maximum lifetime: 7 days (then must recreate)
- Gateway runs periodic garbage collection (every 5 min) to purge expired sessions

**Revocation**:
- Automatic on sandbox destroy via `/session/destroy` call
- Gateway purges session immediately
- Stale tokens rejected with 401

**Restart behavior**:
- `sandbox start` on stopped container: new session token generated, old one invalid
- Container maintains same IP on restart (Docker behavior), but token refreshed

### Git Smart HTTP Protocol

**Upstream pinning and request validation**:
- Hard-pin upstream to `github.com` only (no other hosts)
- Disable HTTP redirects in upstream requests (prevent SSRF via redirect)
- Validate `owner`: `^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$` (GitHub username rules)
- Validate `repo`: `^[a-zA-Z0-9._-]+$` (GitHub repo name rules)
- Canonicalize path: reject `..`, encoded sequences, null bytes
- Allowlist git endpoints only:
  - `GET /info/refs?service=git-upload-pack`
  - `GET /info/refs?service=git-receive-pack`
  - `POST /git-upload-pack`
  - `POST /git-receive-pack`
- Reject all other paths (403) - blocks LFS, API, arbitrary paths

**Request flow**:
```
Sandbox (git client)                    Gateway                         GitHub
        │                                  │                               │
        │ GET /git/owner/repo.git/info/refs?service=git-upload-pack        │
        │ Authorization: Bearer <GATEWAY_TOKEN>                            │
        ├─────────────────────────────────►│                               │
        │                                  │ Validate token + source IP    │
        │                                  │ Check repo in session scope   │
        │                                  │                               │
        │                                  │ GET /owner/repo.git/info/refs │
        │                                  │ Authorization: token <GH_TOKEN>
        │                                  ├──────────────────────────────►│
        │                                  │◄──────────────────────────────┤
        │◄─────────────────────────────────┤ Stream response               │
        │                                  │                               │
        │ POST /git/owner/repo.git/git-upload-pack                         │
        │ Authorization: Bearer <GATEWAY_TOKEN>                            │
        │ Content-Type: application/x-git-upload-pack-request              │
        ├─────────────────────────────────►│                               │
        │                                  │ POST with GH_TOKEN            │
        │                                  ├──────────────────────────────►│
        │                                  │◄──────────────────────────────┤
        │◄─────────────────────────────────┤ Stream packfile               │
```

**Header handling**:
- Accept `Authorization: Bearer <token>` from sandbox
- Replace with `Authorization: token <GH_TOKEN>` to upstream
- Forward `Content-Type`, `Accept`, `Content-Length`
- Handle `Expect: 100-continue` for POST requests
- Never log Authorization headers

**Streaming implementation**:
- Use chunked transfer encoding for responses
- Stream request body to upstream (don't buffer entire packfile)
- Stream response body to client (don't buffer entire packfile)
- Timeout: 30s connect, 600s transfer (large repos)
- No memory limit issues: stream through, don't accumulate

**Error responses**:
- 401 Unauthorized: Invalid or missing token
- 403 Forbidden: Repo not in session scope
- 404 Not Found: Repo doesn't exist on GitHub
- 501 Not Implemented: LFS endpoint detected
- 502 Bad Gateway: GitHub returned error
- 504 Gateway Timeout: GitHub didn't respond in time

### Unix Socket Security

**Location**: `$SANDBOX_STATE_DIR/gateway.sock` (typically `~/.sandboxes/.state/gateway.sock`)

**Permissions**:
- Created by gateway service on startup
- Mode: 0600 (owner read/write only)
- Owner: user running the sandbox CLI
- Gateway validates socket path on startup, refuses to bind if parent dir is world-writable

**Lifecycle**:
- Created: When gateway container starts
- Deleted: When gateway container stops (Docker volume cleanup)
- Stale detection: CLI checks socket exists and is responsive before use

**Access control**:
- Only host CLI uses socket (session create/destroy)
- Sandbox containers cannot access socket (not mounted, wrong network)
- Other local users cannot access (0600 permissions)

### Allowlist Configuration

**Single source of truth**: `gateway/allowlist.conf`

```
# Format: domain [type]
# type: dns (resolve only), proxy (HTTP allowed), both (default)

# Package registries
registry.npmjs.org both
*.npmjs.org both
pypi.org both
files.pythonhosted.org both
*.pythonhosted.org both
proxy.golang.org both
sum.golang.org both
crates.io both
static.crates.io both

# CDNs used by registries
*.cloudfront.net both
*.fastly.net both

# AI APIs
api.anthropic.com both
api.openai.com both
generativelanguage.googleapis.com both

# GitHub (API only - git goes through gateway)
api.github.com both
raw.githubusercontent.com both
objects.githubusercontent.com both

# Blocked DoH endpoints (never resolve, never proxy)
!dns.google
!cloudflare-dns.com
!dns.cloudflare.com
!doh.opendns.com
```

**Generated configs**:
- `dnsmasq.conf` - Generated from allowlist, forwards allowed domains, NXDOMAIN for rest
- `tinyproxy.conf` - Generated from allowlist, allows proxy for marked domains

**IP literal handling**:
- Proxy rejects requests to IP addresses (e.g., `http://1.2.3.4/`)
- Forces all requests to use hostnames that go through DNS resolution
- Prevents allowlist bypass via direct IP

### Audit Logging

**What to log** (structured JSON to stderr):
```json
{"ts": "...", "event": "session_create", "container_id": "abc", "repos": ["o/r"], "ip": "172.18.0.5"}
{"ts": "...", "event": "session_destroy", "container_id": "abc"}
{"ts": "...", "event": "git_access", "repo": "o/r", "action": "clone", "ip": "172.18.0.5", "status": 200}
{"ts": "...", "event": "git_denied", "repo": "o/other", "ip": "172.18.0.5", "reason": "not_in_scope"}
{"ts": "...", "event": "proxy_allow", "host": "pypi.org", "ip": "172.18.0.5"}
{"ts": "...", "event": "proxy_deny", "host": "evil.com", "ip": "172.18.0.5"}
```

**What NOT to log**:
- Authorization headers
- Token values
- Request/response bodies

**Log destination**: Container stderr (captured by Docker logging)

## Phases

### Phase 1: Dangerous Path Blocklist

**Purpose**: Prevent mounting credential directories into sandboxes as the first line of defense.

**Tasks**:
1. Add `DANGEROUS_PATHS` array to `lib/validate.sh` with paths: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.config/gh`, `~/.azure`, `~/.netrc`, `~/.kube`, `~/.gnupg`, `~/.docker`, `~/.npmrc`, `~/.pypirc`, `/var/run/docker.sock`, `/run/docker.sock`
2. Implement `validate_mount_path()` function with symlink resolution via `realpath -m`
3. Add `--allow-dangerous-mount` override flag to `commands/new.sh` for power users
4. Integrate mount validation into the sandbox creation flow in `commands/new.sh`
5. Add unit tests for path validation including symlink edge cases

**Verification**:
- `sandbox new --mount ~/.ssh:/ssh` should be blocked with clear error
- `sandbox new --mount ~/.ssh:/ssh --allow-dangerous-mount` should succeed with warning
- Symlink to `~/.ssh` is also blocked

**Fidelity Review**: Verify implementation matches spec - all dangerous paths blocked, override flag works, symlinks resolved correctly, error messages are clear and actionable.

### Phase 2: Gateway Service

**Purpose**: Provide HTTP gateway for git operations that holds real credentials, issuing session tokens to sandboxes.

**Tasks**:
1. Create `gateway/` directory structure
2. Create `gateway/allowlist.conf` as single source of truth for domain allowlist
3. Create build script to generate `dnsmasq.conf` and `tinyproxy.conf` from allowlist
4. Implement `gateway/gateway.py` Flask application with:
   - `/health` endpoint for health checks (used by docker-compose `healthcheck`)
   - `/session/create` endpoint (Unix socket only) for session token + secret generation with container IP binding
   - `/session/destroy` endpoint (Unix socket only) for session cleanup
   - `/git/<owner>/<repo>.git/<path>` endpoint for git Smart HTTP proxying
   - Strict input validation:
     - `owner` regex: `^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`
     - `repo` regex: `^[a-zA-Z0-9._-]+$`
     - Path allowlist: `info/refs`, `git-upload-pack`, `git-receive-pack` only
     - Reject path traversal (`..`), encoded sequences, null bytes
   - Session management with multi-factor validation (token + secret + IP + container ID)
   - Session TTL (24h inactivity, 7d absolute) with garbage collection
   - Structured audit logging to stderr
   - Hard-pin upstream to `github.com`, disable redirects
5. Implement Git Smart HTTP proxy with:
   - Streaming request/response handling (chunked transfer encoding)
   - Proper header forwarding (`Content-Type`, `Expect: 100-continue`)
   - Authorization header replacement (session token → GitHub token)
   - Configurable timeouts (30s connect, 600s transfer)
   - Memory-bounded streaming (no full response buffering)
6. Create `gateway/Dockerfile` with Python/Flask, gunicorn, and dnsmasq
7. Create `gateway/requirements.txt` with Flask, requests, gunicorn
8. Add LFS detection with 501 response and clear error message
9. Implement IP literal rejection at proxy level

**Verification**:
- Gateway health check returns 200
- Session creation returns valid token with container IP binding
- Git clone via gateway URL works for authorized repos
- Git clone for unauthorized repo returns 403
- Git clone from wrong container IP returns 401
- Request with invalid owner/repo format returns 400
- Request to non-git path (e.g., `/git/owner/repo/api/...`) returns 403
- Request with path traversal (`../`) returns 400
- Large repo clone (>100MB) streams correctly without OOM
- LFS URLs return 501 Not Implemented with clear message
- Audit logs show session lifecycle and access events

**Fidelity Review**: Verify gateway implements all endpoints per spec, session binding includes IP validation, streaming handles large repos without memory issues, error messages match spec, audit logging works.

### Phase 3: Docker Networking

**Purpose**: Configure Docker networks to isolate sandbox from external access except through gateway and proxy.

**Tasks**:
1. Add `sandbox_internal` network with `internal: true` and `com.docker.network.bridge.enable_icc=false` to `docker-compose.yml`
2. Add iptables rules to allow sandbox→gateway/proxy while blocking sandbox→sandbox
3. Add gateway service to docker-compose with:
   - Access to both `sandbox_internal` and `default` networks
   - Unix socket volume mount for host CLI communication
   - `healthcheck` configuration
   - `GH_TOKEN` environment variable from host
3. Add egress-proxy service (tinyproxy) with generated config from allowlist
4. Update dev service to:
   - Use `sandbox_internal` network ONLY (explicitly remove default network)
   - Set `HTTP_PROXY`/`HTTPS_PROXY` env vars pointing to egress-proxy
   - Set `NO_PROXY=gateway` to allow direct gateway access
   - Use gateway as DNS server (`dns: [gateway]`)
5. Add host iptables rules in `safety/network-firewall.sh`:
   - DOCKER-USER chain: block sandbox subnet from direct external egress
   - Block outbound port 53 except to gateway IP
6. Configure `depends_on` with health checks for proper startup ordering
7. Document network topology with proof of no bypass path

**Verification**:
- `curl --noproxy '*' https://example.com` from sandbox fails (connection refused/no route)
- `curl https://api.anthropic.com` from sandbox works (via proxy)
- `curl https://evil.com` from sandbox fails (proxy 403)
- `curl http://1.2.3.4/` from sandbox fails (proxy rejects IP literals)
- `nslookup secret.attacker.com` from sandbox returns NXDOMAIN
- `nslookup dns.google` from sandbox returns NXDOMAIN (DoH blocked)
- Sandbox cannot ping or connect to other sandboxes (ICC disabled)
- `pip install requests` works (allowlist includes PyPI + CDN)
- `npm install lodash` works (allowlist includes npm + CDN)
- Gateway starts before sandbox (health check ordering)

**Fidelity Review**: Verify network isolation is complete - no bypass paths via direct egress, IP literals, or alternate DNS. Verify proxy works for allowed domains. Verify common package manager workflows succeed. Verify startup ordering prevents race conditions.

### Phase 4: Git URL Rewriting & Integration

**Purpose**: Automatically rewrite git URLs to use gateway, ensuring credentials never reach sandbox.

**Tasks**:
1. Update `Dockerfile` to bake in `/etc/gitconfig` with URL rewriting rules:
   - `https://github.com/` → `http://gateway:8080/git/`
   - `git@github.com:` → `http://gateway:8080/git/`
2. Add credential helper in gitconfig that:
   - Reads token from `/run/secrets/gateway_token` file
   - Outputs via git credential helper stdout protocol (`password=<token>`)
   - Never logs or echoes the token
3. Add `validate_git_remotes()` function to `lib/validate.sh` to detect embedded credentials in `.git/config`
4. Integrate remote validation into sandbox creation flow
5. Update `commands/new.sh` to:
   - Start gateway service if not running
   - Call gateway `/session/create` (via Unix socket) with container ID and repo list
   - Wait for gateway health check before proceeding
   - Write token to tmpfs-mounted secret file (`/run/secrets/gateway_token`)
   - Mount tmpfs at `/run/secrets` with size=4k, mode=0400
6. Update `commands/destroy.sh` to:
   - Call gateway `/session/destroy` on sandbox destroy
7. Update `commands/start.sh` to:
   - Generate new session token on restart
   - Update container's `GATEWAY_TOKEN` env var
8. Add feature flag `SANDBOX_GATEWAY_ENABLED` (default: true) for rollback capability
9. Add clear error messages when gateway is unavailable at sandbox start

**Verification**:
- `git clone https://github.com/org/repo.git` rewrites to gateway URL automatically
- `git push origin main` works through gateway
- Embedded credential detection catches `://user:pass@` patterns
- `env | grep GH_TOKEN` in sandbox returns empty
- `env | grep GATEWAY_TOKEN` returns empty (token in file, not env)
- `cat /run/secrets/gateway_token` shows session token (expected, scoped)
- Token file has 0400 permissions
- Gateway unavailable at start produces clear error with remediation steps
- Feature flag `SANDBOX_GATEWAY_ENABLED=false` disables gateway integration
- Container restart generates new session token
- Old session token rejected after restart

**Fidelity Review**: Verify git operations work end-to-end through gateway, credentials never appear in sandbox (except scoped session token), feature flag works for rollback, restart behavior generates fresh tokens, error handling is user-friendly with remediation guidance.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `lib/validate.sh` | Modify | Dangerous path blocklist + symlink resolution + git remote validation |
| `commands/new.sh` | Modify | Validate mounts, call gateway session create, pass token |
| `commands/destroy.sh` | Modify | Call gateway session destroy |
| `commands/start.sh` | Modify | Generate new session token on restart |
| `docker-compose.yml` | Modify | Add gateway + proxy services, internal network |
| `Dockerfile` | Modify | Bake git URL rewrite into /etc/gitconfig |
| `safety/network-firewall.sh` | Modify | Add DOCKER-USER rules, block port 53 except gateway |
| `gateway/gateway.py` | Create | HTTP gateway with streaming git proxy, session management |
| `gateway/Dockerfile` | Create | Gateway container (Python + dnsmasq) |
| `gateway/requirements.txt` | Create | Python dependencies (Flask, requests, gunicorn) |
| `gateway/allowlist.conf` | Create | Single source of truth for domain allowlist |
| `gateway/build-configs.sh` | Create | Generate dnsmasq.conf + tinyproxy.conf from allowlist |
| `gateway/tinyproxy.conf` | Generated | Egress proxy domain allowlist |
| `gateway/dnsmasq.conf` | Generated | DNS allowlist (blocks exfiltration + DoH) |

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Gateway becomes single point of failure | High | Health checks, `depends_on` ordering, clear error messages when unavailable |
| Session token replay from other container | High | Token bound to source IP, gateway validates IP on every request; ICC disabled prevents cross-sandbox attacks |
| Token exposure via /proc or docker inspect | High | Token in tmpfs file (0400), not in environment variables |
| Token theft from sandbox memory | Medium | Tokens require secret + IP + container ID; multi-factor binding prevents simple replay |
| SSRF via gateway | High | Upstream hard-pinned to github.com, redirects disabled, strict path allowlist |
| Path traversal | High | Strict regex validation, canonicalization, reject encoded sequences |
| Proxy bypass via direct IP | Medium | Proxy rejects IP literals, internal-only network, iptables backup |
| DNS exfiltration | Medium | Force DNS through gateway, block port 53 elsewhere, block DoH endpoints |
| Symlink attacks on mount paths | Medium | `realpath -m` for canonical path resolution |
| Static allowlist breaks package installs | Medium | Comprehensive baseline including CDN domains, documented update process |
| Git LFS/submodules fail unexpectedly | Low | Explicit out-of-scope with clear 501 error message |
| Large repo clone OOMs gateway | Medium | Streaming proxy, no full response buffering |
| Unix socket exposed to other users | Medium | 0600 permissions, protected directory, owner validation |

## Success Criteria

- [ ] Mounting `~/.ssh`, `~/.aws`, or other dangerous paths is blocked by default
- [ ] Git operations work through gateway without real credentials in sandbox
- [ ] Session tokens are bound to container IP + secret + container ID (multi-factor)
- [ ] Sessions expire after 24h inactivity, 7d absolute maximum
- [ ] Invalid owner/repo format requests return 400
- [ ] Non-git paths return 403
- [ ] HTTP requests only succeed for allowlisted domains
- [ ] DNS queries for non-allowlisted domains return NXDOMAIN
- [ ] DoH endpoints are blocked (dns.google, cloudflare-dns.com)
- [ ] `env | grep GH_TOKEN` in sandbox returns empty
- [ ] `env | grep GATEWAY_TOKEN` in sandbox returns empty (token in file, not env)
- [ ] Token file at `/run/secrets/gateway_token` has 0400 permissions
- [ ] Sandboxes cannot communicate with each other (ICC disabled)
- [ ] Direct external network access fails (`curl --noproxy '*'`)
- [ ] IP literal requests fail at proxy
- [ ] Unauthorized repository access returns 403
- [ ] Common package manager workflows (pip, npm, go, cargo) work out of the box
- [ ] Gateway failure at startup produces clear error message with remediation
- [ ] Feature flag can disable gateway integration for debugging
- [ ] Audit logs capture session lifecycle and access decisions
- [ ] Unix socket has 0600 permissions

## Assumptions

- GitHub is the primary git provider (other providers can be added later)
- Docker internal networking provides sufficient isolation when sandbox has NO default network
- Session tokens bound to container IP provide adequate replay protection for v1
- Existing network firewall (iptables) can be extended as defense-in-depth
- One shared gateway service per host (not per-sandbox) is acceptable for v1
- Git LFS and cross-host submodules are acceptable to defer to v2
- Container IP remains stable during container lifetime (Docker default behavior)
- In-memory session storage (lost on gateway restart) is acceptable for v1
