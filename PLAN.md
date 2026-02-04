# Consolidated Proxy Architecture Plan

## Overview

Consolidate the gateway and api-proxy into a single mitmproxy-based service that handles all external traffic (git operations + API calls). Replace session tokens with container identity.

## Current Architecture (2 Services)

```
┌─────────────────────────────────────────────────────────┐
│  SANDBOX CONTAINER                                       │
│  - No real credentials                                   │
│  - Session token for git                                 │
│  - Placeholder tokens for APIs                           │
└─────────────────────────────────────────────────────────┘
         │                              │
         │ git (session token)          │ HTTPS (placeholder)
         ▼                              ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│  GATEWAY (Flask)    │      │  API-PROXY (mitmproxy)      │
│  - Session mgmt     │      │  - Credential injection     │
│  - Git proxy        │      │  - OAuth token mgmt         │
│  - DNS (dnsmasq)    │      │  - GitHub API filter        │
│  - Policy checks    │      │  - Egress filtering         │
└─────────────────────┘      └─────────────────────────────┘
         │                              │
         ▼                              ▼
    github.com              api.anthropic.com, etc.
```

**Problems:**
- Two services doing similar things (proxying, policy, credential handling)
- Session token indirection adds complexity
- PLAN.md Phase 2 would add GitHub API proxy to gateway → more overlap

## Proposed Architecture (1 Service + DNS)

```
┌─────────────────────────────────────────────────────────┐
│  SANDBOX CONTAINER                                       │
│  - No real credentials                                   │
│  - Identified by container IP (no session tokens)        │
│  - HTTP_PROXY / HTTPS_PROXY → unified-proxy:8080        │
│  - Git uses same proxy (GIT_PROXY_COMMAND or env)        │
└─────────────────────────────────────────────────────────┘
         │
         │ ALL traffic (git + APIs)
         ▼
┌─────────────────────────────────────────────────────────┐
│  UNIFIED-PROXY (mitmproxy)                              │
│                                                          │
│  Addons:                                                 │
│  ├─ container_identity.py    # ID by source IP          │
│  ├─ policy_engine.py         # Centralized policy       │
│  ├─ git_proxy.py             # Git protocol handling    │
│  ├─ credential_injector.py   # API credential injection │
│  ├─ github_filter.py         # GitHub API policy        │
│  └─ oauth_managers/          # Token refresh handlers   │
│                                                          │
│  Config per container:                                   │
│  - Authorized repos                                      │
│  - Auth mode (user/bot)                                  │
│  - Credential access rules                               │
└─────────────────────────────────────────────────────────┘
         │
         ▼
   github.com, api.anthropic.com, api.openai.com, etc.

┌─────────────────────────────────────────────────────────┐
│  DNS SERVICE (dnsmasq) - lightweight, separate          │
│  - Domain allowlisting                                   │
│  - Could potentially move into unified-proxy too        │
└─────────────────────────────────────────────────────────┘
```

## Key Changes

### 1. Container Identity Replaces Sessions

**Before:** Host creates session → gets token → passes to container → container uses token
**After:** Host registers container IP + config → proxy identifies by IP

```python
# container_identity.py (new mitmproxy addon)

CONTAINER_REGISTRY = {}  # IP → config mapping

class ContainerIdentity:
    """Identify containers by source IP, enforce per-container policy."""

    def request(self, flow):
        client_ip = flow.client_conn.peername[0]

        if client_ip not in CONTAINER_REGISTRY:
            flow.response = Response.make(403, b"Unknown container")
            return

        # Attach container config to flow for other addons
        flow.metadata["container"] = CONTAINER_REGISTRY[client_ip]
```

**Registration endpoint** (simple HTTP API on proxy, localhost only):
```
POST /internal/register
{
  "container_ip": "172.18.0.5",
  "container_id": "abc123",
  "repos": ["owner/repo1", "owner/repo2"],
  "auth_mode": "bot",
  "expires_at": "2024-01-15T00:00:00Z"
}

DELETE /internal/register/{container_ip}
```

### 2. Git Handled by mitmproxy

Git over HTTPS works through HTTP proxy. mitmproxy intercepts:

```python
# git_proxy.py (new mitmproxy addon)

class GitProxy:
    """Handle git operations with policy enforcement."""

    def request(self, flow):
        if not self._is_git_request(flow):
            return

        container = flow.metadata.get("container")
        if not container:
            return  # ContainerIdentity addon will reject

        # Check repo authorization
        owner, repo = self._extract_repo(flow.request.path)
        if f"{owner}/{repo}" not in container["repos"]:
            flow.response = Response.make(403, b"Repo not authorized")
            return

        # For git-receive-pack (push), check policy
        if "git-receive-pack" in flow.request.path:
            self._check_push_policy(flow, container)

    def _check_push_policy(self, flow, container):
        """Parse pkt-line, detect force push/deletion."""
        body = flow.request.content
        updates = parse_pktline(body)

        for old_sha, new_sha, refname, _ in updates:
            # Block deletion
            if new_sha == ZERO_SHA:
                flow.response = Response.make(403,
                    f"Branch deletion blocked: {refname}".encode())
                return

            # Block force push (non-fast-forward)
            if not self._is_fast_forward(old_sha, new_sha, owner, repo):
                flow.response = Response.make(403,
                    f"Force push blocked: {refname}".encode())
                return

            # Bot mode: restrict to sandbox/* branches
            if container["auth_mode"] == "bot":
                if not refname.startswith("refs/heads/sandbox/"):
                    flow.response = Response.make(403,
                        f"Bot mode: can only push to sandbox/* branches".encode())
                    return
```

### 3. Unified Policy Engine

```python
# policy_engine.py (new mitmproxy addon)

class PolicyEngine:
    """Centralized policy for all operations."""

    def __init__(self):
        self.config = load_config()  # From YAML or env
        self._compile_patterns()

    def request(self, flow):
        container = flow.metadata.get("container")
        host = flow.request.host
        method = flow.request.method
        path = flow.request.path

        # Check blocked API patterns
        result = self.check_api_endpoint(host, path, method)
        if not result.allowed:
            flow.response = Response.make(403, result.reason.encode())
            return

    def check_api_endpoint(self, host, path, method):
        """Check if API endpoint is allowed."""
        if host == "api.github.com":
            # Block PR merge
            if method == "PUT" and re.match(r'/repos/[^/]+/[^/]+/pulls/\d+/merge', path):
                return PolicyResult(False, "PR merge blocked - use GitHub UI")
            # Block release creation
            if method == "POST" and re.match(r'/repos/[^/]+/[^/]+/releases$', path):
                return PolicyResult(False, "Release creation blocked")

        return PolicyResult(True)
```

### 4. Credential Injection (Existing, Minor Changes)

Current `inject-credentials.py` stays mostly the same. Changes:
- GitHub token injection now applies to git operations too (unified)
- Can check `flow.metadata["container"]` for per-container rules

### 5. DNS Options

**Option A: Keep dnsmasq separate (simpler)**
- Tiny service, just DNS
- Already works well
- Rename from "gateway" to "dns" for clarity

**Option B: Integrate into mitmproxy**
- mitmproxy can do DNS via `dns` addon (experimental)
- Reduces to truly single service
- More complex, less battle-tested

**Recommendation:** Keep DNS separate for now (Option A). It's lightweight and works.

## File Structure

```
unified-proxy/                # Renamed from api-proxy/
├── addons/
│   ├── __init__.py
│   ├── container_identity.py  # NEW: Container registration + ID
│   ├── policy_engine.py       # NEW: Centralized policy
│   ├── git_proxy.py           # NEW: Git protocol handling
│   ├── credential_injector.py # REFACTORED: from inject-credentials.py
│   ├── github_filter.py       # EXISTS: merged into policy_engine
│   └── oauth_managers/
│       ├── __init__.py
│       ├── codex.py           # EXISTS: from codex-token-manager.py
│       ├── gemini.py          # EXISTS: from gemini-token-manager.py
│       └── opencode.py        # EXISTS: from opencode-token-manager.py
├── pktline.py                 # NEW: Git pkt-line parser (from gateway)
├── config.py                  # NEW: Unified config loader
├── internal_api.py            # NEW: /internal/* endpoints for registration
├── entrypoint.sh              # UPDATED
├── Dockerfile                 # UPDATED
└── requirements.txt           # UPDATED

config/
├── policy.yaml.example        # NEW: Example policy config
└── policy.yaml                # GITIGNORED: Actual policy config

dns/                          # RENAMED from gateway/
├── dnsmasq.conf              # EXISTS
├── firewall-allowlist.generated  # EXISTS (shared with proxy)
├── build-configs.sh          # EXISTS
├── entrypoint.sh             # SIMPLIFIED
└── Dockerfile                # SIMPLIFIED: just dnsmasq + config

lib/
├── proxy.sh                  # NEW: replaces gateway.sh
└── gateway.sh                # DELETE after migration

tests/
├── unit/
│   ├── test_container_identity.py
│   ├── test_policy_engine.py
│   ├── test_git_proxy.py
│   └── test_pktline.py
├── integration/
│   ├── test_git_operations.py
│   ├── test_api_proxy.py
│   └── test_container_lifecycle.py
└── security/
    ├── test_policy_bypass.py
    ├── test_container_isolation.py
    └── redteam-sandbox.sh    # EXISTS: updated

docs/
├── architecture.md           # UPDATED
└── adr/
    ├── 000-template.md       # NEW
    ├── 001-consolidation.md  # NEW
    ├── 002-container-identity.md  # NEW
    └── 003-policy-engine.md  # NEW
```

## Critical Files to Modify/Create

| File | Action | Priority |
|------|--------|----------|
| `unified-proxy/addons/container_identity.py` | Create | Phase 1 |
| `unified-proxy/addons/policy_engine.py` | Create | Phase 2 |
| `unified-proxy/addons/git_proxy.py` | Create | Phase 3 |
| `unified-proxy/pktline.py` | Port from gateway | Phase 3 |
| `unified-proxy/internal_api.py` | Create | Phase 1 |
| `config/policy.yaml.example` | Create | Phase 2 |
| `lib/proxy.sh` | Create | Phase 5 |
| `docker-compose.credential-isolation.yml` | Modify | Phase 5 |
| `dns/Dockerfile` | Simplify | Phase 5 |
| `gateway/gateway.py` | Delete | Phase 6 |

## Implementation Phases

### Phase 0: Research & Setup
**Goal:** Validate git proxy approach, set up test infrastructure

1. Create test environment with mitmproxy + test container
2. Test git proxy methods:
   - `http.proxy` git config
   - `GIT_PROXY_COMMAND`
   - `ALL_PROXY` environment
3. Document findings, choose approach
4. Set up test structure (`tests/unit/`, `tests/integration/`)
5. Write ADR-001 (Consolidation decision)

**Deliverables:**
- Research findings document
- ADR-001
- Test infrastructure

### Phase 1: Container Identity
**Goal:** Replace session tokens with container IP identity

**Files:**
- `api-proxy/addons/container_identity.py` (new)
- `api-proxy/tests/test_container_identity.py` (new)
- `lib/proxy.sh` (new, replaces gateway.sh session functions)

**Implementation:**
```python
# container_identity.py
CONTAINER_REGISTRY: Dict[str, ContainerConfig] = {}

@dataclass
class ContainerConfig:
    container_id: str
    repos: List[str]
    auth_mode: str  # 'user' or 'bot'
    expires_at: datetime
    created_at: datetime

class ContainerIdentity:
    def request(self, flow: HTTPFlow):
        client_ip = flow.client_conn.peername[0]
        if client_ip not in CONTAINER_REGISTRY:
            flow.response = Response.make(403, b'{"error": "Unknown container"}')
            return
        config = CONTAINER_REGISTRY[client_ip]
        if datetime.utcnow() > config.expires_at:
            del CONTAINER_REGISTRY[client_ip]
            flow.response = Response.make(403, b'{"error": "Container registration expired"}')
            return
        flow.metadata["container"] = config
```

**Registration API** (internal endpoint, localhost only):
```python
@app.route('/internal/containers', methods=['POST'])
def register_container():
    # Validate localhost
    # Parse config, add to CONTAINER_REGISTRY
    pass

@app.route('/internal/containers/<ip>', methods=['DELETE'])
def unregister_container(ip):
    # Remove from CONTAINER_REGISTRY
    pass
```

**Verification:**
- Unknown IP → 403
- Registered IP → request proceeds
- Expired registration → 403

### Phase 2: Policy Engine
**Goal:** Centralized policy checks (adapted from PLAN.md)

**Files:**
- `api-proxy/addons/policy_engine.py` (new)
- `api-proxy/tests/test_policy_engine.py` (new)
- `config/policy.yaml` (new)

**Implementation:** (same PolicyResult, check methods from PLAN.md, adapted to mitmproxy)
```python
# policy_engine.py
from config import load_config

@dataclass
class PolicyResult:
    allowed: bool
    reason: Optional[str] = None

class PolicyEngine:
    def __init__(self):
        self.config = load_config().get('policy', {})
        self._blocked_patterns = self._compile_patterns()

    def request(self, flow: HTTPFlow):
        result = self.check_api_endpoint(
            flow.request.host,
            flow.request.path,
            flow.request.method
        )
        if not result.allowed:
            flow.response = Response.make(403, json.dumps({
                'error': result.reason
            }).encode())
```

**Verification:**
- `PUT /repos/x/y/pulls/1/merge` → 403
- `POST /repos/x/y/releases` → 403
- `GET /repos/x/y/pulls` → allowed

### Phase 3: Git Proxy
**Goal:** Handle git operations in mitmproxy

**Files:**
- `api-proxy/addons/git_proxy.py` (new)
- `api-proxy/pktline.py` (ported from gateway/gateway.py)
- `api-proxy/tests/test_git_proxy.py` (new)
- `api-proxy/tests/test_pktline.py` (new)

**Implementation:**
- Port `parse_pktline()` and `check_ref_updates()` from gateway.py
- Add mitmproxy addon for git request handling
- Implement repo authorization check
- Implement force-push/deletion detection
- Implement auth mode branch restrictions

**Verification:**
- Clone authorized repo → works
- Clone unauthorized repo → 403
- Push with force → 403
- Delete branch → 403
- Bot mode push to `main` → 403
- Bot mode push to `sandbox/feature` → works

### Phase 4: Credential Injection Refactor
**Goal:** Integrate existing credential injection with new architecture

**Files:**
- `api-proxy/addons/credential_injector.py` (refactored from inject-credentials.py)
- `api-proxy/addons/oauth_managers/` (moved from root)

**Changes:**
- Move inject-credentials.py logic into addon class
- Integrate with container identity for per-container rules (optional)
- Ensure GitHub token injection works for both git and API

**Verification:**
- API calls get credentials injected
- Git operations get GitHub token
- OAuth refresh flows work

### Phase 5: Infrastructure Changes
**Goal:** Update Docker setup, simplify gateway → dns

**Files:**
- `docker-compose.credential-isolation.yml` (modified)
- `dns/` (new directory, from gateway/)
- `dns/Dockerfile` (minimal, dnsmasq only)
- `dns/entrypoint.sh` (simplified)
- `lib/proxy.sh` (finalized)

**Changes:**
- Rename `api-proxy/` → `unified-proxy/` (optional, for clarity)
- Remove Flask app from gateway, keep only dnsmasq
- Rename gateway service to "dns"
- Update sandbox entrypoint to use new registration
- Update docker-compose environment variables

**Verification:**
- `docker-compose up` starts both services
- DNS resolution works
- Git and API traffic flows through unified proxy

### Phase 6: Cleanup & Documentation
**Goal:** Remove old code, update docs

**Files:**
- `gateway/gateway.py` (delete)
- `gateway/test_gateway.py` (delete)
- `lib/gateway.sh` (delete, replaced by proxy.sh)
- `docs/architecture.md` (update)
- `docs/adr/001-consolidation.md` (finalize)
- `docs/adr/002-container-identity.md` (write)
- `docs/adr/003-policy-engine.md` (write)
- `PLAN.md` (archive or delete)
- `COMPARISON.md` (archive or delete)

**Verification:**
- All tests pass
- Security tests pass
- Documentation reflects new architecture

## Testing Strategy

### Unit Tests (pytest)
```python
# test_git_proxy.py
import pytest
from mitmproxy.test import tflow
from addons.git_proxy import GitProxy

def test_push_to_unauthorized_repo():
    addon = GitProxy()
    flow = tflow.tclientconn()
    flow.request.path = "/owner/unauthorized-repo.git/git-receive-pack"
    flow.metadata["container"] = {"repos": ["owner/other-repo"]}

    addon.request(flow)

    assert flow.response.status_code == 403
    assert b"not authorized" in flow.response.content

def test_force_push_blocked():
    # ... test pkt-line parsing and force push detection
```

### Integration Tests
```bash
# Start unified-proxy in test mode
docker-compose -f docker-compose.test.yml up -d

# Register test container
curl -X POST http://localhost:8080/internal/register \
  -d '{"container_ip": "172.18.0.5", "repos": ["test/repo"]}'

# Test git clone (should work)
docker exec test-sandbox git clone http://github.com/test/repo

# Test git push to unauthorized repo (should fail)
docker exec test-sandbox git push http://github.com/other/repo  # 403

# Test PR merge API (should fail)
docker exec test-sandbox curl -X PUT http://api.github.com/repos/test/repo/pulls/1/merge  # 403
```

### Security Tests
- Verify container can't access other container's repos
- Verify force push detection works
- Verify PR merge blocking works
- Verify unknown container IPs are rejected

## Configuration

### Per-Container Config (at registration)
```json
{
  "container_ip": "172.18.0.5",
  "container_id": "abc123def456",
  "repos": ["owner/repo1", "owner/repo2"],
  "auth_mode": "bot",
  "allowed_branches": ["sandbox/*", "bot/*"],
  "expires_at": "2024-01-15T00:00:00Z"
}
```

### Global Policy Config (YAML)
```yaml
# config/policy.yaml
policy:
  blocked_api_patterns:
    PUT:
      - "^/repos/[^/]+/[^/]+/pulls/\\d+/merge$"
    POST:
      - "^/repos/[^/]+/[^/]+/releases$"
    DELETE:
      - "^/repos/[^/]+/[^/]+$"

  protected_branches:
    - main
    - master

  allow_force_push: false
  allow_branch_deletion: false
```

## What Gets Simpler

1. **No session token dance** - Container identity is implicit
2. **Single proxy for everything** - No routing decisions
3. **Unified policy** - One place for all security rules
4. **Easier debugging** - One service's logs to check
5. **Consistent credential handling** - Same pattern for git and APIs

## What Gets More Complex

1. **mitmproxy addon testing** - Different paradigm than Flask
2. **Git protocol in mitmproxy** - New code, needs careful implementation
3. **Container registration** - New endpoint to manage

## Research: Git Proxy Methods

Before implementation, test both approaches to determine which works best with mitmproxy:

### Option A: `http.proxy` git config
```bash
# Global config
git config --global http.proxy http://unified-proxy:8080
git config --global https.proxy http://unified-proxy:8080

# Or per-repo
git config http.proxy http://unified-proxy:8080
```

**Test points:**
- Does mitmproxy see git-upload-pack/git-receive-pack correctly?
- Does HTTPS certificate validation work with mitmproxy CA?
- Does streaming (large repos) work without buffering issues?

### Option B: `GIT_PROXY_COMMAND`
```bash
# Environment variable
export GIT_PROXY_COMMAND=/usr/local/bin/git-proxy-wrapper

# Wrapper script
#!/bin/bash
exec nc -X connect -x unified-proxy:8080 "$@"
```

**Test points:**
- Does this work for HTTPS git URLs?
- Is netcat/socat required in container?
- How does authentication flow differ?

### Option C: ALL_PROXY environment
```bash
export ALL_PROXY=http://unified-proxy:8080
export http_proxy=http://unified-proxy:8080
export https_proxy=http://unified-proxy:8080
```

**Test points:**
- Does git respect ALL_PROXY?
- Interaction with GnuTLS vs OpenSSL?

**Research task:** Create a test container with mitmproxy and try all three methods with `git clone` and `git push` to a test repo.

## Merged Elements from PLAN.md

### Keep and Adapt

| PLAN.md Element | Adaptation for Consolidated Architecture |
|-----------------|------------------------------------------|
| **Policy Engine design** | Same PolicyResult dataclass, same check methods - just in mitmproxy addon |
| **Blocked API patterns** | Move to `policy_engine.py` addon, load from config |
| **YAML config structure** | Same `config/policy.yaml` format, loaded by mitmproxy |
| **ADR documentation** | Keep ADR format, document consolidation decision |
| **Test organization** | `tests/unit/`, `tests/integration/`, `tests/security/` structure |
| **Auth modes (bot/user)** | Per-container config instead of per-session |
| **Protected branches** | Same logic in `git_proxy.py` addon |
| **Fail-closed design** | Same principle - unknown containers rejected, policy errors → deny |

### Discard

| PLAN.md Element | Reason |
|-----------------|--------|
| **Session token management** | Replaced by container identity |
| **Flask gateway additions** | Gateway becomes DNS-only |
| **Token hashing** | No tokens to hash |
| **`/proxy` endpoint in Flask** | All proxying done by mitmproxy |

### New ADRs Needed

1. **ADR-001: Consolidation to Unified Proxy**
   - Context: Two overlapping services (gateway + api-proxy)
   - Decision: Consolidate into single mitmproxy service
   - Consequences: Simpler architecture, different testing paradigm

2. **ADR-002: Container Identity vs Session Tokens**
   - Context: Session tokens add indirection complexity
   - Decision: Use container IP as implicit identity
   - Consequences: Simpler flow, requires container registration

3. **ADR-003: Policy Engine** (adapted from PLAN.md)
   - Context: Policy scattered across services
   - Decision: Centralized policy in mitmproxy addon
   - Consequences: Single audit point, fail-closed design

## Open Questions

1. **DNS integration**: Keep separate or integrate into mitmproxy later?
   - Recommendation: Keep separate for now (simpler, battle-tested)

2. **Container registration persistence**: In-memory (current sessions) or file/redis?
   - Recommendation: In-memory with optional file backup for restart recovery

## Verification

After implementation:
```bash
# 1. Sandbox can clone authorized repo
git clone https://github.com/owner/authorized-repo  # ✓

# 2. Sandbox cannot clone unauthorized repo
git clone https://github.com/owner/other-repo  # 403 ✓

# 3. Sandbox cannot force push
git push --force origin main  # 403 ✓

# 4. Sandbox cannot merge PR via API
gh pr merge 123  # 403 ✓

# 5. Sandbox can call allowed APIs
curl https://api.anthropic.com/v1/messages  # ✓ (with injected creds)

# 6. Unknown containers are rejected
# (from container not registered)
curl https://api.github.com/user  # 403 ✓
```
