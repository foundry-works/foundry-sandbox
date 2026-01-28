# Credential Isolation: Gateway Sidecar (No Credentials in Sandbox)

## Summary

Implement the gateway sidecar pattern for foundry-sandbox so **external credentials never enter sandbox containers**. All authenticated operations (git and API calls) go through a gateway service that holds credentials. Sandbox containers run on an internal-only network, and all outbound egress is forced through an allowlisted HTTP(S) proxy.

---

## Architecture Overview

```
┌─────────────────────────────┐     ┌─────────────────────────────┐     ┌─────────────────────────────┐
│  Sandbox Container          │     │  Gateway Service            │     │  Egress Proxy               │
│  (No external credentials)  │     │  (Holds external creds)     │     │  (Allowlisted outbound)     │
│                             │     │                             │     │                             │
│  git push/fetch ────────────┼────►│  Git Smart HTTP endpoint    │     │                             │
│  (http://gateway:8080)      │     │  pushes to upstream w/ token│     │                             │
│                             │     │                             │     │                             │
│  HTTP(S) traffic ───────────┼───────────────────────────────────┼────►│  HTTP(S) proxy allowlist    │
│  (via proxy:3128)           │     │                             │     │                             │
└─────────────────────────────┘     └─────────────────────────────┘     └─────────────────────────────┘
       sandbox_internal                 sandbox_internal + external            sandbox_internal + external
```

Notes:
- The **gateway may be a container**; the requirement is that sandbox containers never see external tokens.
- The **egress proxy** can be a separate service or embedded in the gateway container.
- A **local gateway auth token** can be used for gateway APIs; it is not an external credential.

---

## Implementation Phases

### Phase 1: Dangerous Directory Blocklist (Foundation)

**Goal:** Prevent mounting credential directories/files into any sandbox.

**Files to modify:**
- `lib/validate.sh` - Add `DANGEROUS_PATHS` and `validate_mount_path()`
- `commands/new.sh` - Call validation for each mount
- `lib/arg_parser.sh` - Add `--allow-dangerous-mount` flag

**Notes:**
- Treat both directories and files as dangerous.
- This list is **non-exhaustive** by design; allow user extension via env or config.

**Implementation (sketch):**
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
```

---

### Phase 2: Gateway Service (Git Smart HTTP + Auth)

**Goal:** Handle authenticated git operations and API calls without placing tokens in sandbox containers.

**Key design choice:** Git runs in the **gateway**, not the sandbox.

**New files to create:**
```
gateway/
├── Dockerfile.gateway
├── gateway.py              # HTTP server (health + auth + routing)
├── git_http_backend.py     # Git Smart HTTP handler (git http-backend)
├── repo_registry.py        # Maps repo IDs to upstream remotes
├── auth.py                 # Simple Bearer token validation
├── requirements.txt
└── repos.json              # Allowed repos + upstream remotes (gateway-only)
```

**Gateway behavior:**
- `/health` returns 200 OK.
- `/git/<repo>.git/*` implements Git Smart HTTP using `git http-backend`.
- Gateway pushes to upstream using `GH_TOKEN` or other credentials in its own env.
- All gateway endpoints require `Authorization: Bearer $GATEWAY_AUTH_TOKEN` (local-only token).

**Why Git Smart HTTP:**
- Avoids sharing the workspace volume.
- Eliminates `repo_path` from untrusted user input.
- Works with standard `git push` from the sandbox against the gateway URL.

---

### Phase 3: Docker Networking + Egress Proxy

**Goal:** Sandbox has no direct external egress; all outbound traffic uses a proxy with an allowlist.

**Files to modify:**
- `docker-compose.yml` - Add gateway + egress-proxy services and internal network
- `commands/new.sh` - Ensure env vars and flags are wired

**docker-compose.yml (conceptual):**
```yaml
networks:
  sandbox_internal:
    driver: bridge
    internal: true
  sandbox_external:
    driver: bridge

services:
  gateway:
    build:
      context: ./gateway
      dockerfile: Dockerfile.gateway
    environment:
      - GH_TOKEN
      - CLAUDE_CODE_OAUTH_TOKEN
      - OPENAI_API_KEY
      - CURSOR_API_KEY
      - TAVILY_API_KEY
      - PERPLEXITY_API_KEY
      - GATEWAY_AUTH_TOKEN
    networks:
      - sandbox_internal
      - sandbox_external

  egress-proxy:
    image: squid:latest  # or tinyproxy
    volumes:
      - ./gateway/squid.conf:/etc/squid/squid.conf:ro
    networks:
      - sandbox_internal
      - sandbox_external

  dev:
    environment:
      - HTTP_PROXY=http://egress-proxy:3128
      - HTTPS_PROXY=http://egress-proxy:3128
      - NO_PROXY=localhost,127.0.0.1,gateway,egress-proxy
      - GIT_GATEWAY_URL=http://gateway:8080
      - GATEWAY_AUTH_TOKEN=${GATEWAY_AUTH_TOKEN}
    networks:
      - sandbox_internal
    depends_on:
      - gateway
      - egress-proxy
```

**Allowlist model:**
- Maintain `gateway/egress_allowlist.txt` or `gateway/squid.conf` with explicit hostnames.
- Provide CLI flags to add hosts or disable proxying for specific cases.

---

### Phase 4: Git URL Rewrite + Remote Sanitization

**Goal:** Ensure git in the sandbox always targets the gateway and never embeds tokens.

**Changes:**
- In `entrypoint.sh`, rewrite common git hosts:
  ```bash
  git config --global url."${GIT_GATEWAY_URL}/git/github/".insteadOf "https://github.com/"
  git config --global url."${GIT_GATEWAY_URL}/git/github/".insteadOf "git@github.com:"
  ```
- Add a preflight check in `commands/new.sh` (or a helper) to **block remotes with embedded tokens**.

---

### Phase 5: Migration Strategy

1. **Phase 1 first** — blocklist is backward compatible
2. **Gateway opt-in** — add `--with-gateway` initially
3. **Egress proxy opt-in** — `--egress-allowlist` or `--egress-proxy`
4. **Make gateway + proxy default** for new sandboxes
5. **Deprecate direct creds** — warn if credentials passed directly
6. **Remove direct support** in a major version

**Backward compatibility flags:**
- `--allow-dangerous-mount`
- `--with-gateway` / `--no-gateway`
- `--egress-allowlist <file|comma>`
- `--allow-egress` (temporary escape hatch)

---

## Files Summary

| File | Action | Purpose |
|------|--------|---------|
| `lib/validate.sh` | Modify | Add dangerous path blocklist |
| `commands/new.sh` | Modify | Validate mounts + wire gateway/proxy flags |
| `lib/arg_parser.sh` | Modify | Add new flags |
| `docker-compose.yml` | Modify | Add gateway + egress proxy services |
| `gateway/gateway.py` | Create | HTTP server + auth |
| `gateway/git_http_backend.py` | Create | Git Smart HTTP handler |
| `gateway/repo_registry.py` | Create | Repo mapping + allowlist |
| `gateway/auth.py` | Create | Bearer auth validation |
| `gateway/requirements.txt` | Create | Python deps |
| `gateway/squid.conf` | Create | Egress proxy allowlist |
| `entrypoint.sh` | Modify | Git URL rewrite for gateway |

---

## Verification

1. **Blocklist:** `sandbox new repo --mount ~/.ssh:/ssh` fails with clear error
2. **Gateway health:** `curl http://gateway:8080/health` returns 200 (from sandbox)
3. **No creds in sandbox:** `env | grep -E 'TOKEN|KEY'` returns empty for external creds
4. **Egress isolation:** `curl https://example.com` fails without proxy; succeeds with proxy
5. **Git push:** `git push` to a GitHub remote works via gateway URL rewrite
6. **Allowlist enforcement:** request to a non-allowlisted host is blocked by proxy
