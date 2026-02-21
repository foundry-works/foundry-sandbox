# ADR-009: Dedicated API Gateways with Squid Forward Proxy

## Status

Accepted

Date: 2026-02-21

## Context

The unified proxy needs to inject credentials into outbound API requests without exposing real secrets to sandbox containers. Two approaches exist:

1. **MITM interception** — A TLS-intercepting proxy (mitmproxy) decrypts HTTPS traffic, injects credentials, and re-encrypts. This requires sandboxes to trust a custom CA certificate and adds the full TLS handshake overhead on every request.

2. **Gateway credential injection** — Plaintext HTTP endpoints on the internal Docker network accept requests from sandboxes, inject credentials, and forward to the upstream API over HTTPS. No CA trust required.

The MITM approach works universally but has drawbacks:

- **CA trust surface**: Every sandbox must trust a mitmproxy-generated CA. If the CA private key leaks, any traffic from any sandbox can be decrypted.
- **TLS overhead**: Double TLS handshake (sandbox → proxy, proxy → upstream) adds latency.
- **Provider compatibility**: Some providers pin certificates or reject intercepted connections.
- **Blast radius**: A bug in mitmproxy's TLS handling affects all providers simultaneously.

Many AI providers support custom base URLs via environment variables (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `GITHUB_API_URL`, `GOOGLE_GEMINI_BASE_URL`), making gateway injection feasible for the highest-traffic providers. Providers that lack base URL support (Tavily, Semantic Scholar, Perplexity, Zhipu) still require MITM.

**Gemini (Google AI)** supports `GOOGLE_GEMINI_BASE_URL` in API-key mode (both the Gemini CLI and Python SDK respect this env var), so API-key traffic routes through the Gemini gateway. However, Gemini CLI's OAuth login mode authenticates via `oauth2.googleapis.com` and `accounts.google.com`, which remain on the MITM path.

**Codex (OpenAI CLI)** supports `OPENAI_BASE_URL` in API-key mode, so those requests route through the OpenAI gateway like any other OpenAI SDK call. Codex's subscription/ChatGPT login mode authenticates via `auth.openai.com` and sends requests to the `chatgpt.com/backend-api/` backend, which is unaffected by `OPENAI_BASE_URL`. A dedicated ChatGPT gateway handles subscription-mode traffic via transparent TLS interception: `/etc/hosts` redirects `chatgpt.com` to the proxy IP, the gateway terminates TLS on port 443 using a cert signed by the mitmproxy CA, injects OAuth tokens from the mounted Codex `auth.json`, and forwards to the real `chatgpt.com`. The HTTP listener on port 9852 remains available for tests and direct access.

### Constraints

- Sandboxes communicate via `HTTP_PROXY`/`HTTPS_PROXY` environment variables — the routing mechanism must be transparent to application code.
- The solution must support both gateway-routed and MITM-routed providers simultaneously.
- All credential injection must happen on the isolated Docker network; real credentials never enter sandbox containers.
- The system must fail closed: if a gateway is unavailable, requests should fail rather than bypass credential injection.

## Decision

Route API traffic through five dedicated HTTP gateways for providers that support base URL configuration, with Squid as the forward proxy for domain allowlisting, and mitmproxy as a fallback for MITM-required providers.

### Architecture

```
┌──────────────────────────────────┐
│         SANDBOX CONTAINER        │
│                                  │
│  HTTP_PROXY=http://proxy:8080    │
│  ANTHROPIC_BASE_URL=http://proxy:9848        │
│  OPENAI_BASE_URL=http://proxy:9849           │
│  GITHUB_API_URL=http://proxy:9850            │
│  GOOGLE_GEMINI_BASE_URL=http://proxy:9851    │
│  chatgpt.com → proxy IP (via /etc/hosts)      │
│                                  │
│  SDK calls ──► gateway (direct)  │
│  Other HTTPS ──► Squid (proxy)   │
└──────────┬───────────────────────┘
           │ Docker internal network
           │ (plaintext HTTP)
┌──────────▼───────────────────────────────────────┐
│                  UNIFIED PROXY                    │
│                                                   │
│  ┌──────────────────────────────────────────────┐ │
│  │           API GATEWAYS (aiohttp)             │ │
│  │                                              │ │
│  │  :9848  Anthropic ──► api.anthropic.com       │ │
│  │  :9849  OpenAI    ──► api.openai.com         │ │
│  │  :9850  GitHub    ──► api.github.com         │ │
│  │  :9851  Gemini    ──► generativelanguage..   │ │
│  │  :9852  ChatGPT   ──► chatgpt.com (HTTP)     │ │
│  │  :443   ChatGPT   ──► chatgpt.com (TLS)     │ │
│  │                                              │ │
│  │  Shared: gateway_base.py (factory)           │ │
│  │          gateway_middleware.py (identity,     │ │
│  │            rate limit, circuit breaker,       │ │
│  │            metrics)                           │ │
│  │          security_policies.py (GitHub)        │ │
│  └──────────────────────────────────────────────┘ │
│                                                   │
│  ┌──────────────────────────────────────────────┐ │
│  │       SQUID FORWARD PROXY (:8080)            │ │
│  │                                              │ │
│  │  Allowed domains  ──► direct HTTPS tunnel    │ │
│  │  MITM domains     ──► mitmproxy (:8081)      │ │
│  │  IP literals      ──► deny                   │ │
│  │  Unknown domains  ──► deny                   │ │
│  └──────────────────────────────────────────────┘ │
│                                                   │
│  ┌──────────────────────────────────────────────┐ │
│  │    MITMPROXY (:8081, conditional)            │ │
│  │                                              │ │
│  │  TLS interception for MITM-required          │ │
│  │  providers (Tavily, Perplexity, etc.)        │ │
│  │  DNS filtering (when enabled)                │ │
│  └──────────────────────────────────────────────┘ │
│                                                   │
│  ┌──────────────────┐  ┌────────────────────────┐ │
│  │ Internal API     │  │ Git API (:8083)        │ │
│  │ (Flask, Unix)    │  │ (HMAC-authenticated)   │ │
│  └──────────────────┘  └────────────────────────┘ │
└───────────────────────────────────────────────────┘
```

### Request routing

| Request type | Route | Credential injection |
|---|---|---|
| Anthropic SDK calls | `ANTHROPIC_BASE_URL` → gateway `:9848` | Gateway injects `x-api-key` or `Authorization: Bearer` |
| OpenAI SDK calls | `OPENAI_BASE_URL` → gateway `:9849` | Gateway injects `Authorization: Bearer` |
| GitHub CLI / API | `GITHUB_API_URL` → gateway `:9850` | Gateway injects `Authorization: Bearer` |
| Gemini API-key calls | `GOOGLE_GEMINI_BASE_URL` → gateway `:9851` | Gateway injects `x-goog-api-key` |
| Gemini OAuth calls | `GOOGLE_GEMINI_BASE_URL` → gateway `:9851` | Gateway injects `Authorization: Bearer` |
| ChatGPT/Codex subscription | `/etc/hosts` → gateway `:443` (TLS) | Gateway terminates TLS, injects `Authorization: Bearer` (OAuth) |
| MITM-required providers | `HTTP_PROXY` → Squid `:8080` → mitmproxy `:8081` | mitmproxy injects via TLS interception |
| Other allowed HTTPS | `HTTP_PROXY` → Squid `:8080` → direct tunnel | No injection (SNI splice, no TLS decryption) |
| Blocked domains / IPs | `HTTP_PROXY` → Squid `:8080` → deny | N/A |

### Gateway shared infrastructure

All five gateways share common logic via two modules:

**`gateway_base.py`** — Application factory that creates a fully configured aiohttp `Application` given per-gateway settings. Handles:
- Container identity validation (via `IdentityMiddleware` from the middleware stack)
- Header filtering (strips sandbox-supplied auth headers, hop-by-hop headers, placeholder credentials)
- Credential injection (loads credentials from environment, injects into upstream request)
- Upstream forwarding with streaming response relay
- Error handling (JSON error contract: `{"error": {"type": "...", "message": "..."}}`)
- Health check endpoint (`/health`)

**`gateway_middleware.py`** — Middleware stack applied to all gateways, in order:
1. `IdentityMiddleware` — Resolves container identity from source IP via the container registry; must run first
2. `MetricsMiddleware` — Records request count and latency (Prometheus, optional)
3. `CircuitBreakerMiddleware` — Fails fast when upstream is unhealthy (fail-closed)
4. `RateLimiterMiddleware` — Per-container, per-upstream token bucket

Each gateway module is a thin wrapper (~50-150 lines) that calls `create_gateway_app()` with its specific configuration (upstream URL, credential loader, routes, optional request hook).

### Squid domain routing

Squid reads domain lists generated at startup by `generate_squid_config.py` from `config/allowlist.yaml`:

- `allowed_domains.txt` — All domains permitted for HTTPS tunnelling
- `mitm_domains.txt` — Domains routed to mitmproxy via `cache_peer` for TLS interception

IP literals (dotted decimal, IPv6 brackets, octal, hex, integer) are blocked by Squid ACLs, duplicating the policy engine's `is_ip_literal()` check for defense-in-depth.

### MITM fallback

mitmproxy startup is gated behind `ENABLE_MITM_FALLBACK` and provider credential detection. When no MITM-required provider credentials are configured, mitmproxy runs only for DNS filtering (if enabled) and does not generate a CA certificate.

MITM-required providers: Tavily, Semantic Scholar, Perplexity, Zhipu, and GitHub OAuth/git credential flows. Gemini traffic (both API-key and OAuth) routes through the gateway (:9851). ChatGPT/Codex subscription-mode traffic routes through the gateway via transparent TLS interception (:443) — `/etc/hosts` redirects `chatgpt.com` to the proxy IP and `NO_PROXY` bypasses Squid.

### GitHub gateway: security policy enforcement

The GitHub gateway enforces security policies via a request hook that runs after identity validation but before upstream forwarding. These policies are imported from `security_policies.py` (shared with `addons/policy_engine.py`) to prevent pattern drift:

- **Path normalization** — URL decoding, double-encoding rejection, slash collapsing
- **Merge blocking** — REST merge endpoints and GraphQL `mergePullRequest`/`enablePullRequestAutoMerge` mutations
- **Operation blocklist** — Release creation, ref mutation, webhook management, deploy key operations
- **Body inspection** — PR/issue close detection, PR self-approval detection

## Consequences

### Positive

- **Reduced CA trust surface** — Major providers (Anthropic, OpenAI, GitHub API, Gemini API-key) no longer require MITM; sandboxes only trust the CA for MITM-required providers
- **Lower latency** — No double TLS handshake for gateway-routed traffic
- **Provider isolation** — A bug in one gateway does not affect others; mitmproxy issues only affect MITM-required providers
- **Simpler debugging** — Gateway logs show credential injection decisions per-request without TLS decryption artifacts
- **Defense-in-depth** — GitHub security policies enforced at both the gateway layer and the mitmproxy policy engine

### Negative

- **Process complexity** — Five additional processes (gateway servers) plus Squid, compared to mitmproxy alone
- **MITM still required** — Providers without base URL support still need TLS interception
- **Dual code paths** — Credential injection logic exists in both gateways and `credential_injector.py` (mitmproxy addon); changes must be kept in sync
- **Port allocation** — Six fixed ports (443, 9848-9852) consumed on the internal network

### Neutral

- Gateway rollback to MITM is documented in [Operations](../operations.md#gateway-rollback-procedures)
- Each gateway can be rolled back independently by unsetting the corresponding `*_BASE_URL` and re-adding the domain to the MITM allowlist
- Squid replaces mitmproxy as the primary forward proxy on port 8080; mitmproxy moves to port 8081

## Alternatives Considered

**MITM-only (status quo before gateways).** Rejected because it requires universal CA trust, adds TLS overhead to every request, and couples all providers to a single interception point.

**Envoy/nginx sidecar per provider.** Rejected because it adds container orchestration complexity without meaningful benefit over aiohttp gateways, which are simpler to deploy within the existing unified-proxy container.

**CONNECT tunnel with credential injection.** Rejected because injecting credentials into an already-encrypted CONNECT tunnel requires TLS termination, which is functionally equivalent to MITM.

**Per-sandbox gateway processes.** Rejected because shared gateways on the internal network serve all sandboxes via container identity validation; per-sandbox processes would waste resources.

## References

- `unified-proxy/gateway_base.py` — Shared gateway factory
- `unified-proxy/gateway_middleware.py` — Middleware stack (identity, metrics, circuit breaker, rate limiter)
- `unified-proxy/gateway.py` — Anthropic gateway
- `unified-proxy/openai_gateway.py` — OpenAI gateway
- `unified-proxy/github_gateway.py` — GitHub gateway
- `unified-proxy/gemini_gateway.py` — Gemini gateway
- `unified-proxy/chatgpt_gateway.py` — ChatGPT/Codex gateway
- `unified-proxy/security_policies.py` — Shared GitHub security policies
- `unified-proxy/generate_squid_config.py` — Squid domain list generator
- `unified-proxy/squid.conf` — Squid configuration
- [Operations: Gateway Rollback](../operations.md#gateway-rollback-procedures)
- [Threat Model: Credential Theft](../security/sandbox-threats.md#3-credential-theft)
- ADR-003: Policy Engine (related access control context)
