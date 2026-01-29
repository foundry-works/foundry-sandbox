# Credential Isolation via Transparent HTTPS Proxy

## Summary

Isolate API credentials from sandbox containers using transparent HTTPS interception. The sandbox has no API keys - all HTTPS traffic to AI provider domains is intercepted by mitmproxy, which injects real credentials before forwarding upstream.

**Key insight**: CLI tools (claude, codex, gemini, cursor-agent) handle HTTP internally and don't support base URL overrides. The only way to proxy them without modification is network-level interception.

## Architecture

```
+------------------------------------------+
|            Sandbox Container             |
|  (NO API keys in environment)            |
|                                          |
|  claude, codex, gemini, cursor-agent     |
|           ↓                              |
|  iptables DNAT → gateway:8080            |
|  (intercepts api.anthropic.com, etc)     |
|                                          |
|  Trusts: /certs/mitmproxy-ca.pem         |
+---------------------|--------------------+
                      ↓
+------------------------------------------+
|         Gateway (mitmproxy)              |
|  (HAS API keys in environment)           |
|                                          |
|  - Terminates TLS                        |
|  - Injects credentials per-domain        |
|  - Forwards to real API                  |
+------------------------------------------+
```

## Implementation

### 1. Gateway Container

**`gateway/Dockerfile`**
```dockerfile
FROM mitmproxy/mitmproxy:latest

COPY inject-credentials.py /addons/inject-credentials.py
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
```

**`gateway/inject-credentials.py`**
```python
"""Inject API credentials into intercepted requests."""

import os
from mitmproxy import http

# Domain -> (header_name, env_var, header_format)
# header_format: "value" or "Bearer value"
CREDENTIALS = {
    "api.anthropic.com": ("x-api-key", "ANTHROPIC_API_KEY", "value"),
    "api.openai.com": ("Authorization", "OPENAI_API_KEY", "Bearer {value}"),
    "generativelanguage.googleapis.com": ("x-goog-api-key", "GOOGLE_API_KEY", "value"),
    "api.groq.com": ("Authorization", "GROQ_API_KEY", "Bearer {value}"),
    "api.mistral.ai": ("Authorization", "MISTRAL_API_KEY", "Bearer {value}"),
    "api.deepseek.com": ("Authorization", "DEEPSEEK_API_KEY", "Bearer {value}"),
    "api.together.xyz": ("Authorization", "TOGETHER_API_KEY", "Bearer {value}"),
    "openrouter.ai": ("Authorization", "OPENROUTER_API_KEY", "Bearer {value}"),
    "api.fireworks.ai": ("Authorization", "FIREWORKS_API_KEY", "Bearer {value}"),
}


class InjectCredentials:
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host

        if host not in CREDENTIALS:
            return

        header_name, env_var, fmt = CREDENTIALS[host]
        api_key = os.environ.get(env_var, "")

        if not api_key:
            flow.response = http.Response.make(
                500,
                f"Gateway error: {env_var} not configured",
                {"Content-Type": "text/plain"}
            )
            return

        # Format the header value
        if "{value}" in fmt:
            header_value = fmt.replace("{value}", api_key)
        else:
            header_value = api_key

        # Inject credential, replacing any existing auth header
        flow.request.headers[header_name] = header_value


addons = [InjectCredentials()]
```

**`gateway/entrypoint.sh`**
```bash
#!/bin/bash
set -e

# Generate CA cert if not exists (persisted via volume)
if [ ! -f /root/.mitmproxy/mitmproxy-ca-cert.pem ]; then
    echo "Generating mitmproxy CA certificate..."
    mitmdump --mode transparent -q &
    sleep 2
    pkill -f mitmdump || true
fi

# Copy CA cert to shared volume for sandbox containers
cp /root/.mitmproxy/mitmproxy-ca-cert.pem /certs/mitmproxy-ca.pem 2>/dev/null || true

echo "Starting mitmproxy in transparent mode..."
exec mitmdump \
    --mode transparent \
    --ssl-insecure \
    --set stream_large_bodies=10m \
    -s /addons/inject-credentials.py
```

### 2. Sandbox Init Script

**`safety/credential-proxy-init.sh`**
```bash
#!/bin/bash
#
# Initialize transparent proxy for credential isolation.
# Called from entrypoint.sh when CREDENTIAL_ISOLATION=1.
#

set -e

GATEWAY_IP="${GATEWAY_IP:-172.20.0.2}"
PROXY_PORT="${PROXY_PORT:-8080}"

# Domains to intercept (AI provider APIs)
INTERCEPT_DOMAINS=(
    "api.anthropic.com"
    "api.openai.com"
    "generativelanguage.googleapis.com"
    "api.groq.com"
    "api.mistral.ai"
    "api.deepseek.com"
    "api.together.xyz"
    "openrouter.ai"
    "api.fireworks.ai"
)

# Trust mitmproxy CA
if [ -f /certs/mitmproxy-ca.pem ]; then
    cp /certs/mitmproxy-ca.pem /usr/local/share/ca-certificates/mitmproxy.crt
    update-ca-certificates --fresh > /dev/null 2>&1

    # Node.js uses its own CA store
    export NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca.pem
else
    echo "Warning: mitmproxy CA not found at /certs/mitmproxy-ca.pem"
    exit 1
fi

# Redirect HTTPS traffic for intercepted domains to gateway
for domain in "${INTERCEPT_DOMAINS[@]}"; do
    # Resolve domain to IPs
    ips=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' || true)

    for ip in $ips; do
        iptables -t nat -A OUTPUT -p tcp -d "$ip" --dport 443 \
            -j DNAT --to-destination "${GATEWAY_IP}:${PROXY_PORT}"
    done
done

# Ensure traffic to gateway is allowed
iptables -A OUTPUT -d "$GATEWAY_IP" -j ACCEPT

echo "Credential isolation active. API traffic routed through gateway."
```

### 3. Docker Compose

**`docker-compose.credential-isolation.yml`** (override file)
```yaml
services:
  gateway:
    build: ./gateway
    environment:
      # Real API credentials (never enter sandbox)
      - ANTHROPIC_API_KEY
      - OPENAI_API_KEY
      - GOOGLE_API_KEY
      - GROQ_API_KEY
      - MISTRAL_API_KEY
      - DEEPSEEK_API_KEY
      - TOGETHER_API_KEY
      - OPENROUTER_API_KEY
      - FIREWORKS_API_KEY
    volumes:
      - mitm-certs:/certs
      - mitm-data:/root/.mitmproxy
    networks:
      isolated:
        ipv4_address: 172.20.0.2
    restart: unless-stopped

  dev:
    # Remove API keys from sandbox
    environment:
      - ANTHROPIC_API_KEY=
      - OPENAI_API_KEY=
      - GOOGLE_API_KEY=
      - CREDENTIAL_ISOLATION=1
      - GATEWAY_IP=172.20.0.2
      - NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca.pem
    volumes:
      - mitm-certs:/certs:ro
    cap_add:
      - NET_ADMIN
    networks:
      - isolated
    depends_on:
      - gateway

networks:
  isolated:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24

volumes:
  mitm-certs:
  mitm-data:
```

### 4. Entrypoint Integration

**Modify `entrypoint.sh`** - add at the start:
```bash
# Initialize credential isolation if enabled
if [ "${CREDENTIAL_ISOLATION:-0}" = "1" ]; then
    if [ -f /usr/local/bin/credential-proxy-init.sh ]; then
        sudo /usr/local/bin/credential-proxy-init.sh
    fi
fi
```

### 5. Dockerfile Addition

Add to `Dockerfile`:
```dockerfile
# Credential isolation init script
COPY safety/credential-proxy-init.sh /usr/local/bin/credential-proxy-init.sh
RUN chmod +x /usr/local/bin/credential-proxy-init.sh
```

### 6. CLI Integration

**Modify `commands/new.sh`** - add `--isolate-credentials` flag:
```bash
# In parse_new_args()
--isolate-credentials|--isolate)
    NEW_ISOLATE_CREDENTIALS="true"
    shift
    ;;

# In cmd_new(), when building override
if [ "$NEW_ISOLATE_CREDENTIALS" = "true" ]; then
    # Use credential isolation compose override
    COMPOSE_FILES+=("-f" "docker-compose.credential-isolation.yml")
fi
```

## Files Summary

| File | Action | Lines |
|------|--------|-------|
| `gateway/Dockerfile` | Create | ~10 |
| `gateway/inject-credentials.py` | Create | ~50 |
| `gateway/entrypoint.sh` | Create | ~20 |
| `safety/credential-proxy-init.sh` | Create | ~40 |
| `docker-compose.credential-isolation.yml` | Create | ~45 |
| `Dockerfile` | Modify | +3 |
| `entrypoint.sh` | Modify | +5 |
| `commands/new.sh` | Modify | +10 |
| `lib/args.sh` | Modify | +5 |

**Total: ~190 lines of new code**

## Usage

```bash
# Create sandbox with credential isolation
./sandbox.sh new user/repo feature-branch --isolate-credentials

# Verify no API keys in sandbox
docker exec <container> env | grep -E 'ANTHROPIC|OPENAI|GOOGLE'
# (should be empty or unset)

# Verify AI tools still work
docker exec <container> claude --version
docker exec <container> codex --version
```

## Verification

| Test | Command | Expected |
|------|---------|----------|
| No keys in sandbox | `env \| grep API_KEY` | Empty |
| Claude works | `claude "hello"` | Response from API |
| Codex works | `codex "hello"` | Response from API |
| Gateway has keys | `docker exec gateway env` | Keys present |
| CA trusted | `curl https://api.anthropic.com` | No cert error |

## Trade-offs

| Pro | Con |
|-----|-----|
| True credential isolation | +50ms latency (TLS termination) |
| All CLI tools work unmodified | Requires NET_ADMIN capability |
| Battle-tested (mitmproxy) | CA must be trusted in container |
| Simple addon system | Additional container to run |

## What's NOT Included (YAGNI)

- JWT session management
- Per-provider scopes
- Audit logging
- Rate limiting
- SDK adapters
- Config files

Add these when you have real problems to solve.
