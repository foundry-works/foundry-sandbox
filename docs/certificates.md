# Certificate Management

Mitmproxy CA certificate management for HTTPS interception in credential isolation mode.

## How It Works

When MITM-required provider credentials are configured (Gemini, Tavily, Semantic Scholar, Perplexity, Zhipu), the unified proxy generates a CA certificate and uses it to intercept HTTPS traffic for credential injection. Major providers (Anthropic, OpenAI, GitHub) route through plaintext HTTP gateways and do not require MITM or CA trust.

```
unified-proxy                          sandbox container
┌──────────────┐                      ┌────────────────────────┐
│ Generate CA  │                      │ Trust combined bundle  │
│ Build combined│──── mitm-certs ────│ /certs/ca-certificates │
│ CA bundle    │     volume (ro)     │ .crt (system CAs +     │
│              │                      │ mitmproxy CA)          │
└──────────────┘                      └────────────────────────┘
```

### Generation

The proxy's `entrypoint.sh` generates the CA on first startup via `mitmdump`, then builds a combined bundle (system CAs + mitmproxy CA) at `/etc/proxy/certs/ca-certificates.crt`. This avoids running `update-ca-certificates` inside the sandbox (which requires a writable root filesystem).

### Distribution

The combined bundle is shared via a Docker volume (`mitm-certs`), mounted read-only in the sandbox at `/certs/`.

### Trust Configuration

Environment variables are set in `docker-compose.credential-isolation.yml`:

| Variable | Value | Consumers |
|----------|-------|-----------|
| `NODE_EXTRA_CA_CERTS` | `/certs/ca-certificates.crt` | Node.js |
| `REQUESTS_CA_BUNDLE` | `/certs/ca-certificates.crt` | Python requests |
| `SSL_CERT_FILE` | `/certs/ca-certificates.crt` | OpenSSL |
| `CURL_CA_BUNDLE` | `/certs/ca-certificates.crt` | curl |
| `GIT_SSL_CAINFO` | `/certs/ca-certificates.crt` | git |

## Certificate Rotation

Certificates rotate automatically when the sandbox is destroyed and recreated (`cast destroy && cast new`). Manual rotation:

```bash
# Stop sandbox and proxy
docker compose -f docker-compose.credential-isolation.yml down

# Remove the certificate volume
docker volume rm <project>_mitm-certs

# Restart - proxy generates new certificate
docker compose -f docker-compose.credential-isolation.yml up -d
```

## Troubleshooting

### `SSL certificate problem: unable to get local issuer certificate`

```bash
# Inside sandbox: verify combined bundle exists
ls -la /certs/ca-certificates.crt

# Verify env vars are set
echo $NODE_EXTRA_CA_CERTS

# Test HTTPS through proxy
curl -v https://api.github.com 2>&1 | head -20
```

**Common causes:**
1. Combined bundle not generated — proxy may have failed to start mitmproxy
2. Volume not mounted — check `mitm-certs` volume in `docker compose ps`
3. Proxy not ready — sandbox started before proxy healthcheck passed

## Security Properties

- **Isolation**: Each sandbox project has its own CA
- **Read-only mount**: Sandboxes cannot modify the CA certificate
- **No persistence**: CA is regenerated on sandbox recreation
- **Scope limited**: CA only trusted within the sandbox container
- **Reduced surface**: Major providers use gateways (no MITM), limiting CA trust to MITM-required providers only

## See Also

- [Architecture](architecture.md) - Unified proxy architecture
- [Security](security/index.md) - Security model
- [Operations](operations.md) - Certificate troubleshooting in operations context
