# Certificate Management

This guide covers mitmproxy CA certificate management for HTTPS interception in credential isolation mode.

## Overview

The unified proxy uses mitmproxy for HTTPS interception to inject API credentials into requests. This requires a CA certificate that sandboxed containers trust.

```
┌─────────────────────────────────────────────────────────────┐
│                    CERTIFICATE FLOW                          │
│                                                             │
│  unified-proxy                      sandbox container        │
│  ┌─────────────┐                   ┌─────────────────────┐  │
│  │ Generate CA │                   │ Trust CA            │  │
│  │ on startup  │──── mitm-certs ───│ via env vars +      │  │
│  │             │     volume        │ system trust store  │  │
│  └─────────────┘                   └─────────────────────┘  │
│        │                                    │               │
│        ▼                                    ▼               │
│  ~/.mitmproxy/                     /certs/mitmproxy-ca.pem  │
│  mitmproxy-ca-cert.pem             (read-only mount)        │
└─────────────────────────────────────────────────────────────┘
```

## CA Certificate Generation

The unified proxy automatically generates a CA certificate on first startup:

1. **Location**: `~/.mitmproxy/mitmproxy-ca-cert.pem` inside the proxy container
2. **Method**: mitmproxy generates its own CA when started for the first time
3. **Persistence**: The certificate persists in the proxy container's filesystem

### Generation Process (unified-proxy/entrypoint.sh)

```bash
# Start mitmproxy briefly to generate CA cert
mitmdump --mode transparent --listen-port 0 --set confdir="${MITMPROXY_CA_DIR}" &

# Wait for certificate file to appear
for i in {1..30}; do
    if [[ -f "${MITMPROXY_CA_CERT}" ]]; then
        log "CA certificate generated successfully"
        break
    fi
    sleep 0.5
done
```

## Certificate Distribution

The CA certificate is distributed to sandbox containers via a shared Docker volume:

### Docker Compose Configuration

```yaml
volumes:
    # Shared certificate volume - proxy writes CA, sandbox reads it
    mitm-certs:

services:
    unified-proxy:
        volumes:
            - mitm-certs:/etc/proxy/certs  # Write access

    dev:  # Sandbox container
        volumes:
            - mitm-certs:/certs:ro  # Read-only access
```

### Copy to Shared Volume

```bash
# unified-proxy/entrypoint.sh
copy_ca_to_shared_volume() {
    cp "${MITMPROXY_CA_CERT}" "${SHARED_CERTS_DIR}/mitmproxy-ca.pem"
}
```

## Certificate Trust Configuration

Sandbox containers trust the CA through multiple mechanisms:

### Environment Variables

Set in `docker-compose.credential-isolation.yml`:

```yaml
environment:
    # Trust the mitmproxy CA certificate for HTTPS interception
    - NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca.pem
    - REQUESTS_CA_BUNDLE=/certs/mitmproxy-ca.pem
    - SSL_CERT_FILE=/certs/mitmproxy-ca.pem
    - CURL_CA_BUNDLE=/certs/mitmproxy-ca.pem
```

### System Trust Store

The sandbox entrypoint also installs the certificate in the system trust store:

```bash
# entrypoint.sh
if [ -f "/certs/mitmproxy-ca.pem" ]; then
    # Set environment variables
    export NODE_EXTRA_CA_CERTS="/certs/mitmproxy-ca.pem"
    export REQUESTS_CA_BUNDLE="/certs/mitmproxy-ca.pem"
    export SSL_CERT_FILE="/certs/mitmproxy-ca.pem"
    export CURL_CA_BUNDLE="/certs/mitmproxy-ca.pem"

    # Install to system trust store
    sudo cp "/certs/mitmproxy-ca.pem" \
        "/usr/local/share/ca-certificates/mitmproxy-ca.crt"
    sudo update-ca-certificates
fi
```

### Application-Specific Trust

| Application | Trust Method |
|-------------|--------------|
| Node.js | `NODE_EXTRA_CA_CERTS` environment variable |
| Python requests | `REQUESTS_CA_BUNDLE` environment variable |
| curl | `CURL_CA_BUNDLE` environment variable |
| OpenSSL | `SSL_CERT_FILE` environment variable |
| System apps | `/usr/local/share/ca-certificates/` |

## Certificate Rotation

Certificate rotation is handled by recreating the proxy container:

### Manual Rotation

```bash
# 1. Stop sandbox and proxy
docker compose -f docker-compose.credential-isolation.yml down

# 2. Remove the certificate volume
docker volume rm <project>_mitm-certs

# 3. Restart - proxy will generate new certificate
docker compose -f docker-compose.credential-isolation.yml up -d
```

### Automatic Rotation

The certificate is regenerated when:

1. The proxy container is recreated (`docker compose up --force-recreate`)
2. The `mitm-certs` volume is deleted
3. The proxy's `~/.mitmproxy` directory is cleared

### Rotation Considerations

- **No expiration**: mitmproxy CA certificates don't have short expiration by default
- **Per-sandbox isolation**: Each sandbox environment has its own CA
- **Rebuild triggers rotation**: `cast destroy` + `cast new` rotates certificates

## Troubleshooting

### Certificate Errors

**Symptom**: `SSL certificate problem: unable to get local issuer certificate`

**Causes**:
1. Certificate not mounted: Check `/certs/mitmproxy-ca.pem` exists in sandbox
2. Environment not set: Verify `NODE_EXTRA_CA_CERTS` and related vars
3. Proxy not ready: Wait for proxy readiness before making requests

**Debug**:
```bash
# Inside sandbox
ls -la /certs/
echo $NODE_EXTRA_CA_CERTS
curl -v https://api.github.com 2>&1 | head -20
```

### Trust Store Issues

**Symptom**: Some applications ignore environment variables

**Solution**: Ensure system trust store is updated:
```bash
sudo update-ca-certificates
# Verify
ls /etc/ssl/certs/ | grep mitmproxy
```

## Security Considerations

1. **Isolation**: Each sandbox has its own CA - compromising one doesn't affect others
2. **Read-only mount**: Sandboxes cannot modify the CA certificate
3. **No persistence**: CA is regenerated on sandbox recreation
4. **Scope limited**: CA only trusted within the sandbox container

## See Also

- [Architecture](architecture.md) - System overview
- [Security](security/index.md) - Security model
- [ADR-005](adr/005-failure-modes.md) - Failure modes and certificate handling
