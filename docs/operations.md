# Operations Runbook

This guide covers operational procedures for the unified proxy: restart procedures, recovery from failures, DNS fallback activation, and troubleshooting common issues.

## Proxy Restart Procedure

The unified proxy supports graceful shutdown and restart without data loss.

### Graceful Restart (Recommended)

```bash
# From the host machine
docker compose -f docker-compose.credential-isolation.yml restart unified-proxy
```

**What happens:**
1. Docker sends SIGTERM to mitmproxy process
2. Proxy stops accepting new connections
3. In-flight requests complete (up to 10s grace period)
4. Readiness marker (`/var/run/proxy/ready`) is removed
5. Container restarts with fresh state

### Full Stop and Start

```bash
# Stop the proxy (and dependent containers)
docker compose -f docker-compose.credential-isolation.yml stop unified-proxy

# Start the proxy
docker compose -f docker-compose.credential-isolation.yml start unified-proxy
```

### Force Restart (Emergency)

Use only when graceful restart fails:

```bash
# Force kill and restart
docker compose -f docker-compose.credential-isolation.yml kill unified-proxy
docker compose -f docker-compose.credential-isolation.yml up -d unified-proxy
```

**Caution:** Force kill terminates in-flight requests immediately.

### Restart Verification

After restart, verify the proxy is healthy:

```bash
# Check container status
docker compose -f docker-compose.credential-isolation.yml ps unified-proxy

# Check readiness marker (inside proxy container)
docker exec unified-proxy test -f /var/run/proxy/ready && echo "Ready" || echo "Not ready"

# Check mitmproxy is listening
docker exec unified-proxy ss -tlnp | grep 8080

# Test credential injection (from sandbox)
curl -v https://api.anthropic.com/v1/messages 2>&1 | head -20
```

## SQLite Recovery Procedure

The container registry uses SQLite with WAL mode. Recovery is rarely needed but documented here.

### Database Location

```
/var/lib/unified-proxy/registry.db      # Main database
/var/lib/unified-proxy/registry.db-wal  # Write-ahead log
/var/lib/unified-proxy/registry.db-shm  # Shared memory file
```

### Check Database Integrity

```bash
docker exec unified-proxy sqlite3 /var/lib/unified-proxy/registry.db "PRAGMA integrity_check;"
```

Expected output: `ok`

### Recovery from Corruption

**Symptom:** Container registration fails with "database disk image is malformed"

**Step 1: Stop the proxy**
```bash
docker compose -f docker-compose.credential-isolation.yml stop unified-proxy
```

**Step 2: Backup corrupted database (optional)**
```bash
docker cp unified-proxy:/var/lib/unified-proxy/registry.db ./registry.db.corrupt
```

**Step 3: Remove database files**
```bash
docker exec unified-proxy rm -f /var/lib/unified-proxy/registry.db*
```

**Step 4: Restart proxy**
```bash
docker compose -f docker-compose.credential-isolation.yml start unified-proxy
```

The proxy will create a fresh database on startup. Containers will re-register automatically on their next request.

### WAL Checkpoint (Performance)

If the WAL file grows large, force a checkpoint:

```bash
docker exec unified-proxy sqlite3 /var/lib/unified-proxy/registry.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

### Export Container Registrations

```bash
docker exec unified-proxy sqlite3 -header -csv /var/lib/unified-proxy/registry.db \
  "SELECT container_id, ip_address, datetime(registered_at, 'unixepoch') as registered, ttl_seconds FROM containers;"
```

## DNS Fallback Activation

The proxy supports two DNS modes: DNS-enabled (with filtering) and DNS-disabled (fallback).

### When to Activate Fallback

- mitmproxy DNS mode fails go/no-go criteria (latency > 50ms p99)
- DNS filtering causes legitimate requests to fail
- Emergency bypass for debugging

### Check Current DNS Mode

```bash
# Check if DNS is enabled
docker exec unified-proxy printenv PROXY_ENABLE_DNS
```

Output: `true` (DNS enabled) or empty/false (DNS disabled)

### Activate DNS Fallback

**Step 1: Edit docker-compose override**

Create or edit `docker-compose.override.yml`:

```yaml
services:
  unified-proxy:
    environment:
      - PROXY_ENABLE_DNS=false
```

**Step 2: Restart proxy**
```bash
docker compose -f docker-compose.credential-isolation.yml up -d unified-proxy
```

**Step 3: Verify DNS mode disabled**
```bash
docker logs unified-proxy 2>&1 | grep -i "dns"
# Should show: "DNS filtering enabled" is absent
```

### Re-enable DNS Filtering

Remove the `PROXY_ENABLE_DNS=false` override and restart:

```bash
# Remove override or set to true
docker compose -f docker-compose.credential-isolation.yml up -d unified-proxy

# Verify DNS mode enabled
docker logs unified-proxy 2>&1 | grep "DNS filtering enabled"
```

### DNS Fallback Implications

| Feature | DNS Enabled | DNS Disabled (Fallback) |
|---------|-------------|-------------------------|
| Domain allowlist filtering | DNS + Firewall | Firewall only |
| NXDOMAIN for blocked domains | Yes | No (upstream DNS resolves) |
| Defense in depth | Full | Reduced |
| Latency overhead | +5-20ms | None |

**Security note:** DNS fallback reduces defense in depth. Use only when necessary.

## Troubleshooting

### Proxy Won't Start

**Symptom:** Container exits immediately or healthcheck fails

**Check 1: View startup logs**
```bash
docker logs unified-proxy 2>&1 | head -50
```

**Check 2: Validate required files**
```bash
docker exec unified-proxy ls -la /opt/proxy/addons/
docker exec unified-proxy ls -la /etc/proxy/certs/
```

**Check 3: Verify CA certificate**
```bash
docker exec unified-proxy cat /etc/proxy/certs/mitmproxy-ca.pem | head -3
```

Expected: `-----BEGIN CERTIFICATE-----`

**Resolution:** If addons or certificates missing, check volume mounts in docker-compose.

### Containers Not Registered

**Symptom:** Requests fail with "unknown container" errors

**Check registrations:**
```bash
PROXY_CONTAINER="sandbox-<sandbox-name>-unified-proxy-1"
docker exec "$PROXY_CONTAINER" curl -s --unix-socket /var/run/proxy/internal.sock \
  http://localhost/internal/containers | jq .
```

**Manual registration (emergency):**
```bash
PROXY_CONTAINER="sandbox-<sandbox-name>-unified-proxy-1"
docker exec "$PROXY_CONTAINER" curl -X POST --unix-socket /var/run/proxy/internal.sock \
  -H "Content-Type: application/json" \
  -d '{"container_id":"sandbox-123","ip_address":"172.17.0.2","ttl_seconds":86400}' \
  http://localhost/internal/containers
```

### High Latency

**Symptom:** Requests take > 5 seconds

**Check 1: Circuit breaker state**
```bash
curl -s http://unified-proxy:9090/internal/metrics | grep circuit_breaker
```

If state = 2 (OPEN), upstream is failing. See [Circuit Breaker Investigation](observability.md#circuit-breaker-investigation).

**Check 2: Rate limit exhaustion**
```bash
curl -s http://unified-proxy:9090/internal/metrics | grep rate_limit_remaining
```

If remaining < 5, container is rate limited. Wait for refill.

**Check 3: DNS resolution time**
```bash
curl -s http://unified-proxy:9090/internal/metrics | grep dns_duration
```

If p95 > 100ms, consider DNS fallback mode.

### Certificate Errors

**Symptom:** `SSL certificate problem: unable to get local issuer certificate`

**Check 1: Verify CA mounted in sandbox**
```bash
docker exec <sandbox-container> ls -la /certs/
```

**Check 2: Verify environment variables**
```bash
docker exec <sandbox-container> printenv | grep -E "(NODE_EXTRA|SSL_CERT|REQUESTS_CA)"
```

**Check 3: Verify system trust store**
```bash
docker exec <sandbox-container> ls /etc/ssl/certs/ | grep mitmproxy
```

**Resolution:** If CA not found, check `mitm-certs` volume mount.

### Git Operations Failing

**Symptom:** `git clone` or `git push` fails

**Check 1: Verify proxy reachability**
```bash
curl -v http://unified-proxy:8080/
```

**Check 2: Check credential injection logs**
```bash
docker logs unified-proxy 2>&1 | grep -i "credential\|inject" | tail -20
```

**Check 3: Verify GitHub token**
```bash
docker exec unified-proxy printenv GITHUB_TOKEN | head -c 10
# Should show first 10 chars of token (ghp_... or gho_...)
```

### Request Blocked Unexpectedly

**Symptom:** Request returns 403 or connection refused

**Check 1: Policy engine logs**
```bash
docker logs unified-proxy 2>&1 | grep -i "policy\|blocked\|denied" | tail -20
```

**Check 2: DNS filter logs (if DNS enabled)**
```bash
docker logs unified-proxy 2>&1 | grep -i "dns.*blocked\|NXDOMAIN" | tail -20
```

**Check 3: Verify domain in allowlist**
```bash
docker exec unified-proxy cat /etc/proxy/allowlist.conf | grep <domain>
```

## Emergency Procedures

### Complete Proxy Reset

Use when proxy is in unrecoverable state:

```bash
# 1. Stop all credential isolation services
docker compose -f docker-compose.credential-isolation.yml down

# 2. Remove volumes (CAUTION: loses certificates)
docker volume rm $(docker volume ls -q | grep -E "mitm-certs|proxy-")

# 3. Recreate everything
docker compose -f docker-compose.credential-isolation.yml up -d
```

### Bypass Proxy (Emergency Only)

**CAUTION:** This bypasses credential isolation. Use only for debugging.

```bash
# Inside sandbox container, temporarily unset proxy
unset HTTP_PROXY HTTPS_PROXY
curl https://api.github.com  # Direct connection (no credential injection)
```

## See Also

- [Architecture](architecture.md) - System components
- [Observability](observability.md) - Metrics and debugging
- [Certificates](certificates.md) - CA management
- [ADR-005](adr/005-failure-modes.md) - Failure modes and recovery design
- [ADR-004](adr/004-dns-integration.md) - DNS integration decision
