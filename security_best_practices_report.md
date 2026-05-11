# Security Best Practices Report

## Executive Summary

Reviewed the repository using the `security-best-practices` skill on 2026-05-11. The codebase is primarily Python with a Flask-based host-side git-safety/proxy server, plus shell assets used inside `sbx` sandboxes. The available local guidance that applies directly is `python-flask-web-server-security.md`; no general Python CLI guidance file was present in the skill references, so this review also focused on subprocess, filesystem, secret-handling, and sandbox-boundary code.

No critical issues were found. The main risks are concentrated around user-defined credential proxying: query-string credential transport can leak host secrets into logs, proxy registrations default to broad upstream access when method/path lists are empty, and internal proxy authentication headers are forwarded to upstream services.

## High Severity

### H-1: Query-string credential injection can leak host API keys into logs

- Rule ID: FLASK-HTTP-001 / FLASK-CONFIG-001
- Location: `foundry-git-safety/foundry_git_safety/user_services_proxy.py`, `proxy_request`, lines 208-218 and 255-259
- Evidence:

```python
if svc.format == "query":
    query_pairs.append((svc.header, api_key))
if query_pairs:
    full_path += f"?{urlencode(query_pairs)}"
...
logger.info(
    "Proxied %s %s/%s -> %s://%s%s (%d)",
    request.method, service_slug, upstream_path,
    svc.scheme, svc.domain, full_path, upstream_response.status,
)
```

- Impact: If a service is configured with `format: query`, the real host secret is appended to `full_path` and then logged. Anyone with access to git-safety application logs can recover that host API key.
- Fix: Prefer removing `query` credential transport. If compatibility requires keeping it, do not log query strings, and add a redaction helper that removes configured credential parameter names before logging.
- Mitigation: Document `format: query` as unsafe for production and reject it unless an explicit trusted config flag enables it.
- False positive notes: This only leaks when a configured service uses `format: query`, but the feature is documented as supported in `docs/configuration.md` lines 214-218.

## Medium Severity

### M-1: User-defined service proxy defaults to allow-all methods and paths

- Rule ID: FLASK-SSRF-001 / Least-privilege credential proxying
- Location: `foundry-git-safety/foundry_git_safety/user_services_proxy.py`, `proxy_request`, lines 143-159; `foundry_sandbox/foundry_config.py`, `compile_mcp_servers`, lines 1167-1175
- Evidence:

```python
if svc.methods:
    allowed_methods = [m.upper() for m in svc.methods]
    if request.method.upper() not in allowed_methods:
        ...

if svc.paths:
    if not any(fnmatch(f"/{upstream_path}", p) for p in svc.paths):
        ...
```

```python
user_services.append({
    ...
    "methods": [],
    "paths": [],
    "scheme": "https",
})
```

- Impact: Empty `methods` or `paths` lists mean no restriction. A sandbox with HMAC access to the proxy can use the configured host credential against any endpoint and any supported HTTP method on the target domain, including destructive or administrative endpoints.
- Fix: Make least privilege the default: require explicit methods and paths for `user_services`, or introduce an explicit `allow_all: true` escape hatch in trusted user config. For generated proxy MCP registrations, require target-specific restrictions where possible.
- Mitigation: Keep user-service definitions in trusted user config only, and prefer narrow examples such as `methods: [GET, POST]` and `paths: ["/search*", "/extract*"]`.
- False positive notes: The security model accepts that data sent to already-allowed destinations is not prevented (`docs/security/security-model.md` lines 78 and 132). This finding is about insecure default breadth for a credential-bearing proxy, not repo-controlled configuration.

### M-2: Proxy forwards internal HMAC authentication headers upstream

- Rule ID: FLASK-SSRF-001 / Secret minimization
- Location: `foundry-git-safety/foundry_git_safety/user_services_proxy.py`, `proxy_request`, lines 195-200; `foundry-git-safety/foundry_git_safety/deep_policy_proxy.py`, `deep_policy_proxy`, lines 242-247
- Evidence:

```python
headers = {}
for key, value in request.headers:
    if key.lower() not in _HOP_BY_HOP and key.lower() != "host":
        headers[key] = value
headers["Host"] = svc.domain
```

- Impact: Upstream services receive internal headers such as `X-Sandbox-Id`, `X-Request-Signature`, `X-Request-Timestamp`, and `X-Request-Nonce`. The HMAC signature is not the raw secret and replay protection limits direct reuse, but these headers are internal authentication artifacts and should not leave the trust boundary.
- Fix: Strip all Foundry-internal headers before forwarding, for example `x-sandbox-id`, `x-request-signature`, `x-request-timestamp`, `x-request-nonce`, and `x-foundry-*`. Keep forwarding opt-in for any header class that is needed by a specific upstream.
- Mitigation: Prefer allowlisting upstream request headers instead of copying all non-hop-by-hop headers.
- False positive notes: Replay is unlikely because nonces are stored and signatures are path/body/timestamp-bound. The issue is unnecessary exposure of internal auth metadata.

### M-3: User-service secrets are pushed to global `sbx` secret scope

- Rule ID: Least-privilege secret scoping
- Location: `foundry_sandbox/artifacts.py`, `_apply_sbx_secrets`, lines 203-208; `foundry_sandbox/sbx.py`, `sbx_secret_set`, lines 487-506
- Evidence:

```python
sbx_secret_set(slug_name, value, global_scope=True)
```

```python
global_scope: If True, make secret available to all sandboxes.
...
if global_scope:
    args.append("-g")
```

- Impact: Secrets compiled for one sandbox are stored in a scope documented as available to all sandboxes. If another sandbox can reference the same service slug or an operator expects project-local secret isolation, this broadens the credential boundary beyond the individual sandbox.
- Fix: Prefer sandbox-scoped `sbx` secrets for per-sandbox user services, or make global scope an explicit trusted-user option. Use stable names that include the sandbox id where practical.
- Mitigation: Document current global-scope behavior prominently and avoid reusing broad service slugs for high-privilege credentials.
- False positive notes: The proxy still requires per-sandbox HMAC authentication and per-sandbox service metadata. This finding concerns defense-in-depth and cross-sandbox blast radius.

## Low Severity

### L-1: Unauthenticated health/readiness endpoints disclose operational paths and write log entries on GET

- Rule ID: FLASK-HTTP-001 / FLASK-HEADERS-001
- Location: `foundry-git-safety/foundry_git_safety/server.py`, `health` and `ready`, lines 282-353
- Evidence:

```python
@app.route("/health", methods=["GET"])
def health():
    ...
    log_check = _check_decision_log()
    return jsonify({
        "config_error": config_error,
        "logging": log_check,
        ...
    })
```

```python
def _check_decision_log() -> dict:
    ...
    writer.write(test_entry)
    return {"ok": True, "detail": f"Decision log writable at {log_dir}"}
```

- Impact: If the server is bound beyond localhost or exposed through the sandbox proxy path, callers can learn host-side data/log/secrets paths and repeatedly trigger decision-log writes via GET requests.
- Fix: Either protect `/health` and `/ready` with the same admin-token mechanism used by `/metrics`, `/tamper-event`, `/proxy/health`, and `/deep-policy/health`, or reduce their responses to non-sensitive booleans and make readiness checks non-mutating.
- Mitigation: Keep the default bind address at `127.0.0.1` and verify `sbx` policy prevents arbitrary access to this host-side listener.
- False positive notes: These endpoints are often intentionally unauthenticated for local orchestration. The risk depends on network exposure.

## Positive Observations

- HMAC verification uses `hmac.compare_digest` and rejects malformed signatures.
- Flask request bodies are capped with `MAX_CONTENT_LENGTH`.
- The git execution path uses list-based subprocess calls, a command allowlist, blocked git flags, clean environment construction, and path validation.
- Repo-owned `foundry.yaml` files are rejected if they attempt to declare host-bound credentials or host filesystem reads.
- Admin endpoints listed in the docs are protected by default when an admin token is configured.

## Recommended Fix Order

1. Fix H-1 by removing or redacting query-string credential transport.
2. Fix M-2 by stripping Foundry/internal auth headers before upstream forwarding.
3. Fix M-1 by making credential proxy scopes explicit and least-privilege by default.
4. Decide whether global `sbx` secret scope is an accepted operational tradeoff or should become sandbox-scoped.
5. Reduce unauthenticated health/readiness detail if the listener can be reached from sandboxes or non-local clients.
