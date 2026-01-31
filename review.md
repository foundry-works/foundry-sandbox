# Credential Isolation Gateway Code Review

## Context
- Branch: `tyler/foundry-sandbox-20260131-0856` (commits 41748f4 → c16ec07)
- Scope: credential isolation gateway spec + implementation (gateway service, session plumbing, credential isolation workflow).

## Blocking issues
1. **Gateway session APIs never reach the service.** `lib/gateway.sh` talks to `curl --unix-socket /var/run/gateway/gateway.sock` for session health/create/destroy (`lib/gateway.sh:4-64`), but `gateway/Dockerfile` starts only Gunicorn on TCP port 8080 (`gateway/Dockerfile:36-37`). No socket is ever created or mounted, so every attempt to build a session fails before any git traffic can begin.
2. **DNS routing depends on services the gateway never runs.** The dev service points its DNS at `gateway` (`docker-compose.credential-isolation.yml:112-115`), implying gateway must serve DNS via `dnsmasq`, but the gateway image only installs dnsmasq and never launches it—there is no entrypoint to start dnsmasq alongside Gunicorn (`gateway/Dockerfile:6-37`). As soon as a sandbox comes up, DNS lookups begin timing out and credential isolation cannot be validated.
3. **Git credential helper output doesn’t match gateway expectations.** `safety/gateway-credential-helper` emits username/password pairs (Basic auth) per the Git credential protocol (`safety/gateway-credential-helper:36-40`), yet the gateway only accepts `Authorization: Bearer token:secret` (`gateway/gateway.py:556-582`). Every Git request through the gateway will return 401 because the helper never supplies the required Bearer form.
4. **Session store is per-worker but gateway runs multi-worker Gunicorn.** Sessions live in the in-memory `SESSIONS` dict (`gateway/gateway.py:32-136`), but the container launches Gunicorn with `--workers 4` (`gateway/Dockerfile:36-37`). Session creation happens in one worker, yet Git requests may hit any worker, so tokens rarely match, causing unpredictable “invalid session” errors.
5. **Session garbage collection never runs.** The GC timer is started only in the `__main__` block (`gateway/gateway.py:761-770`), which isn’t executed when Gunicorn imports the module. Sessions therefore never expire or free memory, which defeats the 24h/7d TTL design and leaves stale tokens valid indefinitely.
6. **Repo scoping is never enforced.** `create_session` records the authorized repo list (`gateway/gateway.py:128-136`), but `git_proxy` never checks `session['repos']` when serving requests (`gateway/gateway.py:592-623`). Any token authorized for any repo can be reused against any owner/repo, breaking repository-level restrictions.
7. **Gateway-specific URL rewrites are always enabled inside the sandbox.** `/etc/gitconfig` rewrites every GitHub URL to `http://gateway:8080/git/` regardless of whether credential isolation is running (`Dockerfile:127-137`). When a user runs the default compose stack (without `--isolate-credentials`), the sandbox still points to a gateway that doesn’t exist, so git clones immediately fail. The rewrite must be gated on `SANDBOX_GATEWAY_ENABLED=true`.

## High-risk behavior
- **Large payload buffering in gateway.** `git_proxy` calls `request.get_data()` for POST/PUT (`gateway/gateway.py:650-654`), which buffers entire packfiles/push data in memory instead of streaming, so large pushes may exhaust a worker’s RAM. Stream the request body or relay `request.stream` to avoid DoS.

## Recommendations
1. Run the gateway entrypoint in a wrapper that starts dnsmasq, creates `/var/run/gateway/gateway.sock`, and keeps both services alive (or switch the control plane to plain TCP and update `lib/gateway.sh` to talk over HTTP).
2. Align the credential helper with gateway expectations (emit `Bearer token:secret`) or have the gateway accept Basic auth and translate it into a session lookup.
3. Replace per-worker `SESSIONS` with a shared store (Redis/filesystem) or run Gunicorn with a single worker until such a store exists. Also move `start_garbage_collection()` to a hook Gunicorn uses (e.g., `gunicorn.conf.py` on worker boot).
4. Enforce `session['repos']` on each request before proxying, so tokens are repo-scoped.
5. Gate the GitHub URL rewrite and credential helper setup behind `SANDBOX_GATEWAY_ENABLED=true`; default mode should keep GitHub URLs unchanged.
6. Switch from `request.get_data()` to streaming proxies to avoid buffering large payloads.

## Testing
- Not run (review only).
