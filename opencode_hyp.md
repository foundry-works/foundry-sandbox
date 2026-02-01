# OpenCode OAuth Regression Hypotheses (Credential Isolation)

## Hypotheses (original)

1) **Placeholder mismatch due to stale stub auth**
   - OpenCode placeholder changed from `OPENCODE_CREDENTIAL_PROXY_PLACEHOLDER` to `PROXY_PLACEHOLDER_OPENCODE`.
   - If the sandbox still has the old stub or copied auth file, the proxy won’t detect the placeholder and won’t inject real tokens.
   - Codex still works because its placeholder (`CREDENTIAL_PROXY_PLACEHOLDER`) did not change.

2) **Stubs volume not repopulated / stale external volume**
   - Stubs moved from bind mounts to an external named volume.
   - If `populate_stubs_volume` did not run (or failed), `/etc/proxy-stubs/stub-auth-opencode.json` won’t exist, so no stub auth is copied into `~/.local/share/opencode/auth.json`.
   - Codex can still work if its auth is copied via `copy_configs_to_container`.

3) **Stub filename change not reflected in existing volume**
   - Entry-point now copies `/etc/proxy-stubs/stub-auth-opencode.json` (new name).
   - If the volume still contains old filenames (e.g., `opencode-auth.json`), the copy won’t happen.

4) **Host OpenCode auth.json shape changed**
   - `MultiProviderTokenManager` expects a provider-keyed JSON with `access/refresh/expires/type`.
   - If the codex oauth plugin now writes a different structure, the manager will fail to load, disabling OpenCode injection.

5) **Provider host mapping mismatch**
   - Injection only triggers for hosts in `OPENCODE_PROVIDER_HOSTS`.
   - If the plugin now calls different hosts/endpoints (e.g., new OpenAI host), injection won’t happen.

## Findings from latest sandbox (2026-02-01, sandbox-tyler-foundry-sandbox-20260201-1013)

- **(1) Placeholder mismatch**: **Not observed**. Both `/etc/proxy-stubs/stub-auth-opencode.json` and `/home/ubuntu/.local/share/opencode/auth.json` contain `PROXY_PLACEHOLDER_OPENCODE`.
- **(2) Stubs volume not repopulated**: **Not observed**. `/etc/proxy-stubs` exists with the new `stub-*.json` files.
- **(3) Stub filename mismatch**: **Not observed**. The volume contains the new filenames used by `entrypoint.sh`.
- **(4) Auth.json shape mismatch**: **Not observed**. `/credentials/opencode/auth.json` is provider-keyed; `openai` and `google` are `type=oauth`, `zai-coding-plan` is `type=api`.
- **(5) Provider host mapping mismatch**: **No direct evidence**, but **no OpenCode injection logs** appear in api-proxy.

## New strongest hypothesis (based on logs)

6) **OpenCode OAuth plugin not loading; falling back to API key**
   - OpenCode logs show requests to `https://api.openai.com/v1/responses` returning **401 Missing scopes: api.responses.write**.
   - This strongly suggests the API key path is being used (not OAuth token injection).
   - `opencode-openai-codex-auth` is listed in `opencode.json`, but the OpenCode log does **not** show it being installed/loaded, and it’s not present in `/home/ubuntu/.cache/opencode/node_modules`.
   - If the plugin does not load, the proxy never sees the OpenCode OAuth placeholder and cannot inject real tokens.

## Investigation Results (2026-02-01)

### Hypothesis Assessment

| # | Hypothesis | Status | Evidence |
|---|------------|--------|----------|
| 1 | Placeholder mismatch (stale stub) | **Refuted** | Stub has correct `PROXY_PLACEHOLDER_OPENCODE` |
| 2 | Stubs volume not populated | **Refuted** | `/etc/proxy-stubs/` has correct files |
| 3 | Stub filename mismatch | **Refuted** | Correct filenames in volume |
| 4 | Auth.json shape mismatch | **Refuted** | Provider-keyed JSON is correct |
| 5 | Provider host mapping mismatch | **Refuted** | Proxy logs show injection for `api.openai.com` |
| 6 | Plugin not loading / fallback to API key | **Partially correct but not root cause** | Internal `CodexAuthPlugin` loads and works |

### Confirmed Root Cause

**The OAuth token lacks required API scopes.**

The proxy injection IS working correctly:
```
[15:14:55.349] Injected real OAuth token for api.openai.com
```

But the injected Codex OAuth token has only basic scopes:
```json
"scp": ["openid", "profile", "email", "offline_access"]
```

OpenCode calls the **Responses API** (`/v1/responses`) which requires the `api.responses.write` scope - which is **missing**.

### Detailed Flow

1. OpenCode loads the internal `CodexAuthPlugin` (not `opencode-openai-codex-auth` from config)
2. `CodexAuthPlugin` uses `~/.codex/auth.json` which has `CREDENTIAL_PROXY_PLACEHOLDER`
3. The proxy's **Codex handler** matches (before OpenCode handler) and injects real OAuth token
4. The real Codex token from `/credentials/codex/auth.json` is injected
5. BUT: This token was obtained with basic OAuth scopes only
6. OpenCode calls `/v1/responses` which requires `api.responses.write` → **401 error**

### Why Original Hypothesis 6 Was Close But Wrong

- The external `opencode-openai-codex-auth` plugin indeed does NOT load (not installed in node_modules)
- BUT the internal `CodexAuthPlugin` DOES load and works
- The real issue is scope mismatch, not plugin loading

### Plugin Loading Evidence

From OpenCode logs:
```
INFO  service=plugin name=CodexAuthPlugin loading internal plugin
INFO  service=plugin name=CopilotAuthPlugin loading internal plugin
INFO  service=plugin path=opencode-antigravity-auth@latest loading plugin
```

Note: `opencode-openai-codex-auth` is in config but NOT in the loading logs.

Installed plugins in `/home/ubuntu/.cache/opencode/node_modules/`:
- `opencode-anthropic-auth` ✓
- `opencode-antigravity-auth` ✓
- `opencode-openai-codex-auth` ✗ (missing)

### Fix Options

1. **Re-authenticate Codex CLI** with scopes that include `api.responses.write`
2. **Use separate OpenCode-specific OAuth** that requests Responses API scopes
3. **Configure OpenCode to use Chat Completions API** (`/v1/chat/completions`) instead of Responses API
