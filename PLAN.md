# Plan: User-Configurable API Keys and Services

## Context

Adding a new API key/service to foundry-sandbox (e.g., OpenRouter for multi-model routing) currently requires modifying 6+ files across both the CLI and proxy codebases. This makes it impossible for downstream projects to add custom services without forking. The goal is a single config file that users can drop in to define custom API keys and services, with the system handling placeholder generation, credential injection, and domain allowlisting automatically.

## Design

A new `config/user-services.yaml` file defines custom services. The CLI reads it to generate placeholders and display status. It gets mounted into the proxy container, which reads it to dynamically extend its credential injection and allowlist.

### Config File Format

```yaml
# config/user-services.yaml
version: "1"

services:
  - name: OpenRouter
    env_var: OPENROUTER_API_KEY
    domain: openrouter.ai
    header: Authorization       # HTTP header for credential injection
    format: bearer              # "bearer" -> "Bearer <key>", "value" -> raw key
    paths: ["/api/**"]          # optional, defaults to ["/**"]
    methods: [GET, POST]        # optional, defaults to [GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD]

  - name: Groq
    env_var: GROQ_API_KEY
    domain: api.groq.com
    header: Authorization
    format: bearer
    paths: ["/openai/**"]

  - name: CustomService
    env_var: CUSTOM_API_KEY
    domain: api.custom.example
    header: X-Api-Key           # works with any header name
    format: value               # injects raw key value (no "Bearer " prefix)
```

### Limitations (MVP)

This config supports header-based credential injection only. The following patterns from built-in providers are **not** supported for user-defined services:

- OAuth token refresh flows (Claude OAuth)
- Request body injection (Zhipu-style API keys embedded in JSON payloads)
- File-based credential loading (Gemini settings files)

These could be added in a future version if demand warrants it.

### Security Note

User-defined services expand the proxy's allowlist and MITM domain list. A misconfigured `user-services.yaml` could allowlist domains that bypass the proxy's security model. This is by design — the config file is host-side only and requires the same trust level as other host-side configuration. This will be documented in `docs/security/security-model.md`.

## Implementation

### Phase 1: Config loader modules

**New file: `foundry_sandbox/user_services.py`** (~120 lines)

- `UserService` dataclass: `name`, `env_var`, `domain`, `header`, `format`, `methods`, `paths`
  - `methods` defaults to `["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]`
  - `paths` defaults to `["/**"]`
- `load_user_services(path=None) -> list[UserService]`: search order is explicit path -> `FOUNDRY_USER_SERVICES_PATH` env -> `./config/user-services.yaml`. Returns empty list if no file found. **Logs which path was resolved** for debuggability.
- Validation: env_var matches `[A-Z_][A-Z0-9_]*`, domain is non-empty, format is `bearer` or `value`, header is non-empty, methods entries are valid HTTP methods, paths entries are non-empty strings
- Path glob syntax (`/**`, `/api/**`) must use the same matching semantics as the existing allowlist `paths` field in `unified-proxy/config.py` — reuse the same matcher, do not introduce a second glob implementation
- `find_user_services_path() -> str | None`: returns the resolved path (needed for mounting into proxy)

**New file: `unified-proxy/user_services.py`** (~60 lines)

Shared proxy-side YAML loader so that `credential_injector.py`, `generate_squid_config.py`, and `config.py` all use a single parser:

- `ProxyUserService` dataclass: `name`, `env_var`, `domain`, `header`, `format`, `methods`, `paths`
- `load_proxy_user_services(path="/etc/unified-proxy/user-services.yaml") -> list[ProxyUserService]`: reads and validates the YAML. Returns empty list if file not found or malformed (logs warning on parse errors). Called once per proxy startup; callers cache the result.

This avoids three independent YAML parsers diverging if the schema changes. **Note:** `ProxyUserService` and `UserService` share the same YAML schema — both files should cross-reference each other with a comment to keep them in sync.

### Dependency Note

The CLI-side loader (`foundry_sandbox/user_services.py`) requires PyYAML. Verify `pyyaml` is listed in `pyproject.toml` dependencies; add it if missing. The proxy side already has `pyyaml~=6.0` in `unified-proxy/requirements.txt`.

### Phase 2: CLI-side integration (placeholder generation + status)

**Modify: `foundry_sandbox/models.py`** -- `CredentialPlaceholders`
- Add field: `user_service_placeholders: dict[str, str] = Field(default_factory=dict)`
- Extend `to_env_dict()`: for each entry, add `SANDBOX_{env_var}: placeholder` (e.g., `SANDBOX_OPENROUTER_API_KEY: CRED_PROXY_<hex>`)

**Modify: `foundry_sandbox/docker.py`** -- `setup_credential_placeholders()`
- After existing hardcoded logic, call `load_user_services()`
- For each service where `os.environ.get(svc.env_var)` is truthy, generate a placeholder via `_credential_placeholder()`
- Store in `user_service_placeholders` dict

**Modify: `foundry_sandbox/docker.py`** -- compose override management
- Refactor temp file cleanup: replace individual temp file variables with a `_compose_overrides: list[str]` that collects all temp override paths. Clean up the entire list in the `finally` block. This prevents the pattern from growing a new variable per feature.
- New `_prepare_user_services_override(compose_extras) -> tuple[str | None, list[str]]`:
  - Same pattern as `_prepare_allowlist_override()` (temp compose file, returns path + updated extras)
  - Generates compose override that:
    - Passes real env vars to `unified-proxy` (just the env var name, compose inherits from host; if unset on host, proxy gets empty string and `_load_credentials()` skips it — this is the correct no-op behavior)
    - Passes placeholder values to `dev` container (`ENV_VAR=${SANDBOX_OPENROUTER_API_KEY:-}`)
    - Bind-mounts the user-services.yaml into proxy at `/etc/unified-proxy/user-services.yaml:ro`
  - Returns `(None, compose_extras)` if no user-services.yaml found

**Modify: `foundry_sandbox/docker.py`** -- `compose_up()`
- Chain `_prepare_user_services_override()` after `_prepare_allowlist_override()`
- Both temp file paths go into `_compose_overrides` list for cleanup

**Modify: `foundry_sandbox/api_keys.py`** -- `get_cli_status()`
- After existing status lines, load user services and append status for each (configured/not configured)
- Uses same `os.environ.get(svc.env_var)` check as placeholder generation for consistency

### Phase 3: Proxy-side integration (credential injection + allowlist)

All three proxy-side consumers import from the shared `unified-proxy/user_services.py` loader.

**Modify: `unified-proxy/addons/credential_injector.py`** -- `CredentialInjector.__init__()`
- New instance attribute `self.provider_map = dict(PROVIDER_MAP)` — shallow copy of the module-level map so user entries don't leak across instances (matters for tests)
- All credential lookups in the class use `self.provider_map` instead of the module-level `PROVIDER_MAP`
- New method `_load_user_services()`:
  - Calls `load_proxy_user_services()` from shared loader
  - For each service, checks if `svc.domain` already exists in `self.provider_map` — if so, logs warning and **skips** (built-in providers are not overridable)
  - Otherwise, adds entry to `self.provider_map`: `{domain: {header, env_var, format}}`
- Call `_load_user_services()` before `_load_credentials()` so existing credential loading picks up user entries automatically

**Modify: `unified-proxy/generate_squid_config.py`**
- New helper `_load_user_mitm_domains()`: calls `load_proxy_user_services()`, returns list of domains
- In `generate_squid_config()`, extend `MITM_DOMAINS` with user domains **before** the dedup logic so existing wildcard deduplication handles them correctly

**Modify: `unified-proxy/config.py`** -- `load_allowlist_config()`
- After merging `PROXY_ALLOWLIST_EXTRA_PATH`, also load user services via shared loader
- New helper `_synthesize_allowlist_from_user_services(services) -> AllowlistConfig | None`:
  - Takes list of `ProxyUserService` (already loaded)
  - For each service, creates:
    - Domain entry for `svc.domain`
    - HTTP endpoint: `host=svc.domain`, `methods=svc.methods`, `paths=svc.paths`
  - Constructs the config via `AllowlistConfig._partial()` to bypass `__post_init__` validation (synthetic config won't have all required fields)
  - Returns `None` if services list is empty (caller skips merge)
- Merge into the config via existing `merge_allowlist_configs()`

### Phase 4: Example file + docs

**New file: `config/user-services.yaml.example`** -- documented example with commented-out entries showing both `bearer` and `value` formats, custom headers, and methods/paths overrides

**Modify: `docs/configuration.md`** -- add "User-Defined Services" section documenting:
- Config file format and field descriptions
- Search order for config file location
- How to verify a service is working (CLI status + curl test)
- Limitations (header injection only, no OAuth/body injection)

**Modify: `docs/security/security-model.md`** -- add note that user-services.yaml expands the allowlist and MITM scope, requires host-level trust

## Files Changed

| File | Type | Summary |
|------|------|---------|
| `foundry_sandbox/user_services.py` | New | CLI-side config loader + validation (~120 lines) |
| `unified-proxy/user_services.py` | New | Shared proxy-side YAML loader (~60 lines) |
| `config/user-services.yaml.example` | New | Documented example config |
| `foundry_sandbox/models.py` | Modify | Add `user_service_placeholders` dict to `CredentialPlaceholders` |
| `foundry_sandbox/docker.py` | Modify | Refactor temp file cleanup to list-based pattern, add `_prepare_user_services_override()`, extend `setup_credential_placeholders()` and `compose_up()` |
| `foundry_sandbox/api_keys.py` | Modify | Extend `get_cli_status()` for user services |
| `unified-proxy/addons/credential_injector.py` | Modify | Copy `PROVIDER_MAP` to instance attr, add `_load_user_services()` with conflict detection |
| `unified-proxy/generate_squid_config.py` | Modify | Load user service domains into MITM list via shared loader |
| `unified-proxy/config.py` | Modify | Synthesize allowlist entries from user services via shared loader |
| `docs/configuration.md` | Modify | Document user-services.yaml format and usage |
| `docs/security/security-model.md` | Modify | Document allowlist expansion trust model |

## Verification

1. Create `config/user-services.yaml` with a test service (e.g., OpenRouter)
2. Set `OPENROUTER_API_KEY=sk-or-test123` on host
3. Run `cast new` -- verify "OpenRouter: configured" appears in status output
4. Verify log output shows which user-services.yaml path was resolved
5. Inspect proxy container env -- verify `OPENROUTER_API_KEY=sk-or-test123` is set
6. Inspect sandbox container env -- verify `OPENROUTER_API_KEY=CRED_PROXY_<hex>` (placeholder)
7. From sandbox, `curl -X POST https://openrouter.ai/api/v1/chat/completions -H "Content-Type: application/json" -d '{}'` -- verify proxy injects real key (check proxy logs for injection, expect 401 from OpenRouter since test key is invalid)
8. Run `./scripts/ci-local.sh` -- verify existing tests pass
9. Run unit tests for both `user_services.py` modules
