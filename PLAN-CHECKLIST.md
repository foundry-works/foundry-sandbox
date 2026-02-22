# Implementation Checklist

## Phase 1: Config loader modules
- [x] Verify `pyyaml` is in `pyproject.toml` dependencies; add if missing
- [x] Create `foundry_sandbox/user_services.py` with `UserService` dataclass and `load_user_services()` loader
- [x] Add `find_user_services_path()` helper for resolving config file location
- [x] Search order: explicit path -> `FOUNDRY_USER_SERVICES_PATH` env -> `./config/user-services.yaml` (no `~/.config` fallback for MVP)
- [x] Add validation (env_var format, domain non-empty, format is bearer/value, header non-empty, methods are valid HTTP methods, paths non-empty)
- [x] Path glob syntax must reuse existing allowlist path matching from `unified-proxy/config.py`
- [x] Default methods: `["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]`
- [x] Log which config path was resolved (or that none was found)
- [x] Create `unified-proxy/user_services.py` with shared `ProxyUserService` dataclass and `load_proxy_user_services()` loader
- [x] Add cross-reference comments between `UserService` and `ProxyUserService` noting shared schema
- [x] Handle missing/malformed YAML gracefully in proxy loader (return empty list, log warning)

## Phase 2: CLI-side integration
- [x] `foundry_sandbox/models.py`: Add `user_service_placeholders: dict[str, str]` to `CredentialPlaceholders`
- [x] `foundry_sandbox/models.py`: Extend `to_env_dict()` to emit `SANDBOX_{env_var}` entries
- [x] `foundry_sandbox/docker.py`: Extend `setup_credential_placeholders()` to generate placeholders for user services
- [x] `foundry_sandbox/docker.py`: Refactor temp file cleanup from individual variables to `_compose_overrides` list pattern
- [x] `foundry_sandbox/docker.py`: Add `_prepare_user_services_override()` (temp compose override, mounts config + threads env vars)
- [x] `foundry_sandbox/docker.py`: Extend `compose_up()` to chain user services override + list-based cleanup
- [x] `foundry_sandbox/api_keys.py`: Extend `get_cli_status()` to show user service status

## Phase 3: Proxy-side integration
- [x] `unified-proxy/addons/credential_injector.py`: Add `self.provider_map = dict(PROVIDER_MAP)` instance copy in `__init__()` — do NOT mutate the module-level dict
- [x] `unified-proxy/addons/credential_injector.py`: Update all credential lookups to use `self.provider_map` instead of module-level `PROVIDER_MAP`
- [x] `unified-proxy/addons/credential_injector.py`: Add `_load_user_services()` using shared `load_proxy_user_services()`
- [x] `unified-proxy/addons/credential_injector.py`: Add domain conflict detection — skip with warning if domain exists in built-in `PROVIDER_MAP`
- [x] `unified-proxy/addons/credential_injector.py`: Call `_load_user_services()` before `_load_credentials()` in `__init__()`
- [x] `unified-proxy/generate_squid_config.py`: Add `_load_user_mitm_domains()` using shared loader
- [x] `unified-proxy/generate_squid_config.py`: Extend MITM list before dedup logic in `generate_squid_config()`
- [x] `unified-proxy/config.py`: Add `_synthesize_allowlist_from_user_services()` helper (uses `AllowlistConfig._partial()`, returns `AllowlistConfig | None`)
- [x] `unified-proxy/config.py`: Integrate into `load_allowlist_config()` after extra path merge, skip merge if None

## Phase 4: Documentation
- [x] Create `config/user-services.yaml.example` with documented examples (bearer, value, custom headers, methods/paths)
- [x] `docs/configuration.md`: Add "User-Defined Services" section (format, search order, verification, limitations)
- [x] `docs/security/security-model.md`: Add note on allowlist expansion trust model

## Phase 5: Testing
- [x] Unit tests for `foundry_sandbox/user_services.py`: valid config loads correctly
- [x] Unit tests for `foundry_sandbox/user_services.py`: missing file returns empty list
- [x] Unit tests for `foundry_sandbox/user_services.py`: malformed YAML (missing fields, bad env_var format, invalid method)
- [x] Unit tests for `foundry_sandbox/user_services.py`: config path search order and logging
- [x] Unit tests for `unified-proxy/user_services.py`: valid config, missing file, malformed YAML
- [x] Unit tests for `foundry_sandbox/models.py`: `to_env_dict()` emits `SANDBOX_OPENROUTER_API_KEY` etc. from `user_service_placeholders`
- [x] Unit tests for placeholder generation with user services (env var set vs not set)
- [x] Unit tests for compose override generation (mounts config, passes env vars)
- [x] Unit tests for proxy-side `self.provider_map` dynamic loading (instance copy, not module-level mutation)
- [x] Unit tests for domain conflict detection (built-in domain skipped with warning)
- [x] Unit tests for allowlist synthesis (domains + endpoints generated, uses `_partial()`, empty services returns None)
- [x] Unit tests for MITM domain extension (user domains added before dedup)
- [x] Run `./scripts/ci-local.sh` -- all existing tests pass
- [ ] Manual integration test: create config, set env var, `cast new`, verify status output
- [ ] Manual integration test: verify compose override mounts user-services.yaml into proxy
- [ ] Manual integration test: verify proxy injects credential on matching request (check proxy logs)
- [ ] Manual integration test: verify env var not set on host → no placeholder generated, proxy doesn't inject
