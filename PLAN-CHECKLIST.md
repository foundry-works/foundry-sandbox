# Implementation Checklist

## Phase 1: Auto-discovery and env var loading
- [x] Add `_collect_compose_extras(cli_extras=None) -> list[str]` to `foundry_sandbox/docker.py`
- [x] Implement auto-discovery: glob `config/docker-compose.*.yml`, sorted by name
- [x] Implement `FOUNDRY_COMPOSE_EXTRAS` env var parsing (colon-separated, skip empty segments)
- [x] Append `cli_extras` after env var paths
- [x] Resolve all paths to absolute via `Path.resolve()` before validation and dedup
- [x] Validate all resolved paths exist and are regular files (`FileNotFoundError` with clear message showing original path)
- [x] Deduplicate on resolved absolute paths, preserving earliest occurrence
- [x] Log final extras list at DEBUG level
- [x] Wire `_collect_compose_extras()` into `compose_up()` — call before `get_compose_command()`, merge with existing temp overrides
- [x] Wire `_collect_compose_extras()` into `compose_down()` — pass sidecar extras so custom networks/volumes are cleaned up

## Phase 2: CLI flag + metadata persistence
- [x] `foundry_sandbox/commands/new.py`: Add `--compose-extra` Click option (`multiple=True`, `click.Path(exists=True)`)
- [x] `foundry_sandbox/commands/new_setup.py`: Add `compose_extras` keyword parameter to `_new_setup()`
- [x] Pass CLI extras through to `compose_up()` via `compose_extras` parameter
- [x] `foundry_sandbox/models.py`: Add `compose_extras: list[str]` to `SandboxMetadata`
- [x] `foundry_sandbox/models.py`: Add `compose_extras: list[str]` to `CastNewPreset`
- [x] Store paths **relative to project root** in metadata (resolve to absolute at load time)
- [x] `foundry_sandbox/commands/start.py`: Add `--compose-extra` Click option (`multiple=True`, `click.Path(exists=True)`)
- [x] `foundry_sandbox/commands/start.py`: Load `compose_extras` from metadata, merge with CLI extras, pass to `compose_up()`
- [x] `foundry_sandbox/commands/start.py`: Pass merged extras to error-path `compose_down()` call
- [x] `foundry_sandbox/commands/stop.py`: Load `compose_extras` from metadata, pass to `compose_down()`
- [ ] Verify metadata survives stop/start cycle

## Phase 3: Documentation + templates
- [ ] Create `docs/usage/sidecars.md` with network topology, Pattern A (internal-only), Pattern B (with egress)
- [ ] Document all three extension mechanisms (auto-discovery, env var, CLI flag) with precedence
- [ ] Document auto-discovery "live-fire" behavior: matching files are included unconditionally, use `.yml.disabled` / `.yml.bak` to exclude
- [ ] Add troubleshooting section (container not starting, network connectivity, healthchecks)
- [ ] Create `config/docker-compose.redis.yml.example` (internal-only sidecar template)
- [ ] Create `config/docker-compose.ollama.yml.example` (sidecar-with-egress template)
- [ ] `docs/configuration.md`: Add "Sidecar Containers" section with brief overview + link to sidecars guide
- [ ] `docs/security/security-model.md`: Add "Sidecar Containers" subsection under "Explicit Non-Goals and Accepted Risks" covering:
  - [ ] Host volume mount trust boundary (compose files are repo-owner-controlled)
  - [ ] Proxy bypass: `proxy-egress` sidecars reach internet directly, not through mitmproxy
  - [ ] Privilege escalation surface: `privileged`, host network mode (accepted risk, same trust as Dockerfiles)
  - [ ] Network isolation: custom internal networks cannot reach internet
  - [ ] Trust model summary: compose files in `config/` = same trust level as base compose

## Phase 4: Testing
- [ ] Create `tests/unit/test_collect_compose_extras.py`
- [ ] Test: auto-discovery finds `config/docker-compose.*.yml`, sorted by name
- [ ] Test: auto-discovery returns empty list when no matching files
- [ ] Test: env var single path
- [ ] Test: env var multiple colon-separated paths
- [ ] Test: env var with empty segments (leading/trailing/double colons)
- [ ] Test: CLI extras appended after env var paths
- [ ] Test: deduplication on resolved paths (relative and absolute pointing to same file)
- [ ] Test: missing path raises `FileNotFoundError` with offending path in message
- [ ] Test: all three sources combine correctly (auto-discovered + env var + CLI)
- [ ] Test: relative paths in metadata resolved correctly at load time
- [ ] Test: metadata round-trip — compose extras stored at new, loaded at start/stop
- [ ] Test: `compose_down()` receives sidecar extras for network/volume cleanup
- [ ] Verify `_collect_compose_extras()` output integrates with `get_compose_command()` ordering
- [ ] Run `./scripts/ci-local.sh` — all existing and new tests pass
- [ ] Manual test: drop Redis override into `config/`, `cast new`, verify sidecar starts
- [ ] Manual test: `cast stop` + `cast start`, verify sidecar comes back via metadata
- [ ] Manual test: `--compose-extra` flag on `cast new` with explicit path
- [ ] Manual test: `--compose-extra` flag on `cast start` (merged with metadata extras)
- [ ] Manual test: `FOUNDRY_COMPOSE_EXTRAS` env var
