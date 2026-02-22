# Plan: Sidecar Container Extension Points

## Context

Adding a sibling container to a sandbox (e.g., Redis for caching, a local vector DB, a dev database) requires manually writing a docker-compose override, knowing the internal network topology, and invoking `docker compose` with the right `-f` chain. Teardown must mirror the same chain. None of this is integrated into `cast`.

The `compose_extras` parameter already exists end-to-end in `docker.py` — `get_compose_command()`, `compose_up()`, and `compose_down()` all accept it, with path validation and correct `-f` ordering. It's used in production for `PROXY_ALLOWLIST_EXTRA_PATH` and user-services mounting. The infrastructure is tested (886 lines in `test_compose_extras.py`). What's missing is the user-facing layer: CLI flags, auto-discovery, and documentation.

## Design

Three complementary ways to attach sidecar compose overrides, plus documentation so users don't have to reverse-engineer the network topology.

### Extension Mechanisms

**1. `--compose-extra` CLI flag** — explicit, per-invocation

```bash
cast new my-sandbox --compose-extra ./config/docker-compose.redis.yml
cast start my-sandbox --compose-extra ./extra-override.yml
```

Accepts one or more paths. Validated at invocation time. On `cast new`, stored in sandbox metadata so subsequent `cast start` / `cast stop` can reconstruct the same `-f` chain without re-specifying. On `cast start`, merged with any metadata-persisted extras for that invocation (but not re-persisted — use `cast new` to set the permanent baseline).

**2. Auto-discovery from `config/`** — convention-based, zero-flag

```
config/
  user-services.yaml              # API services (existing)
  docker-compose.redis.yml        # Sidecar (auto-discovered)
  docker-compose.chromadb.yml     # Another sidecar (auto-discovered)
```

Any file matching `config/docker-compose.*.yml` is automatically included. No flags needed — drop a file in, it gets picked up. Files are sorted by name for deterministic ordering.

Note: `.example` files don't match the glob. This directory is a **live-fire zone** — any matching file is included unconditionally. Temporary or work-in-progress files should use a different extension (e.g., `.yml.disabled`, `.yml.bak`) to avoid accidental inclusion. This will be called out in the documentation.

**3. `FOUNDRY_COMPOSE_EXTRAS` env var** — persistent, no flags or file placement

```bash
export FOUNDRY_COMPOSE_EXTRAS="/path/to/docker-compose.redis.yml:/path/to/another.yml"
```

Colon-separated paths. Same pattern as `PROXY_ALLOWLIST_EXTRA_PATH` and `FOUNDRY_USER_SERVICES_PATH`.

### Precedence

All three mechanisms stack. The final `-f` chain is:

```
base → credential-isolation → user override → auto-discovered → env var → CLI flag
```

Later files override earlier ones (standard docker-compose merge behavior).

### Teardown (`compose_down`) Behavior

`compose_down()` does **not** call the `_prepare_allowlist_override()` or `_prepare_user_services_override()` functions — those temp overrides are only generated during `compose_up()`. This is fine: `docker compose down` tears down all services in the Compose project regardless of which `-f` files are passed, because it operates on the project name, not the file list. The `-f` files are only needed during `down` to resolve project name and custom networks/volumes for cleanup.

The sidecar extras **are** passed to `compose_down()` so that any custom networks or named volumes defined in the sidecar overrides are properly cleaned up.

### Network Topology

Sidecars can attach to these networks:

| Network | Type | Purpose |
|---------|------|---------|
| `credential-isolation` | Internal bridge | Sandbox ↔ proxy (existing) |
| `proxy-egress` | External bridge | Proxy/sidecars → internet (existing) |
| Custom (e.g., `redis-internal`) | Internal bridge | Sandbox ↔ sidecar (user-defined) |

**Pattern A: Internal-only sidecar** — sandbox talks to it, no internet access. Define a custom internal network shared between the `dev` service and the sidecar.

**Pattern B: Sidecar with egress** — sidecar also needs to reach external servers (e.g., downloading models). Attach the sidecar to both a custom internal network and `proxy-egress`.

### Not Doing

- A `config/sidecars.yaml` abstraction on top of compose. Compose files are already declarative — wrapping them in another YAML just moves complexity without reducing it.
- A separate `config/sidecars.d/` directory for auto-discovery. The `config/` convention is already established and adding a subdirectory fragments discoverability. The glob pattern is explicit enough, and documentation will make the "live-fire" nature clear.

## Example: Redis (Internal-Only Sidecar)

```yaml
# config/docker-compose.redis.yml
services:
  redis:
    image: redis:7-alpine
    expose:
      - "6379"
    networks:
      redis-internal: {}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  dev:
    networks:
      - redis-internal
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      redis:
        condition: service_healthy

networks:
  redis-internal:
    driver: bridge
    internal: true
```

With auto-discovery, dropping this into `config/` is all that's needed. `cast new` picks it up, `cast stop` tears it down.

## Example: Ollama (Sidecar With Egress)

```yaml
# config/docker-compose.ollama.yml
services:
  ollama:
    image: ollama/ollama:latest
    expose:
      - "11434"
    networks:
      ollama-internal: {}
      proxy-egress: {}       # needs internet to pull models
    volumes:
      - ollama-models:/root/.ollama
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:11434/api/tags || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 30s

  dev:
    networks:
      - ollama-internal
    environment:
      - OLLAMA_HOST=http://ollama:11434
    depends_on:
      ollama:
        condition: service_healthy

networks:
  ollama-internal:
    driver: bridge
    internal: true

volumes:
  ollama-models:
```

## Implementation

### Phase 1: Auto-discovery and env var loading

**Modify: `foundry_sandbox/docker.py`** -- new `_collect_compose_extras()`

Centralize all compose extras collection into one function (~50 lines):

- `_collect_compose_extras(cli_extras=None) -> list[str]`:
  - Start with auto-discovered files: glob `config/docker-compose.*.yml` relative to project root, sorted by name
  - Append paths from `FOUNDRY_COMPOSE_EXTRAS` env var (colon-split, skip empty segments)
  - Append `cli_extras` (from `--compose-extra` flag)
  - Resolve all paths to absolute (`Path.resolve()`) before validation and deduplication
  - Validate all resolved paths exist and are regular files (raise `FileNotFoundError` with clear message showing the original path)
  - Return deduplicated list preserving order — dedup on resolved absolute paths so `./config/foo.yml` and `/abs/path/config/foo.yml` are recognized as the same file
  - Log the final list at DEBUG level for troubleshootability

This function is called by `compose_up()` and `compose_down()` before passing extras to `get_compose_command()`. It does **not** include the temp overrides for allowlist/user-services — those are added separately by their existing `_prepare_*` functions.

### Phase 2: CLI flag + metadata persistence

**Modify: `foundry_sandbox/commands/new.py`** -- add Click option

- Add `--compose-extra` Click option (`multiple=True`, type `click.Path(exists=True)`)
- Pass through to `_new_setup()` as `compose_extras`

**Modify: `foundry_sandbox/commands/new_setup.py`** -- accept and forward `compose_extras`

- Add `compose_extras` keyword parameter (list of paths) to `_new_setup()`
- Pass to `compose_up()` via existing `compose_extras` parameter

**Modify: `foundry_sandbox/models.py`** -- persist in sandbox metadata

- Add `compose_extras: list[str] = Field(default_factory=list)` to `SandboxMetadata`
- Add `compose_extras: list[str] = Field(default_factory=list)` to `CastNewPreset` (mirrors metadata for preset persistence)
- Store paths **relative to project root** at `cast new` time — resolve to absolute at load time. This avoids stale paths when the project directory moves or another user clones with a different home path.

**Modify: `foundry_sandbox/commands/start.py`**

- Add `--compose-extra` Click option (`multiple=True`, type `click.Path(exists=True)`)
- Load `compose_extras` from sandbox metadata
- Merge CLI extras (appended after metadata extras) and pass to `compose_up()`
- Also pass merged extras to the `compose_down()` call in the error-recovery path

**Modify: `foundry_sandbox/commands/stop.py`**

- Load `compose_extras` from sandbox metadata
- Pass to `compose_down()`

### Phase 3: Documentation + templates

**New file: `docs/usage/sidecars.md`** -- sidecar guide covering:

- Network topology diagram (credential-isolation, proxy-egress, custom internal)
- Pattern A walkthrough: internal-only sidecar (Redis example)
- Pattern B walkthrough: sidecar with egress (Ollama example)
- All three extension mechanisms (auto-discovery, env var, CLI flag)
- Precedence and `-f` chain ordering
- Troubleshooting (container not starting, network connectivity, healthchecks)

**New file: `config/docker-compose.redis.yml.example`** -- copy-paste template for internal-only pattern

**New file: `config/docker-compose.ollama.yml.example`** -- copy-paste template for egress pattern

**Modify: `docs/configuration.md`** -- add "Sidecar Containers" section with brief overview + link to `docs/usage/sidecars.md`

**Modify: `docs/security/security-model.md`** -- add "Sidecar Containers" subsection under "Explicit Non-Goals and Accepted Risks"

This is a meaningful expansion of the security perimeter and deserves more than a one-liner. The subsection should cover:

- **Host volume mounts**: Sidecar compose files can mount arbitrary host paths — the trust boundary is the compose file itself (same as `CLAUDE.md`, controlled by the repo owner)
- **Proxy bypass**: Sidecars on `proxy-egress` reach the internet directly, not through mitmproxy — they are not subject to allowlist filtering or credential isolation
- **Privilege escalation surface**: A compose file could specify `privileged: true`, host network mode, or other Docker capabilities. This is accepted risk — compose files are repo-owner-controlled, same trust level as Dockerfiles
- **Network isolation**: Sidecars on custom internal networks (`internal: true`) cannot reach the internet. Sidecars must explicitly join `proxy-egress` for egress.
- **Trust model summary**: Compose files in `config/` are trusted at the same level as the base `docker-compose.yml` — they are checked into the repo and reviewed via normal code review

### Phase 4: Testing

**New tests in `tests/unit/test_collect_compose_extras.py`**:

- Auto-discovery finds `config/docker-compose.*.yml` files, sorted by name
- Auto-discovery returns empty list when no matching files exist
- Env var parsing: single path, multiple colon-separated paths, empty segments skipped
- CLI extras appended after env var paths
- Deduplication preserves earliest occurrence
- Missing path raises `FileNotFoundError` with the offending path in the message
- Integration: all three sources combine correctly

**Extend existing tests**:

- `test_compose_extras.py`: verify `_collect_compose_extras()` output integrates correctly with `get_compose_command()` ordering
- Metadata round-trip: compose extras stored at `new` time, loaded at `start`/`stop` time

## Files Changed

| File | Type | Summary |
|------|------|---------|
| `foundry_sandbox/docker.py` | Modify | Add `_collect_compose_extras()`, wire into `compose_up()` / `compose_down()` |
| `foundry_sandbox/commands/new.py` | Modify | Add `--compose-extra` Click option, pass to `_new_setup()` |
| `foundry_sandbox/commands/new_setup.py` | Modify | Accept `compose_extras` param, forward to `compose_up()` |
| `foundry_sandbox/models.py` | Modify | Add `compose_extras` to `SandboxMetadata` and `CastNewPreset` |
| `foundry_sandbox/commands/start.py` | Modify | Add `--compose-extra` flag, load from metadata, merge, pass to `compose_up()` and error-path `compose_down()` |
| `foundry_sandbox/commands/stop.py` | Modify | Load compose extras from metadata, pass to `compose_down()` |
| `docs/usage/sidecars.md` | New | Sidecar guide with network topology, patterns, examples |
| `config/docker-compose.redis.yml.example` | New | Internal-only sidecar template |
| `config/docker-compose.ollama.yml.example` | New | Sidecar-with-egress template |
| `docs/configuration.md` | Modify | Add sidecar section with link |
| `docs/security/security-model.md` | Modify | Add "Sidecar Containers" subsection under accepted risks |
| `tests/unit/test_collect_compose_extras.py` | New | Unit tests for extras collection |

## Verification

1. Drop `docker-compose.redis.yml` into `config/` — verify `cast new` picks it up (check compose command in debug logs)
2. Run `cast new --compose-extra ./some-override.yml` — verify override is applied and path is stored in metadata
3. Run `cast stop` then `cast start` — verify the sidecar comes back (metadata persistence)
4. Set `FOUNDRY_COMPOSE_EXTRAS=/path/to/override.yml` — verify it's included
5. Verify all three mechanisms stack correctly when used simultaneously
6. Verify missing path produces clear error, not a compose failure
7. Run `./scripts/ci-local.sh` — all existing and new tests pass
