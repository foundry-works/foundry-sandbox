# foundry-sandbox — Post-sbx-Migration Cleanup Checklist

**Last updated:** 2026-04-21
**Companion to:** `PLAN.md`

Legend: `[ ]` todo, `[x]` done, `[~]` partial / accepted risk

---

## 3.1 Remove Proxy-Era Legacy Artifacts

- [x] Delete `safety/` directory (network-firewall.sh, network-mode, gateway-*, credential-redaction.sh, sudoers-allowlist, operator-approve, sandbox-completions.bash)
- [x] Delete `lib/` directory (lib/python/*.py)
- [x] Delete `Dockerfile`
- [x] Delete `entrypoint.sh`
- [x] Delete `entrypoint-root.sh`
- [x] Delete `docker-compose.yml`
- [x] Delete `docker-compose.credential-isolation.yml`
- [x] Delete `tests/docker-compose.test.yml`
- [x] Delete `foundry.yaml`
- [x] Delete `statusline.conf`
- [x] Delete `completion.bash`
- [x] Delete `requirements.txt` (superseded by `pyproject.toml`)
- [x] Update `.github/workflows/test.yml:74` — drop shellcheck targets for deleted files
- [x] Update `scripts/ci-local.sh:99-100` — drop shellcheck targets for deleted files
- [x] Update `CLAUDE.md:9` description of `stubs/` — no change needed; §3.2 will update
- [x] Update `AGENTS.md:9` description of `stubs/` — fixed Docker→MicroVM, removed unified-proxy line
- [x] Sweep `docs/` for references to deleted files and update/remove
- [x] Confirm `git grep` finds no remaining references outside `CHANGELOG.md`, `docs/adr/`, `sbx-analysis.md`
- [x] `./scripts/ci-local.sh` passes

## 3.2 Consolidate Sandbox Stubs

- [x] Delete `stubs/git-wrapper.sh`
- [x] Delete `stubs/proxy-sign.sh` (duplicate of `foundry_sandbox/assets/proxy-sign.sh`)
- [x] Delete `stubs/git-api-standalone.py`
- [x] Delete `stubs/AGENTS.md`
- [x] Delete `stubs/CLAUDE.md`
- [x] Decide on Option A (keep `stubs/git-wrapper-sbx.sh` in place) or Option B (move to `foundry_sandbox/assets/`) — chose B
- [x] If Option B: move `git-wrapper-sbx.sh` to `foundry_sandbox/assets/` — already existed there (identical copy)
- [x] If Option B: update `scripts/build-foundry-template.sh:17,30` to resolve the new path
- [x] If Option B: update CI shellcheck target
- [x] If Option B: delete `stubs/` directory entirely
- [x] Verify no duplicate `proxy-sign.sh` remains
- [ ] Foundry-template rebuild passes via `./scripts/ci-local.sh --all` or smoke tests

## 3.3 Prune Legacy Constants and Dependency Manifests

- [x] Delete `TIMEOUT_DOCKER_COMPOSE` from `foundry_sandbox/constants.py`
- [x] Delete `TIMEOUT_DOCKER_BUILD` from `foundry_sandbox/constants.py`
- [x] Delete `TIMEOUT_DOCKER_NETWORK` from `foundry_sandbox/constants.py`
- [x] Delete `TIMEOUT_DOCKER_VOLUME` from `foundry_sandbox/constants.py`
- [x] Delete `CONTAINER_USER`, `CONTAINER_HOME`, `CONTAINER_OPENCODE_PLUGIN_DIR`, `SSH_AGENT_CONTAINER_SOCK` from `foundry_sandbox/constants.py`
- [x] Delete `DOCKER_IMAGE` from `foundry_sandbox/constants.py` (if present and unused)
- [x] Remove `"lib/python/**" = ["E402"]` from `pyproject.toml:94`
- [x] Remove `orchestration` pytest marker from `pyproject.toml:76` (if no test references it)
- [x] Grep for `UNIFIED_PROXY`, `GATEWAY_PORT`, `PROXY_SUBNET` and remove orphans from `config.py`, `paths.py`, `state.py`
- [x] `mypy --strict` passes
- [x] `ruff check` passes
- [x] `git grep -n "DOCKER_COMPOSE\|UNIFIED_PROXY\|TIMEOUT_DOCKER_" foundry_sandbox/` is empty

## 3.4 Complete `sbx` CLI Wrapper Surface

- [ ] Add JSON parsing to `sbx_diagnose()` in `foundry_sandbox/sbx.py:529-535`
- [ ] Update `commands/diagnose.py` to display structured fields
- [ ] Add `cpus: str | None` parameter to `sbx_create()`
- [ ] Add `memory: str | None` parameter to `sbx_create()`
- [ ] Add `sbx_ports_publish(name, spec)` helper to `foundry_sandbox/sbx.py`
- [ ] Add `sbx_ports_unpublish(name, spec)` helper to `foundry_sandbox/sbx.py`
- [ ] Add unit tests for JSON diagnose parsing
- [ ] Add unit tests for cpus/memory argv construction
- [ ] Add unit tests for ports publish/unpublish argv construction
- [ ] (Deferred) Decide whether to expose `cast ports` as a user-facing command — not required for this PR

## 3.5 Audit and Retire Compose-Era Test Modules

- [ ] Classify each module in `tests/redteam/modules/` as port / retire / skip
- [ ] Retire: delete `03-dns-filtering.sh`, `04-network-isolation.sh`, `05-proxy-egress.sh`, `06-direct-ip-egress.sh`, `07-proxy-admin.sh`, `14-network-bypass.sh`, `18-ip-encoding-bypass.sh` (contingent on classification)
- [ ] Port surviving credential / git-security modules to run against a live sbx sandbox
- [ ] Confirm `tests/chaos/modules/` modules 03 and 04 run under sbx or retire them
- [ ] Update `tests/redteam/harness.sh` and `tests/redteam/runner.sh` to match the new module set
- [ ] Update `tests/redteam-sandbox.sh` launcher to match
- [ ] Add `tests/redteam/README.md` (or update `tests/README.md`) documenting covered threats
- [ ] Update `docs/security/security-model.md` to reflect the reduced live suite
- [ ] Record deletions in `CHANGELOG.md`

## 3.6 Close the Deferred Deep-Policy Live Gate

- [ ] Decide how to stand up the deep-policy sidecar inside the smoke sandbox
- [ ] Add a live smoke test exercising a blocked GitHub API call (e.g. `PUT /repos/:o/:r/pulls/:n/merge`)
- [ ] Mark the test with `requires_sbx`
- [ ] Assert the deep-policy sidecar returns a block response (not a git-safety block)
- [ ] Flip prior `PLAN-CHECKLIST.md §3.8` item "Prove GitHub API merge/update path is blocked" from `[~]` to `[x]`
- [ ] Remove the accepted-risk note for GitHub API merge/update blocking from prior checklist / CHANGELOG if stale

## 3.7 Plan the Post-0.20.x Migration Sunset

- [ ] Pick an EOL release or date for the 0.20.x → 0.21.x migration helper
- [ ] Add EOL notice to `docs/migration/0.20-to-0.21.md`
- [ ] Add EOL notice to `CHANGELOG.md` under the next unreleased section
- [ ] File a tracked issue for the eventual deletion work covering: `foundry_sandbox/migration.py`, `commands/migrate.py`, `cli.py:50-51` entries, `tests/unit/test_migration.py`, `tests/smoke/test_migration_smoke.py`, `docs/migration/0.20-to-0.21.md`
- [ ] Do **not** delete migration code in this workstream

---

## Final Verification Gate

- [ ] Root unit tests pass
- [ ] `foundry-git-safety` unit tests pass
- [ ] `foundry-git-safety` integration tests pass
- [ ] `./scripts/ci-local.sh` passes
- [ ] `./scripts/ci-local.sh --all` passes
- [ ] `tests/smoke/test_live_sbx.py` passes against a local `sbx` install
- [ ] Installed wheel still provisions a sandbox end-to-end
- [ ] No deleted file is referenced outside `CHANGELOG.md`, `docs/adr/`, `sbx-analysis.md`
- [ ] `mypy --strict` passes
- [ ] `ruff check` passes
- [ ] `git diff --check main HEAD` is clean
