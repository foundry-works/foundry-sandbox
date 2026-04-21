# foundry-sandbox — Post-sbx-Migration Cleanup Plan

**Last updated:** 2026-04-21
**Branch:** `sbx`
**Scope:** Delete proxy-era legacy code that the sbx migration superseded, close small fidelity gaps in the `sbx` CLI wrapper, and put the remaining fragile pieces (deep-policy live gate, compose-era test modules, 0.20.x migration path) on an explicit schedule.

**Companion file:** `PLAN-CHECKLIST.md`

---

## 1. Objective

Finish the sbx migration by removing the docker-compose / unified-proxy artifacts that are now dead, reducing surface area for security auditors, shellcheck/CI, and new contributors. Fill the handful of sbx wrapper gaps identified during review. Do not change runtime semantics for the sbx control plane that already shipped in 0.21.0.

The migration itself is ~85% complete (see §3.1–§3.9 of the prior plan in `CHANGELOG.md`). This plan is about removing the remaining 15% of legacy mass, plus two small correctness/observability items that were deferred.

---

## 2. Review Findings Driving This Plan

1. The proxy-era runtime — `safety/` helpers, `lib/python/` agent-init scripts, `Dockerfile`, `entrypoint.sh`, `entrypoint-root.sh`, `docker-compose.yml`, `docker-compose.credential-isolation.yml`, `tests/docker-compose.test.yml`, `foundry.yaml`, `statusline.conf`, `completion.bash` — is unreferenced from `foundry_sandbox/` Python code but still present at the repo root and still exercised by `.github/workflows/test.yml:74` and `scripts/ci-local.sh:99` (shellcheck only).
2. `stubs/` contains a mix of live assets (`git-wrapper-sbx.sh`) and dead duplicates (`git-wrapper.sh`, `proxy-sign.sh`, `git-api-standalone.py`, `AGENTS.md`, `CLAUDE.md`). The canonical copies the code actually loads live at `foundry_sandbox/assets/` (`git_safety.py:276`, `scripts/build-foundry-template.sh:17,30`).
3. `foundry_sandbox/constants.py:103-131` declares `TIMEOUT_DOCKER_COMPOSE`, `TIMEOUT_DOCKER_BUILD`, `TIMEOUT_DOCKER_NETWORK`, `TIMEOUT_DOCKER_VOLUME` and earlier container constants with no callers. `pyproject.toml:94` carries a `lib/python/**` ruff override that becomes dead as soon as `lib/` is removed. `requirements.txt` still lists Flask/Werkzeug/gunicorn/mitmproxy/httpx/python-dotenv — none are in `pyproject.toml` and none are imported from `foundry_sandbox/`.
4. `foundry_sandbox/sbx.py` covers lifecycle, exec, secrets, policy, templates, and diagnose — but `sbx_diagnose()` returns a raw `CompletedProcess` rather than parsed JSON (`sbx.py:529-535`), `sbx_create()` has no `--cpus`/`--memory` parameters, and there is no wrapper for `sbx ports publish/unpublish`.
5. `PLAN-CHECKLIST.md §3.8` accepted as risk that the deep-policy sidecar GitHub merge/update blocking is not live-tested. That gap is still open; the smoke suite only exercises git-safety wrapper paths.
6. `tests/redteam/modules/` still contains compose-shaped scenarios (`05-proxy-egress.sh`, `07-proxy-admin.sh`, `04-network-isolation.sh`, `18-ip-encoding-bypass.sh`) that exercise the removed unified-proxy. They likely fail or silently skip under sbx. `tests/chaos/modules/` looks partially ported.
7. `commands/migrate.py` and `foundry_sandbox/migration.py` are still live because 0.20.x users may upgrade, but there is no declared sunset. Once 0.20.x EOL is set, the two `_LAZY_COMMANDS` entries at `cli.py:50-51` plus ~540 lines of migration code can go.

---

## 3. Workstreams

### 3.1 Remove Proxy-Era Legacy Artifacts

Current state:
- Repo-root legacy files exist and are shellchecked in CI but never executed by the sbx path.
- No `foundry_sandbox/*.py` or `scripts/*` references these files except CI lint rules.
- `docker-compose.credential-isolation.yml:180` is the only live reference to `stubs/git-wrapper.sh`; once the compose files go, the old wrapper has no consumer.

Required work:
- Delete: `safety/` (8 files), `lib/` (entire `python/` subdir), `Dockerfile`, `entrypoint.sh`, `entrypoint-root.sh`, `docker-compose.yml`, `docker-compose.credential-isolation.yml`, `tests/docker-compose.test.yml`, `foundry.yaml`, `statusline.conf`, `completion.bash`, `requirements.txt`.
- Update `.github/workflows/test.yml:74` to stop shellchecking `entrypoint.sh entrypoint-root.sh stubs/git-wrapper.sh`; keep only `stubs/git-wrapper-sbx.sh` (or its new home — see §3.2).
- Update `scripts/ci-local.sh:99-100` in the same way.
- Update `CLAUDE.md:9` and `AGENTS.md:9` descriptions of `stubs/` to reflect the final contents.
- Remove any mention of the deleted files from `docs/` (grep-driven sweep, not a rewrite).

Exit criteria:
- `git grep -l "docker-compose\|unified-proxy\|entrypoint\.sh" -- ':!CHANGELOG.md' ':!docs/adr/**' ':!sbx-analysis.md'` returns nothing.
- `./scripts/ci-local.sh` still passes.
- The wheel artifact list is unchanged (these files were never packaged).

### 3.2 Consolidate Sandbox Stubs

Current state:
- `stubs/git-wrapper-sbx.sh` is live — loaded by `scripts/build-foundry-template.sh` during template build.
- `stubs/git-wrapper.sh`, `stubs/proxy-sign.sh`, `stubs/git-api-standalone.py`, `stubs/AGENTS.md`, `stubs/CLAUDE.md` have no runtime consumers.
- Canonical copies of the live wrapper and proxy-sign helper already live at `foundry_sandbox/assets/`, shipped in the wheel via `pyproject.toml:96-100`.

Required work:
- Delete `stubs/git-wrapper.sh`, `stubs/proxy-sign.sh`, `stubs/git-api-standalone.py`, `stubs/AGENTS.md`, `stubs/CLAUDE.md`.
- Decide placement of `git-wrapper-sbx.sh`:
  - Option A: leave under `stubs/`, delete everything else.
  - Option B: move to `foundry_sandbox/assets/git-wrapper-sbx.sh` alongside the other canonical assets, update `scripts/build-foundry-template.sh:17,30` and the CI shellcheck target, and delete `stubs/` entirely.
- Option B is preferred — it eliminates a top-level directory and makes the wrapper wheel-resident, but requires updating the build script and any developer muscle memory.
- Verify no duplicate `proxy-sign.sh` remains; `foundry_sandbox/assets/proxy-sign.sh` is the only copy after cleanup.

Exit criteria:
- There is exactly one git wrapper on disk (`git-wrapper-sbx.sh`) and one proxy-sign script (`proxy-sign.sh`).
- `scripts/build-foundry-template.sh` and the CI shellcheck step both resolve the chosen path.
- The foundry-template rebuild in `./scripts/ci-local.sh --all` or the smoke tests still succeeds.

### 3.3 Prune Legacy Constants and Dependency Manifests

Current state:
- `foundry_sandbox/constants.py:103-131` defines `TIMEOUT_DOCKER_COMPOSE/BUILD/NETWORK/VOLUME`, none referenced outside the file.
- Earlier in the same file, `CONTAINER_USER`, `CONTAINER_HOME`, `CONTAINER_OPENCODE_PLUGIN_DIR`, `SSH_AGENT_CONTAINER_SOCK`, `DOCKER_IMAGE` describe the old container model.
- `pyproject.toml:94` has `"lib/python/**" = ["E402"]` — becomes dead once §3.1 lands.
- `pyproject.toml:76` declares a pytest marker `orchestration: marks docker orchestration/lifecycle tests` — no current test applies it (grep).
- `requirements.txt` lists Flask/Werkzeug/gunicorn/mitmproxy/httpx/python-dotenv — zero imports from `foundry_sandbox/`. Deleted as part of §3.1 but cross-listed here for traceability.

Required work:
- Remove unreferenced container/docker-era constants from `foundry_sandbox/constants.py`. Keep `TIMEOUT_SBX_*` (in `sbx.py`) as the authoritative source.
- Remove the `lib/python/**` ruff override and the `orchestration` pytest marker.
- Grep once more for any other docker/compose term (`unified-proxy`, `GATEWAY_PORT`, `PROXY_SUBNET`, etc.) that leaked into `config.py`, `paths.py`, or `state.py`; delete orphans.
- Cross-check `mypy --strict` and `ruff check` both still pass after removal.

Exit criteria:
- `git grep -n "DOCKER\|CONTAINER_\|UNIFIED_PROXY" foundry_sandbox/` returns only genuine sbx usage (if any) or nothing.
- No pytest marker or ruff override references removed paths.
- `./scripts/ci-local.sh` passes.

### 3.4 Complete the `sbx` CLI Wrapper Surface

Current state:
- `foundry_sandbox/sbx.py` covers: lifecycle (create/run/stop/rm/ls/exists/is_running), exec (normal + streaming), secrets (set), policy (set-default/allow/deny network), templates (save/load/ls/rm), diagnose, version check, plugin-shim detection.
- Gaps: `sbx_diagnose()` returns raw `CompletedProcess` (no JSON parsing), `sbx_create()` lacks `--cpus`/`--memory` parameters, no wrapper for `sbx ports publish/unpublish`.
- Nothing in `commands/` currently needs ports/resource-limits — the gap is feature-completeness, not a bug.

Required work:
- Teach `sbx_diagnose()` to parse `sbx diagnose --json` output into a structured dict, with a `parse: bool` flag so existing callers that want raw text still work. Update `commands/diagnose.py` to display structured fields instead of piping raw output.
- Add optional `cpus: str | None` and `memory: str | None` parameters to `sbx_create()` (accept either numeric strings or sbx's native format; let sbx error on invalid input).
- Add `sbx_ports_publish(name, spec)` and `sbx_ports_unpublish(name, spec)` helpers. Do **not** add a `cast ports` command in this PR — expose via config/preset first, or defer until a command case materializes.
- Add unit tests asserting the wrappers build the right `sbx ...` argv.

Exit criteria:
- `cast diagnose` surfaces parsed sbx status alongside foundry git-safety status.
- Resource-limit parameters flow from `sbx_create()` to the `sbx create` argv.
- Ports helpers exist on `sbx.py` with unit-test coverage but need not be wired to the CLI.

### 3.5 Audit and Retire Compose-Era Test Modules

Current state:
- `tests/redteam/modules/` contains 20 scripts; several are explicitly compose/proxy-shaped: `05-proxy-egress.sh`, `07-proxy-admin.sh`, `04-network-isolation.sh`, `14-network-bypass.sh`, `18-ip-encoding-bypass.sh`. Others (git-security, self-merge, workflow-push, credential-*) likely still have value against an sbx sandbox but have not been verified.
- `tests/chaos/modules/01-sbx-daemon-kill.sh` and `02-git-safety-server-kill.sh` suggest partial sbx rewrite; `03-network-partition.sh` and `04-corrupted-reset.sh` need confirmation.
- `tests/redteam/harness.sh` and `tests/redteam/runner.sh` may assume compose networking.

Required work:
- Per module, make a three-way decision: **port** (rewrite against sbx), **retire** (delete), or **skip** (keep for reference behind a marker that's not run in CI).
- Suggested initial classification (subject to confirmation on read):
  - Port: `01-credentials-env`, `02-credentials-files`, `08-credential-injection`, `09-git-security`, `11-github-api`, `13-credential-patterns`, `15-self-merge`, `17-workflow-push`, `19-merge-early-exit`.
  - Retire: `03-dns-filtering`, `04-network-isolation`, `05-proxy-egress`, `06-direct-ip-egress`, `07-proxy-admin`, `14-network-bypass`, `18-ip-encoding-bypass` (these depend on the deleted proxy network stack).
  - Defer / evaluate: `10-container-escape`, `12-tls-filesystem`, `16-readonly-fs`, `20-package-install`.
- Update `tests/redteam-sandbox.sh` and `tests/redteam/harness.sh` to only launch modules in the current set; retire the obsolete ones; document what's covered and what isn't in `tests/redteam/README` (new file) or `tests/README.md`.
- Do not add new security claims during this audit — this is scope reduction, not new coverage.

Exit criteria:
- Every remaining redteam/chaos module runs to completion against a live sbx sandbox.
- `docs/security/security-model.md` accurately reflects what the reduced suite covers.
- Deleted modules are noted in `CHANGELOG.md` so external users who ran them know they went away deliberately.

### 3.6 Close the Deferred Deep-Policy Live Gate

Current state:
- `PLAN-CHECKLIST.md §3.8` accepted as risk: "GitHub API merge/update blocking is accepted risk — live testing requires a running deep-policy proxy which needs sbx networking."
- The deep-policy sidecar lives in `foundry-git-safety` and is documented as the sole GitHub API protection after `github_filter.py` was removed (§3.4 resolution).
- `tests/smoke/test_live_sbx.py` covers git-safety but not the deep-policy path.

Required work:
- Stand up the deep-policy sidecar inside the smoke-test sbx sandbox (or alongside it, depending on how `foundry-git-safety` wires it).
- Add one live smoke test that attempts a blocked GitHub API call (e.g. `PUT /repos/:owner/:repo/pulls/:pr/merge`) from inside the sandbox and asserts the deep-policy sidecar returns the block response.
- Mark the test with the existing `requires_sbx` marker.
- Update `PLAN-CHECKLIST.md §3.8` to flip the remaining `[~]` item and remove the note.

Exit criteria:
- A protected GitHub API path is live-tested end-to-end, not just asserted in unit tests.
- The accepted-risk line in the previous plan becomes a closed item.

### 3.7 Plan the Post-0.20.x Migration Sunset

Current state:
- `foundry_sandbox/migration.py` (544 LOC), `commands/migrate.py` (383 LOC), plus `docs/migration/0.20-to-0.21.md` exist to help 0.20.x users land on 0.21.x.
- No EOL date is declared. Until one is, this code is load-bearing.

Required work:
- Pick a concrete EOL date or release for 0.20.x (e.g. "deleted in 0.23.0" or "deleted 2026-10-01, whichever first").
- Write it into `docs/migration/0.20-to-0.21.md` and `CHANGELOG.md` as a prominent notice.
- File a tracked issue / TODO for the actual deletion work: remove `foundry_sandbox/migration.py`, `commands/migrate.py`, the two `_LAZY_COMMANDS` entries at `cli.py:50-51`, the `test_migration*.py` files, and `docs/migration/0.20-to-0.21.md` itself.
- This workstream **does not delete the code now**; it only sets the schedule.

Exit criteria:
- Users who still have 0.20.x metadata know when the migration path disappears.
- The deletion is ticketed, not ambient debt.

---

## 4. Execution Order

1. **§3.1 (delete legacy artifacts)** and **§3.3 (prune constants/deps)** — do these together in one PR. They are pure removals with no behavior change; doing them first unblocks the rest and gives immediate signal from CI.
2. **§3.2 (consolidate stubs)** — follow-up PR once §3.1's compose-file consumer is gone. Pick Option A or B; A is one line of CI change, B is a small but broader refactor.
3. **§3.4 (sbx wrapper surface)** — small additive PR; can run in parallel with §3.2.
4. **§3.5 (redteam/chaos audit)** — largest unknown; do after §3.1 so the deleted files don't muddy the analysis.
5. **§3.6 (deep-policy live gate)** — do after §3.5 so the smoke harness is in known-good shape.
6. **§3.7 (migration sunset scheduling)** — documentation-only, can be first or last; does not block anything.

The first PR should delete files and fix CI. The rest can be sequenced or parallelized per team bandwidth.

---

## 5. Verification Gate

- `./scripts/ci-local.sh` passes after every PR.
- `./scripts/ci-local.sh --all` passes after §3.1–§3.3 land.
- `tests/smoke/test_live_sbx.py` still passes against a local `sbx` installation.
- After §3.6, the smoke suite includes a live-blocked GitHub API assertion.
- No file deleted in §3.1 or §3.2 is referenced from any `.py`, `.sh`, `.yml`, or `.toml` file outside `CHANGELOG.md`, `docs/adr/`, and `sbx-analysis.md` (historical records).
- `git grep -n "DOCKER_COMPOSE\|UNIFIED_PROXY\|TIMEOUT_DOCKER_" foundry_sandbox/` returns nothing.
- `mypy --strict` and `ruff check` both pass.
