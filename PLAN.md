# foundry-sandbox — Phase 9: Documentation Alignment

**Last updated:** 2026-04-21
**Branch:** `sbx`
**Scope:** Align all documentation with the sbx migration, close outdated references, add missing command docs, and prepare the CHANGELOG for the 0.21.0 release.
**Prerequisite:** Phase 8 complete (all code items done; CI verification pending a test push).

---

## 1. Objective

Every doc page should accurately describe the current sbx-based architecture. No references to removed flags (`--mount`, `--network`, `--with-ssh`), removed commands (`cast prune`), or removed infrastructure (unified-proxy, Squid, mitmproxy, Docker compose) should remain in user-facing docs. The CHANGELOG should be versioned for release.

---

## 2. Workstreams

### 2.1 Rewrite root README.md

Current state:
- Still describes the docker-compose/unified-proxy architecture with a diagram showing Squid and mitmproxy.
- References removed features: "Read-only filesystem", "Network allowlists" with Squid, "Volume mounts".
- `pyproject.toml` description says "Docker-based sandbox environment".

Required work:
- Replace the architecture diagram with an sbx-based flow: sandbox → sbx proxy → foundry-git-safety → external APIs.
- Update the security layers table: microVM isolation, credential injection via sbx, git safety via foundry-git-safety, network policy via sbx.
- Remove references to `--mount`, `--network`, volume mounts.
- Update prerequisites: Docker sbx instead of Docker 20.10+, remove tmux requirement.
- Update limitations: replace "Requires Docker" with "Requires Docker sbx".
- Update `pyproject.toml` description from "Docker-based" to "microVM-based".
- Update CLAUDE.md: remove `unified-proxy/` reference, update `stubs/` description.

Exit criteria:
- README.md accurately describes sbx architecture with no docker-compose/unified-proxy references.
- `pyproject.toml` description is current.
- CLAUDE.md reflects actual directory structure.

### 2.2 Update docs/usage/workflows.md

Current state:
- "Using Custom Mounts" section references `--mount` flag (removed).
- "Installing SSH-Based Plugins" references `--with-ssh` (removed).
- "Network Isolation Workflow" references `--network=limited`, `--network=none`, `--network=host-only`, `sudo network-mode`, `SANDBOX_ALLOWED_DOMAINS` (all removed).
- "Tips and Best Practices" references `cast prune` (removed).
- "Private Repositories" section references `--with-ssh` and `--mount` for SSH keys.

Required work:
- Remove the "Using Custom Mounts" section entirely.
- Remove "Using File Copies" section (file copy is no longer a feature).
- Remove "Installing SSH-Based Plugins" section.
- Remove the "Network Isolation Workflow" section — network is now handled by sbx policy, not per-sandbox flags.
- Remove "Advanced Plugin Configuration" section (OpenCode plugins/SANDBOX_OPENCODE_* env vars are docker-compose-era).
- Update "Private Repositories" to remove SSH and mount references; credential injection is now via sbx.
- Update "Tips and Best Practices" to remove `cast prune` and `SANDBOX_DEBUG`/`SANDBOX_VERBOSE` references.
- Keep and lightly update the core workflow sections: Feature Development, PR Review, Multiple Sandboxes, Quick Iterations, Debugging Production Issues, Using Different AI Tools.

Exit criteria:
- No references to `--mount`, `--copy`, `--with-ssh`, `--network`, `sudo network-mode`, `SANDBOX_ALLOWED_DOMAINS`, `SANDBOX_DEBUG`, `SANDBOX_VERBOSE`, `cast prune`.
- All remaining workflow examples use current commands and flags.

### 2.3 Add missing commands to docs/usage/commands.md

Current state:
- `cast diagnose`, `cast watchdog`, `cast migrate-to-sbx`, `cast migrate-from-sbx` have command modules but are not documented in commands.md.

Required work:
- Add documentation for `cast diagnose` (sbx diagnostics, git safety health checks).
- Add documentation for `cast watchdog` (HMAC rotation, wrapper integrity monitoring).
- Add documentation for `cast migrate-to-sbx` and `cast migrate-from-sbx` (cross-reference migration guide).
- Verify existing command docs are still accurate (no removed flags shown).

Exit criteria:
- All CLI commands with command modules are documented in commands.md.

### 2.4 Update docs/README.md (index)

Current state:
- Does not link to `docs/sbx-compatibility.md` or `docs/migration/`.
- Does not link to `docs/security/wrapper-integrity.md` or `docs/security/audit-5.6.md`.
- ADR table is missing entries for ADR-009 through ADR-013.

Required work:
- Add sbx-compatibility and migration guide to the main table.
- Add wrapper-integrity and audit-5.6 to the security table.
- Add missing ADR entries (009–013).
- Verify all links resolve.

Exit criteria:
- Every doc file under `docs/` is reachable from the index.

### 2.5 Update docs/getting-started.md

Current state:
- Prerequisites section lists sbx correctly but doesn't mention foundry-git-safety version requirement.
- No mention of sbx version compatibility (documented separately in sbx-compatibility.md but not linked).

Required work:
- Add a link to sbx-compatibility.md in the prerequisites section.
- Verify the install steps are current (the guide looks mostly correct already).

Exit criteria:
- Prerequisites section links to sbx compatibility matrix.

### 2.6 Version CHANGELOG.md for 0.21.0 release

Current state:
- Massive `[Unreleased]` section contains the entire sbx migration.
- Link reference at bottom says `v0.15.9...HEAD` instead of `v0.20.15...HEAD`.
- Missing link entries for 0.16.0 through 0.20.15 versions.

Required work:
- Rename `[Unreleased]` to `[0.21.0] - 2026-04-XX` (date TBD).
- Add link entries for all missing versions (0.16.0 through 0.20.15).
- Fix the `[Unreleased]` link to compare from `v0.20.15`.
- Add any Phase 8 entries (HMAC secret relocation, observability plumbing, CI pipeline).

Exit criteria:
- CHANGELOG has a clean `[0.21.0]` header with all link references intact.
- All version links resolve correctly.

### 2.7 Update docs/development/contributing.md

Current state:
- Does not reference the CI workflows, foundry-git-safety test suites, or `scripts/ci-local.sh`.

Required work:
- Add a section on CI: describe the test.yml jobs, the foundry-git-safety test tiers, and the ci-local.sh script.
- Reference the pytest isolation rule (root package and foundry-git-safety must not be run in the same pytest invocation).

Exit criteria:
- Contributing guide documents the CI pipeline and how to run tests locally.

---

## 3. Execution Order

1. §2.1 — Rewrite root README.md + pyproject.toml + CLAUDE.md (highest visibility)
2. §2.2 — Update workflows.md (remove outdated sections)
3. §2.3 — Add missing commands to commands.md
4. §2.4 — Update docs/README.md index
5. §2.5 — Update getting-started.md
6. §2.6 — Version CHANGELOG.md
7. §2.7 — Update contributing.md

---

## 4. Verification Gate

Before calling this phase complete:

- [x] `grep -r "unified-proxy\|Squid\|mitmproxy\|docker.compose\|--mount\|--network=\|--with-ssh\|cast prune\|sudo network-mode" docs/ README.md` → zero hits in user-facing docs (ADRs and migration guide are historical records)
- [x] `grep -r "\.foundry/hmac-secret" docs/ stubs/ foundry_sandbox/` → zero hits
- [x] All CLI commands with command modules are documented in commands.md
- [x] docs/README.md links to every doc file under `docs/`
- [x] CHANGELOG.md has a clean `[0.21.0]` section with correct links
- [x] pyproject.toml description says "microVM-based" (not "Docker-based")
