# foundry-sandbox — Phase 9 Checklist: Documentation Alignment

**Last updated:** 2026-04-21
**Companion to:** `PLAN.md`

Legend: `[ ]` todo, `[x]` done, `[~]` partial / accepted risk

---

## 2.1 Rewrite Root README.md

- [x] Replace architecture diagram with sbx-based flow
- [x] Update security layers table for sbx architecture
- [x] Remove references to `--mount`, volume mounts, `--network`
- [x] Update prerequisites: Docker sbx, remove tmux
- [x] Update limitations section
- [x] Update `pyproject.toml` description from "Docker-based" to "microVM-based"
- [x] Update CLAUDE.md: remove `unified-proxy/`, update `stubs/` description

## 2.2 Update docs/usage/workflows.md

- [x] Remove "Using Custom Mounts" section
- [x] Remove "Using File Copies" section
- [x] Remove "Installing SSH-Based Plugins" section
- [x] Remove "Network Isolation Workflow" section
- [x] Remove "Advanced Plugin Configuration" section
- [x] Update "Private Repositories" — remove SSH/mount references
- [x] Update "Tips and Best Practices" — remove `cast prune`, `SANDBOX_DEBUG`, `SANDBOX_VERBOSE`
- [x] Verify remaining sections use current commands/flags

## 2.3 Add Missing Commands to docs/usage/commands.md

- [x] Add `cast diagnose` documentation
- [x] Add `cast watchdog` documentation
- [x] Add `cast migrate-to-sbx` documentation
- [x] Add `cast migrate-from-sbx` documentation
- [x] Verify existing command docs accurate (no removed flags) — removed `--with-ide`/`--ide-only`/`--no-ide` from new and attach

## 2.4 Update docs/README.md (Index)

- [x] Add sbx-compatibility.md to main table
- [x] Add migration guide to main table
- [x] Add wrapper-integrity.md to security table
- [x] Add audit-5.6.md to security table
- [x] Add ADR entries 009–013
- [x] Verify all links resolve

## 2.5 Update docs/getting-started.md

- [x] Add link to sbx-compatibility.md in prerequisites
- [x] Verify install steps are current

## 2.6 Version CHANGELOG.md

- [x] Rename `[Unreleased]` to `[0.21.0] - 2026-04-21`
- [x] Add Phase 8 entries (HMAC relocation, observability, CI)
- [x] Add link entries for 0.16.0–0.20.15
- [x] Fix `[Unreleased]` link to `v0.21.0...HEAD`
- [x] Verify all version links resolve

## 2.7 Update docs/development/contributing.md

- [x] Add CI pipeline section (test.yml jobs, foundry-git-safety test tiers)
- [x] Reference ci-local.sh
- [x] Document pytest isolation rule

---

## Verification Gate

- [x] `grep -r "unified-proxy\|Squid\|mitmproxy\|docker.compose\|--mount\|--network=\|--with-ssh\|cast prune\|sudo network-mode" docs/ README.md` → zero hits in user-facing docs (ADRs and migration guide are historical records)
- [x] `grep -r "\.foundry/hmac-secret" docs/ stubs/ foundry_sandbox/` → zero hits
- [x] All CLI commands documented in commands.md
- [x] docs/README.md links to every doc file
- [x] CHANGELOG.md has clean `[0.21.0]` section
- [x] pyproject.toml description says "microVM-based"

---

## Phase 8 Carry-Over

- [ ] Verify CI passes on a test push

## Pre-existing Issues (not from Phase 9)

- [~] 2 chaos tests in foundry-git-safety expect 422 but get 400 (missing repo_root metadata) — test/code mismatch from earlier change
- [x] 2 mypy errors in git_safety.py — fixed (dict type params + import-untyped)
