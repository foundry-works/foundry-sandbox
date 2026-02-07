# Fix Shared Bare Repo Issues

## Context

Multiple sandboxes sharing the same git repository use a single bare repo at `~/.sandboxes/repos/{host}/{repo}.git`, each with its own worktree. This creates correctness bugs, cross-sandbox information leaks, and maintenance issues:

1. `repositoryformatversion=0` with `extensions.worktreeConfig=true` violates git spec
2. Docker Desktop VirtioFS caches stale inodes after `git config` atomic renames
3. `core.bare=true` (shared) conflicts with `core.worktree` (per-worktree) when extensions become visible
4. Any sandbox can read/diff/cherry-pick other sandboxes' branches
5. Any sandbox can delete other sandboxes' stale branches
6. `git branch -a` lists every sandbox's branch (namespace pollution)
7. Concurrent `git fetch` from multiple proxies causes lock contention
8. Destroyed sandboxes leave branches accumulating in the bare repo

## Phases

| Phase | Summary | Link |
|-------|---------|------|
| 1 | Correctness Bugs | [phase-1-correctness.md](phase-1-correctness.md) |
| 2 | Pass Sandbox Branch to Proxy Metadata | [phase-2-metadata.md](phase-2-metadata.md) |
| 3 | Cross-Sandbox Branch Isolation | [phase-3-isolation.md](phase-3-isolation.md) |
| 4 | Server-Side Fetch Locking | [phase-4-fetch-locking.md](phase-4-fetch-locking.md) |
| 5 | Branch Cleanup on Destroy/Prune | [phase-5-cleanup.md](phase-5-cleanup.md) |
| 6 | Automated Tests | [phase-6-tests.md](phase-6-tests.md) |
| 7 | Hardening and Leak Closure | [phase-7-hardening.md](phase-7-hardening.md) |

## Files Modified Summary

| File | Phases | Summary |
|------|--------|---------|
| `lib/git_worktree.sh` | 1A, 5A | Bump repoformatversion; add `cleanup_sandbox_branch()` |
| `lib/container_config.sh` | 1B | VirtioFS cache refresh + defensive extensions set |
| `commands/new.sh` | 2A | Add `sandbox_branch` to proxy metadata |
| `commands/start.sh` | 2A, 2B | Add `sandbox_branch` to proxy metadata; fail-closed startup |
| `unified-proxy/git_operations.py` | 3A | Subcommand helpers, rev suffix stripping, ref allowlist, isolation validator (checkout/switch, fetch/pull, worktree, bisect, reflog, notes, implicit-all flags) |
| | 3B | Wire `validate_branch_isolation()` into `execute_git()` |
| | 3C | Output filters: branch listing, ref-enum, log decorations (SHA-anchored + custom `%d`/`%D`), `--source` redaction |
| | 4A | Bare repo resolver + fetch lock context manager |
| | 7A | SHA reachability gate (`merge-base --is-ancestor`) |
| | 7B | Reflog, `for-each-ref --format`, `--source`, notes leak closure |
| | 7C | Push-protection bare-repo resolution fix |
| `unified-proxy/git_api.py` | 2A | Legacy sandbox warning when `sandbox_branch` missing |
| `commands/destroy.sh` | 5B | Load metadata + branch cleanup |
| `commands/prune.sh` | 5C | Load metadata + branch cleanup |
| `unified-proxy/tests/unit/test_branch_isolation.py` | 6B-6D | Unit tests for isolation logic |
| `tests/integration/test_branch_isolation_flow.py` | 6E | End-to-end branch isolation and fetch-lock tests |
| `tests/security/test_git_branch_isolation.sh` | 6E, 7 | Security regression tests for leak channels and SHA enforcement |

## Accepted Risks and Limitations

1. **Host-level trust boundary remains:** `docker exec`, host root access, or direct host filesystem access can bypass proxy checks. This remains out of scope and is consistent with the documented threat model.
2. **Metadata-loss cleanup gap remains:** If both sandbox config metadata and branch identity are missing, automatic branch cleanup still cannot safely infer deletion targets. Manual cleanup remains the fallback.
3. **All paths require `--` separator:** File path arguments are not auto-detected — users must use `--` to separate refs from paths (e.g., `git log branch -- path`). This is git-standard behavior and eliminates the false-allow risk of pathspec heuristics on branch names like `src/exploit.py` or `feature/component.tsx`.
4. **SHA reachability checks add cost:** Phase 7 introduces extra git plumbing calls for SHA arguments. Mitigate with per-request memoization and targeted command coverage.
5. **Operator override risk:** Break-glass fetch override (`FOUNDRY_ALLOW_UNLOCKED_FETCH`) weakens lock guarantees when enabled. It must be disabled by default and monitored with audit alerts.
6. **Tag policy remains permissive:** Tags continue to be globally readable unless future policy chooses to isolate tag namespaces as well.
7. **Fetch no-refspec behavior remains allowed:** `git fetch origin` is still allowed for compatibility; isolation depends on ref validation and output filtering rather than banning default fetch.
8. **TOCTOU in branch cleanup remains theoretically possible:** the check-then-delete window in cleanup is still not atomic, though practical impact is low.
9. **Stash refs are per-worktree (safe):** Since git 2.17+, `refs/stash` is per-worktree, so `git stash list` from sandbox A cannot see sandbox B's stashes. No isolation handling needed. If a shared bare repo predates 2.17 worktree stash support, stashes would be shared — but this is an edge case covered by the minimum git version requirement.

## Verification

See each phase document for phase-specific verification steps, plus the comprehensive checklist in [phase-6-tests.md](phase-6-tests.md) and [phase-7-hardening.md](phase-7-hardening.md).
