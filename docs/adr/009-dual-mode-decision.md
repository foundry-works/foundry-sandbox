# ADR-009: No Dual-Mode Operation During Migration

## Status

Accepted

Date: 2026-04-20

## Context

The migration from docker-compose (0.20.x) to `sbx` (0.21.x) backend raises the question: should `cast` support running both backends simultaneously during the transition period?

This would mean maintaining two complete backend implementations in the codebase:
- Docker-compose: proxy infrastructure, container management, credential injection
- `sbx`: microVM lifecycle, network policy, `sbx` secret storage

## Decision

We will **not** support dual-mode operation. Users must fully migrate to the `sbx` backend or remain on 0.20.x.

## Rationale

1. **The old backend was deleted** — ~67k lines removed. Re-introducing it as a parallel path would be a regression that reverts the code reduction.

2. **Maintenance burden** — Dual-mode requires every command to branch on backend type, doubling the testing surface and the bug surface.

3. **foundry-git-safety is backend-agnostic** — The standalone git safety package works with any backend. The orchestration layer (`cast` commands) is where the coupling lives.

4. **Migration is one-time** — The `cast migrate-to-sbx` command with snapshot/rollback provides safety without requiring runtime dual-mode.

5. **Users who cannot migrate should pin** — `pip install foundry-sandbox==0.20.15` remains available. There is no deadline to migrate.

## Consequences

- Users cannot incrementally migrate sandboxes — they must migrate all at once.
- The snapshot/rollback mechanism must be reliable, as it is the sole safety net.
- Future releases will not maintain backward compatibility with docker-compose metadata.
- Users on 0.20.x can continue using that version indefinitely.
