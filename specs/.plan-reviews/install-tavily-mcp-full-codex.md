I’m glad you shared this plan for review — it’s a solid and concrete implementation outline, and I’m happy to help refine it.

# Review Summary

## Critical Blockers
Issues that MUST be fixed before this becomes a spec.

- **[Completeness]** Missing validation of existing config formats and locations in this repo
  - **Description:** The plan assumes the exact config file locations and JSON/TOML shapes for each tool, but it doesn’t confirm how this repo currently writes or merges those files (for example, how `lib/container_config.sh` currently structures JSON or whether `~/.claude/.claude.json` is the authoritative path in this environment).
  - **Impact:** If the current repo uses different schemas or merge logic, the new entries may be overwritten, ignored, or cause config corruption.
  - **Fix:** Add a pre-implementation verification step to inspect the existing config generation code paths for each tool and confirm the exact schema and merge strategy used in this repo. Capture any deviations as plan updates.

- **[Risk]** Global npm install in Dockerfile may not be aligned with build constraints
  - **Description:** The plan assumes `npm install -g tavily-mcp` is viable in the Docker build, but does not address whether the base image has Node/npm versions compatible with `tavily-mcp`, or whether image builds allow outbound npm access.
  - **Impact:** Builds can fail or create inconsistent behavior if the npm install step is blocked or incompatible.
  - **Fix:** Add a validation step to confirm Node/npm versions and whether the build pipeline allows outbound npm access, plus fallback strategy (pin version, use npm cache, or bake in a tarball).

## Major Suggestions
Significant improvements to strengthen the plan.

- **[Architecture]** Consider a shared MCP registration helper to avoid drift
  - **Description:** Each tool configuration is updated independently, which risks schema drift and inconsistent defaults over time.
  - **Impact:** Future MCP additions may have to re-implement similar logic, increasing maintenance cost and likelihood of mismatch.
  - **Fix:** Introduce or extend a shared helper in `lib/container_config.sh` that accepts a “server spec” and writes to each tool’s config in one place.

- **[Sequencing]** Verify config injection order relative to other setup steps
  - **Description:** The plan adds a post-merge patch for OpenCode, but doesn’t specify where relative to other config syncs or whether those syncs will overwrite the patch later.
  - **Impact:** The Tavily entry may be lost during subsequent merges, producing a “works once” or flaky setup.
  - **Fix:** Explicitly place the patch step after all OpenCode sync/merge steps, and ensure idempotence (running setup twice should preserve Tavily config).

- **[Feasibility]** Missing check for permissions model differences across tools
  - **Description:** Auto-approval is added only for Claude Code permissions; other tools may also gate MCP use.
  - **Impact:** Tavily could still prompt or fail in tools other than Claude Code even if configured correctly.
  - **Fix:** Add an explicit check to confirm whether OpenCode/Codex CLI/Gemini CLI require allowlist entries or permissions flags, and document how to configure them if needed.

## Minor Suggestions
Smaller refinements.

- **[Clarity]** Clarify whether `tavily-mcp` should be pinned
  - **Description:** The plan references “latest: 0.1.3” but doesn’t specify pinning versus floating to latest.
  - **Fix:** Add a clear decision: either pin to a tested version (e.g., `tavily-mcp@0.1.3`) or explicitly allow latest, with rationale.

- **[Completeness]** Add rollback guidance
  - **Description:** No plan for reverting config changes if issues arise.
  - **Fix:** Add a short “rollback” section (remove config blocks, remove npm package, rebuild image).

- **[Risk]** Ensure the binary path is consistent across tools
  - **Description:** The plan assumes `tavily-mcp` is on PATH for all tools.
  - **Fix:** Add a validation that PATH is consistent in all tool run contexts; if not, use absolute path in config.

## Questions
Clarifications needed before proceeding.

- **[Clarity]** Which config file is authoritative for Claude Code in this environment?
  - **Context:** The plan writes to both `~/.claude.json` and `~/.claude/.claude.json`.
  - **Needed:** Confirm whether both are required or if one is redundant; otherwise, risk of conflicting configs.

- **[Architecture]** How are JSON/TOML merges handled in `lib/container_config.sh`?
  - **Context:** The plan injects entries but does not describe conflict resolution or idempotence.
  - **Needed:** Confirm whether there is a merge utility or direct overwrite; share the expected merge behavior.

- **[Sequencing]** What other MCP servers are configured today, and where?
  - **Context:** The plan mentions foundry-mcp already configured but does not detail current entries.
  - **Needed:** A quick inventory of existing `mcpServers` entries to ensure Tavily doesn’t clash with naming or schema.

- **[Feasibility]** Does the build environment allow outbound npm registry access?
  - **Context:** The plan relies on `npm install -g tavily-mcp` during build.
  - **Needed:** Confirm network policy or provide offline installation fallback.

## Praise
What the plan does well.

- **[Completeness]** Clear scope boundaries and explicit out-of-scope items
  - **Why:** This reduces risk of hidden work and helps keep the spec tight.

- **[Sequencing]** Phased breakdown is logical and tool-by-tool
  - **Why:** Makes the work approachable and testable in increments.

- **[Clarity]** Concrete config snippets for each tool
  - **Why:** Minimizes ambiguity and makes implementation straightforward.

- **[Risk]** Risks and mitigations section is present and relevant
  - **Why:** Shows forethought and helps reviewers focus on key failure points.

---

If you want, I can help refine the plan with these adjustments and turn it into a spec-ready version.