# Review Summary

## Critical Blockers
Issues that MUST be fixed before this becomes a spec.

- **[Feasibility]** Package name and command verification needed
  - **Description:** The plan assumes the npm package is `tavily-mcp` and the binary command is also `tavily-mcp`, but this hasn't been verified against the actual npm registry. The Tavily docs reference the package but the actual installed binary name may differ (e.g., could be `@tavily/mcp`, `tavily-mcp-server`, or similar).
  - **Impact:** If the package name or command is wrong, the entire implementation will fail. Docker build may succeed but configs will point to non-existent binaries.
  - **Fix:** Before creating the spec, verify: (1) Run `npm view tavily-mcp` to confirm package exists and check the `bin` field for actual command name, (2) Or check the package.json in the tavily-mcp repo to confirm the binary name.

## Major Suggestions
Significant improvements to strengthen the plan.

- **[Completeness]** Missing error handling for MCP server startup failures
  - **Description:** The plan configures all four tools to use tavily-mcp but doesn't address what happens if tavily-mcp fails to start (e.g., missing API key, network issues). Currently, if `TAVILY_API_KEY` is not set, the MCP server may fail silently or noisily depending on implementation.
  - **Impact:** Users could experience confusing errors when tavily-mcp tools are unavailable without clear feedback.
  - **Fix:** Add a task to Phase 2 or create a new phase to document expected behavior when TAVILY_API_KEY is missing/invalid. Consider whether tavily-mcp should only be configured when the API key is present.

- **[Architecture]** Conditional configuration based on API key availability
  - **Description:** The plan unconditionally adds tavily-mcp to all tool configs. If a user doesn't have a TAVILY_API_KEY, they'll have a broken MCP server configured that may produce errors.
  - **Impact:** Users without Tavily API keys get unnecessary error noise; tools may behave unexpectedly.
  - **Fix:** Consider adding logic to only configure tavily-mcp when `TAVILY_API_KEY` is set, similar to how other optional features might be gated. At minimum, document this as an accepted trade-off.

- **[Risk]** OpenCode array format assumption unverified
  - **Description:** The plan notes OpenCode uses `"command": ["tavily-mcp"]` (array format) vs other tools using `"command": "tavily-mcp"` (string). This is called out in risks but the source of this requirement isn't cited.
  - **Impact:** If the array format assumption is wrong, OpenCode integration will fail.
  - **Fix:** Add a reference to OpenCode documentation confirming the array format requirement, or add a verification step to check existing foundry-mcp config format in OpenCode.

## Minor Suggestions
Smaller refinements.

- **[Completeness]** Add rollback guidance
  - **Description:** If something goes wrong during implementation, there's no documented way to revert changes.
  - **Fix:** Add a brief "Rollback" section noting: (1) Remove tavily-mcp from npm install line in Dockerfile, (2) Revert container_config.sh changes, (3) Rebuild image.

- **[Clarity]** Phase 2 task 2 is confusing
  - **Description:** Task 2 mentions updating `ensure_claude_foundry_mcp()` to handle registration in "both `~/.claude.json` and `~/.claude/.claude.json`" but Task 1 already mentions updating `ensure_foundry_mcp_config()`. The relationship between these functions isn't clear.
  - **Fix:** Clarify which function handles which config file, or consolidate into a single task with sub-steps explaining the two config file locations.

- **[Sequencing]** Phase 6 could be parallelized with earlier phases
  - **Description:** Phase 6 verification is listed as sequential after all configuration phases, but partial verification could happen earlier (e.g., verify Claude Code works before moving to OpenCode).
  - **Fix:** Consider adding inline verification to each phase and making Phase 6 a final integration smoke test, or note that incremental testing is optional but recommended.

- **[Clarity]** Permissions pattern scope unclear
  - **Description:** The pattern `"mcp__tavily-mcp__*"` is added to FOUNDRY_ALLOW, but the specific tools this enables (search, extract, etc.) aren't listed.
  - **Fix:** Add a brief note listing the known Tavily MCP tools this pattern will match (e.g., `tavily_search`, `tavily_extract` based on the docs).

## Questions
Clarifications needed before proceeding.

- **[Feasibility]** What happens when tavily-mcp is invoked without a valid API key?
  - **Context:** Understanding failure modes helps set user expectations and informs whether conditional configuration is necessary.
  - **Needed:** Test or document what error message/behavior occurs when TAVILY_API_KEY is missing or invalid.

- **[Architecture]** Should tavily-mcp environment variable be explicitly passed in MCP config?
  - **Context:** Some MCP servers require explicit `env` configuration in the server block (e.g., `"env": {"TAVILY_API_KEY": "..."}`) rather than inheriting from the shell environment.
  - **Needed:** Verify whether tavily-mcp inherits environment variables automatically or needs explicit env config. Check the Tavily MCP docs for the recommended configuration format.

- **[Completeness]** Are there any tavily-mcp tool-specific permissions needed beyond the wildcard?
  - **Context:** The plan uses `mcp__tavily-mcp__*` but some tools may require read/write permissions or network access that need separate approval.
  - **Needed:** Review tavily-mcp tool definitions to ensure the wildcard pattern is sufficient.

## Praise
What the plan does well.

- **[Clarity]** Excellent configuration format documentation
  - **Why:** Each tool's exact JSON/TOML format is specified with code blocks, making implementation unambiguous. The comparison table in Background is particularly helpful for understanding the landscape.

- **[Completeness]** Comprehensive verification commands
  - **Why:** Phase 6 provides copy-pasteable verification commands for every tool, making it easy to confirm success. Each earlier phase also has specific verification criteria.

- **[Architecture]** Smart reuse of existing patterns
  - **Why:** The plan correctly identifies that foundry-mcp is already configured and follows the same patterns, reducing implementation risk and maintaining consistency.

- **[Risk]** Proactive risk identification
  - **Why:** The risks table identifies real concerns (package name, config formats, OpenCode array format) with appropriate mitigations. This shows mature planning.

- **[Sequencing]** Logical phase progression
  - **Why:** Starting with package installation, then tool-by-tool configuration, ending with integration verification follows a sensible dependency order.