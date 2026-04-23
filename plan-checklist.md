# Local Dev Ergonomics Checklist

## Phase 1: `cast dev`

- [ ] Add a new `cast dev` command.
- [ ] Default repo resolution to the current checkout when possible.
- [ ] Add `--profile` selection.
- [ ] Add explicit reuse behavior for repo/profile/branch.
- [ ] Add `--fresh` to force a new sandbox.
- [ ] Reuse existing `cast new` creation logic instead of duplicating it.
- [ ] Reuse existing `cast up` behavior for start, IDE launch, and attach.
- [ ] Persist the selected profile in sandbox metadata.
- [ ] Print clear output that explains whether the sandbox was reused or created.

## Phase 2: Profile Schema

- [x] Add profile models to the config layer.
- [x] Decide where profiles are allowed: user config only, or user config plus repo config with safe merge rules.
- [x] Define merge and precedence behavior for profiles.
- [x] Add validation for unknown profile names.
- [x] Add plan rendering support so `--plan` can show the selected profile.
- [x] Document the profile schema with examples.

## Phase 3: Package Bootstrap

- [ ] Replace the narrow `--pip-requirements` mental model with typed package bootstrap.
- [ ] Add support for `pip` bootstrap.
- [ ] Evaluate whether to add `uv` bootstrap.
- [ ] Evaluate whether to add `npm` bootstrap outside MCP-only flows.
- [ ] Evaluate whether to add `apt` bootstrap.
- [ ] Decide whether a generic `bootstrap.commands` escape hatch is needed.
- [ ] Gate higher-risk bootstrap paths explicitly.
- [ ] Persist package bootstrap configuration in metadata and state.
- [ ] Make package bootstrap visible in dry-run plan output.

## Phase 4: Tooling Bundles

- [ ] Design a bundle abstraction for reusable tooling sets.
- [ ] Allow bundles to expand into Claude skills.
- [ ] Allow bundles to expand into Claude commands.
- [ ] Allow bundles to expand into MCP servers.
- [ ] Allow bundles to declare package prerequisites when needed.
- [ ] Define conflict handling when multiple bundles set overlapping config.
- [ ] Keep generated `.claude` and `.mcp.json` files as compiled artifacts, not source of truth.
- [ ] Document how bundles map to the current Claude and MCP config surfaces.

## Phase 5: Template Caching

- [ ] Add a managed-template strategy for profile-backed environments.
- [ ] Define a stable cache key for template reuse.
- [ ] Invalidate cached templates when profile inputs change.
- [ ] Track template provenance in sandbox metadata.
- [ ] Provide a way to rebuild or refresh cached templates.
- [ ] Keep secrets, git safety, and other runtime-sensitive state out of templates.

## Safety And Policy

- [ ] Preserve current git-safety provisioning as a per-sandbox step.
- [ ] Preserve proxy-backed credential injection.
- [ ] Preserve user-level veto behavior for third-party tooling installs.
- [ ] Ensure repo config cannot silently weaken user restrictions.
- [ ] Add tests that confirm templates do not capture raw secrets.

## Testing

- [ ] Add unit tests for `cast dev` create-or-reuse behavior.
- [ ] Add unit tests for profile selection and precedence.
- [ ] Add unit tests for new package bootstrap config parsing.
- [ ] Add unit tests for bundle expansion.
- [ ] Add unit tests for template cache hit and miss behavior.
- [ ] Add smoke coverage for a typical local-dev flow.
- [ ] Extend red-team coverage for new package/plugin installation paths.

## Docs

- [ ] Update getting-started docs to recommend the new default workflow.
- [ ] Update command reference with `cast dev`.
- [ ] Update configuration docs with profile, bundle, and package bootstrap sections.
- [ ] Update workflow docs to show create-or-reuse local dev flows.
- [ ] Add examples for Claude-focused and Python-focused profiles.

## Implementation Order

- [ ] Ship `cast dev` first.
- [ ] Ship declarative profiles second.
- [ ] Ship expanded package bootstrap third.
- [ ] Ship tooling bundles fourth.
- [ ] Ship managed template caching last.
