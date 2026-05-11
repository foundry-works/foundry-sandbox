# Remediation Plan

## Goal

Bring the documented Foundry security model back in line with the code, and fix the places where the code currently does not enforce the documented boundary.

The highest-risk gap is GitHub API deep-policy enforcement: direct `gh api` and `curl https://api.github.com/...` traffic reaches GitHub through the sbx HTTPS proxy and does not pass through Foundry's `/deep-policy/github/...` route.

## Priority 0: Decide The Security Boundary

Before changing code, make the intended contract explicit:

- If Foundry is supposed to prevent agents from performing dangerous GitHub API operations, ordinary `gh` and `curl https://api.github.com/...` traffic must be covered.
- If `/deep-policy/...` is only a helper API for explicitly routed requests, the README, security model, and usage docs must say that directly.

Recommendation: treat GitHub API filtering as an enforced boundary. The current docs already describe it that way, and the threat model assumes agents cannot merge PRs or access sensitive repo endpoints just by using another client.

Acceptance criteria:

- A live sandbox test proves `gh api -X PUT repos/OWNER/REPO/pulls/1/merge` receives Foundry's `403 BLOCKED` response.
- A live sandbox test proves direct `curl https://api.github.com/.../merge` cannot bypass Foundry policy.
- Docs describe the actual mechanism and its limits.

## Priority 1: Fix GitHub API Enforcement

Investigate the sbx network and credential path first:

- Identify where `GH_TOKEN=proxy-managed` is resolved into real GitHub authorization.
- Determine whether sbx can disable or scope GitHub credential injection for `api.github.com`.
- Determine whether sbx policy can deny sandbox egress to `api.github.com` while still allowing the host-side Foundry deep-policy server to call GitHub.
- Determine whether sbx supports host/domain rewrite rules. If it does, route `api.github.com` to Foundry deep-policy and preserve method, path, headers, and body.

Preferred enforcement model:

- Do not expose a real GitHub token to the sandbox.
- Deny direct sandbox egress to `api.github.com`.
- Require GitHub REST API traffic to pass through Foundry's deep-policy proxy.
- Keep host-side upstream GitHub calls inside `foundry-git-safety`, where policy and audit logging apply.

Implementation tasks:

- Add a live smoke test that executes `gh api` against a blocked endpoint and expects Foundry `403`.
- Add a live smoke test that executes `curl https://api.github.com/...` against the same blocked endpoint and expects either Foundry `403` or network denial, not a GitHub response.
- Add audit logging that distinguishes direct-denied API attempts from policy-denied deep-policy attempts.
- Update `docs/security/security-model.md`, `README.md`, and `docs/usage/workflows.md` with the final behavior.

Fallback if transparent enforcement is not possible with current sbx:

- Document GitHub API deep-policy as explicit-only.
- Remove or soften claims that normal `gh` traffic is filtered.
- Add a warning that GitHub token scope and sbx credential injection remain the real enforcement layer for normal GitHub API clients.

## Priority 2: Fix `git_safety` Overlay Compilation

The docs say repo/user config can add protected branches and blocked file patterns, but compiled patches are written in a shape that enforcement does not read.

Implementation tasks:

- Align `compile_git_safety()` patch paths with the metadata shape consumed by enforcement.
- Ensure protected branch additions land under `metadata["git"]["protected_branches"]["patterns"]`.
- Ensure blocked file additions are consumed by push validation, either through sandbox metadata or by generating a resolved file-restrictions config.
- Add unit tests for resolved metadata shape.
- Add an integration test that creates a sandbox metadata overlay and verifies the added branch/pattern is enforced.

Acceptance criteria:

- A configured `git_safety.protected_branches.add` value blocks pushes to that branch.
- A configured `git_safety.file_restrictions.blocked_patterns_add` value blocks commits/pushes touching that path.
- Docs and examples match the accepted config shape.

## Priority 3: Fix MCP `${from_host:VAR}` Proxy Semantics

The docs say `${from_host:VAR}` resolves to a proxy URL, but builtin/npm MCP handling only records an sbx secret and does not register a matching proxy service.

Implementation tasks:

- Decide whether `${from_host:VAR}` means "inject a raw secret through sbx" or "create a Foundry proxy-backed service".
- If it means proxy-backed service, register a `user_services` entry for each generated slug.
- If it means raw secret, change the generated env value and docs so MCP servers receive the expected token value.
- Add tests for builtin MCP, npm MCP, and proxy MCP behavior.

Acceptance criteria:

- A builtin MCP using `${from_host:GITHUB_TOKEN}` receives a value that the MCP server can actually use.
- Generated proxy URLs resolve to a registered service and do not 404.
- Docs explain when to use `type: proxy` versus `${from_host:VAR}`.

## Priority 4: Fix Profile And Tooling Bundle Precedence

Docs say user-layer profiles and tooling bundles win over repo-layer definitions, but the current merge order lets repo definitions replace user definitions with the same name.

Implementation tasks:

- Decide whether docs or code should win.
- Recommended: make user definitions win, because the docs frame user config as the trust boundary for host credentials and local tooling.
- Adjust merge order or merge logic for `profiles` and `tooling_bundles`.
- Add tests for builtin, user, and repo precedence.

Acceptance criteria:

- A repo `foundry.yaml` cannot replace a same-named user profile or tooling bundle.
- The plan output shows which layer supplied the selected profile/bundle.
- Docs describe precedence in one place and link to it from examples.

## Priority 5: Wire Or Remove Documented `foundry-git-safety` Config

Some documented config, especially `rate_limits`, is parsed but not wired into runtime construction.

Implementation tasks:

- Pass configured rate-limit values into `RateLimiter`.
- Add unit tests proving configured limits affect request handling.
- Audit the rest of `foundry-git-safety/docs/configuration.md` for parsed-but-unused fields.
- Remove docs for any intentionally unsupported settings.

Acceptance criteria:

- Changing `rate_limits` in config changes observed limiter behavior in tests.
- The configuration docs contain no settings that are silently ignored.

## Priority 6: Make `cast dev --plan` Match Creation

`cast dev --plan` can under-report artifacts because active tooling bundles are expanded during sandbox creation, not during the plan rendering path.

Implementation tasks:

- Expand active profile tooling bundles before rendering the plan.
- Show artifact counts after expansion.
- Add a test where a profile enables a tooling bundle with MCP servers and confirm the plan includes them.

Acceptance criteria:

- `cast dev --plan` and `cast new --plan` preview the same artifact set that creation applies.

## Suggested Work Order

1. Add failing live tests for the GitHub API bypass.
2. Fix or explicitly downgrade the documented GitHub API security claim.
3. Fix `git_safety` overlay compilation and enforcement.
4. Fix MCP `${from_host:VAR}` behavior.
5. Fix precedence semantics for profiles and tooling bundles.
6. Wire documented rate-limit config.
7. Fix plan rendering drift.
8. Do a final docs pass against code and tests.

## Final Verification Checklist

- Unit tests pass.
- `foundry-git-safety` integration tests pass.
- Live sbx smoke test proves direct GitHub API bypass is closed or documented as unsupported.
- Red-team GitHub API module tests ordinary `gh api`, ordinary `curl`, and explicit `/deep-policy` routes.
- README, security model, configuration docs, and workflow docs describe the same behavior.
