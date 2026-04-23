# Security Model

Foundry Sandbox is a safety boundary for AI-assisted development. Its goal is to reduce accidental damage, over-broad automation, and ordinary supply-chain risk while an agent works inside an `sbx` microVM.

This is not a hostile-tenant or hostile-host design. If the host is compromised, `sbx` is bypassed, or a trusted human intentionally disables the controls, the guarantees below do not hold.

## Trust Boundaries

```text
AI agent / build scripts (untrusted)
        |
        v
sbx microVM
  - isolated kernel
  - network policy
  - no real credentials
  - git wrapper at /usr/local/bin/git
        |
        +--> sbx proxy on host
        |      - injects credentials into allowed outbound requests
        |
        +--> foundry-git-safety on host
               - authenticates git wrapper requests
               - enforces branch and push policy
```

## What This Protects

| Asset | Main control |
|-------|--------------|
| Host filesystem | MicroVM isolation |
| Real API credentials | sbx host-side credential injection |
| Protected git refs | `foundry-git-safety` |
| Cross-sandbox branch visibility | branch isolation in `foundry-git-safety` |

## Core Controls

### MicroVM Isolation

Each sandbox runs in an `sbx` microVM with its own kernel. Dangerous commands inside the sandbox can damage the sandbox worktree, but they should not write to the host filesystem outside the sandbox boundary.

What this gives you:

- separate kernel boundary instead of a plain shared-kernel container
- ephemeral sandbox state
- a narrow host/sandbox sync boundary around the workspace

What it does not give you:

- protection against an `sbx` or kernel escape
- protection against a malicious host operator

`cast diagnose` checks that sandbox and host kernels differ and warns if the sandbox appears to have fallen back to a non-isolated mode.

### Network Policy

Sandbox traffic goes through the `sbx` proxy. The default `balanced` policy allows common development destinations such as GitHub and supported AI APIs and blocks arbitrary outbound access.

Important constraints:

- sandboxes do not get unrestricted direct egress
- sandboxes cannot talk to arbitrary host ports
- the git-safety server is reached through the proxy path, not as a general host-side service

If you need to inspect or change policy behavior, use `sbx policy status` and related `sbx policy` commands.

### Credential Handling

Real credentials stay on the host. Foundry pushes them into `sbx` host-side secrets and the proxy injects them into outbound requests when needed.

In normal operation:

- `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and similar secrets are not present as real values inside the sandbox
- GitHub auth is represented by a placeholder such as `GH_TOKEN=proxy-managed`
- user-defined services can expose proxy URLs instead of raw secrets, with requests authenticated by sandbox HMAC headers

This protects against simple credential scraping by agent code, shell commands, or dependencies running inside the sandbox. It does not protect against abuse of already-allowed outbound requests.

### Branch Isolation

`foundry-git-safety` limits each sandbox to its own branch plus a small allowlist of well-known branches and tags.

The current implementation uses:

- deny-by-default ref validation
- SHA reachability checks for raw commit arguments
- output filtering for ref-listing commands
- fail-closed behavior when sandbox branch metadata is missing

This is the control that prevents one sandbox from casually checking out or enumerating another sandbox's branch.

### Git Safety

Git inside the sandbox is routed through `foundry_sandbox/assets/git-wrapper.sh`, installed as `/usr/local/bin/git`. The wrapper authenticates to `foundry-git-safety`, which applies policy before running host-side git operations.

The current policy blocks:

- direct pushes to protected branches such as `main`, `master`, `release/*`, and `production`
- force pushes to protected refs
- branch and tag deletion pushes
- PR merge endpoints
- pushes that modify blocked file patterns such as `.github/workflows/`

It also rate-limits requests and rejects malformed or unauthenticated wrapper traffic.

## Important Non-Goals and Accepted Risks

| Case | Status |
|------|--------|
| Trusted human intentionally disables controls | Out of scope |
| Host compromise | Out of scope |
| `sbx` / kernel escape | Out of scope |
| Data sent to already-allowed destinations | Not prevented by the sandbox |
| Wrapper removed from inside the sandbox | Accepted risk |
| Third-party npm MCP servers | Controlled by `allow_third_party_mcp` gate. When enabled, npm packages run inside the sandbox with full agent privileges. The gate is ANDed across layers — a user-level `false` cannot be overridden by a repo config. |

The wrapper-removal case matters most in practice: a root-capable process in the sandbox can remove `/usr/local/bin/git` and fall back to `/usr/bin/git`. Foundry mitigates that with reinjection and watchdog tooling, but it is not a hard security boundary.

If wrapper reinjection fails during `cast start`, Foundry leaves the sandbox
running but marks git safety as disabled. Treat that as a degraded state, not a
safe operating mode.

Credential redaction in shell output is also only a convenience feature. It is not a security control.

## Verification

Useful checks:

```bash
cast diagnose
cast status <name>
foundry-git-safety status
sbx policy status
```

Quick manual spot checks:

```bash
# from inside the sandbox
env | grep -i anthropic
echo $GH_TOKEN
which git

# from the host
ls ~/.foundry/data/git-safety/sandboxes/
sbx exec <name> -- head -1 /usr/local/bin/git
```

Expected results:

- real provider keys are absent from the sandbox environment
- `GH_TOKEN` is empty or a placeholder
- `git` resolves to `/usr/local/bin/git`
- `cast status <name>` reports `Git safety` as `True`
- sandbox registrations exist under `~/.foundry/data/git-safety/sandboxes/`

If `cast status <name>` shows `Git safety: False`, or `cast start` reported that
the sandbox started without enforcement, destroy and recreate the sandbox before
trusting git policy behavior.

Security behavior in this repo is exercised by:

- `tests/unit/`
- `tests/smoke/`
- `tests/chaos/`
- `tests/redteam/`

See `tests/redteam/README.md` for the active red-team module list.
