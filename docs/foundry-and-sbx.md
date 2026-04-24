# Foundry and sbx

Foundry Sandbox is not a replacement for Docker `sbx`. It is a policy and
workflow layer built on top of the standalone `sbx` CLI.

Use this page when deciding whether plain `sbx` is enough, or whether a repo
should be launched through `cast`.

## Short Version

Use plain `sbx` when you want an isolated environment for an AI coding agent:
microVM isolation, a private Docker daemon, network policy, host-side credential
injection, templates, ports, and sandbox lifecycle management.

Use Foundry when you also need repo-aware controls around git and GitHub:
branch isolation, protected refs, blocked file-pattern pushes, PR/API policy,
compiled per-repo configuration, wrapper integrity checks, and auditable
decisions.

Foundry depends on `sbx` for the sandbox boundary. `sbx` depends on Foundry for
none of its core behavior.

## Responsibility Split

| Concern | Plain `sbx` | Foundry Sandbox |
|---------|-------------|-----------------|
| MicroVM isolation | Provides the VM boundary, separate kernel, and isolated sandbox filesystem | Requires and uses this boundary |
| Docker access | Provides a private Docker daemon inside each sandbox | Leaves Docker isolation to `sbx` |
| Network access | Provides HTTP/HTTPS proxying and network policies | Uses the `sbx` network path for sandbox traffic |
| Credential handling | Keeps provider credentials on the host and injects them through the `sbx` proxy | Pushes supported host credentials into `sbx`; can also compile proxy-backed env vars for user-defined services |
| Sandbox lifecycle | Creates, runs, stops, removes, snapshots, and reconnects sandboxes | Wraps lifecycle commands in `cast` workflows with repo metadata |
| Git worktrees | Supports branch/worktree workflows | Creates repo-local worktrees as part of the Foundry workflow |
| Git authorization | Does not treat branch mode as a security boundary | Routes sandbox git through `foundry-git-safety` for branch/ref/push policy |
| GitHub API authorization | Provides network and credential plumbing | Filters selected GitHub API operations, including PR merge and sensitive repository endpoints |
| Repo policy | Not repo-policy aware beyond sandbox/workspace options | Resolves `foundry.yaml` layers and compiles sandbox artifacts |
| Wrapper integrity | Not applicable | Checksums and re-injects the sandbox git wrapper when possible |
| Audit trail | Provides `sbx` status, policy, and lifecycle state | Logs git-safety decisions for review |

## What sbx Already Gives You

Docker Sandboxes run AI agents in microVMs. Each sandbox has its own Docker
daemon, filesystem, and network, so an agent can install packages, build images,
run Compose, and mutate its environment without direct access to the host Docker
daemon.

The standalone `sbx` CLI also covers the normal sandbox lifecycle:

```bash
sbx run claude
sbx exec -it <sandbox-name> bash
sbx ls
sbx stop <sandbox-name>
sbx rm <sandbox-name>
sbx save <sandbox-name> my-template:v1
```

It also provides network policies, secret management, custom templates, port
publishing, and an interactive dashboard.

Foundry's role starts above that sandbox boundary. It adds repo-aware policy for
git, GitHub, and generated per-sandbox configuration rather than replacing the
host-isolation, Docker-isolation, network, or credential controls provided by
`sbx`.

## What Foundry Adds

Foundry starts from the assumption that the agent is already inside an `sbx`
microVM. It then adds controls for the parts of software development that are
still risky even when host isolation is working:

- `cast new` creates a sandbox and a repo-local worktree, then records metadata
  so later commands can reattach, start, stop, diagnose, and destroy the same
  environment.
- Git inside the sandbox is routed through `/usr/local/bin/git`, which calls the
  host-side `foundry-git-safety` service.
- `foundry-git-safety` enforces branch visibility, protected-branch rules,
  deletion and force-push rules, blocked file-pattern pushes, and selected
  GitHub API restrictions.
- Foundry resolves built-in defaults, user config, and repo `foundry.yaml`, then
  compiles the resulting policy into sandbox artifacts such as MCP config,
  Claude Code config, git-safety overlays, and proxy-backed environment values.
- A wrapper watchdog checks whether the installed git wrapper has changed and
  re-injects it when possible.

These controls focus on reducing blast radius after the agent has legitimate
access to the workspace and to allowed development services.

## When Plain sbx Is Enough

Plain `sbx` is usually enough when:

- The agent is doing local experimentation and will not push code.
- A human will review and perform all git, GitHub, release, and CI operations
  from the host.
- The main concern is isolating package installs, build scripts, test runs, and
  Docker workloads from the host environment.
- You want a lightweight sandbox lifecycle without Foundry metadata or repo
  policy.

In this mode, use `sbx` branch mode or manual worktrees as workflow tools, not
as authorization boundaries. Review agent-modified workspace files before
running them on the host.

## When Foundry Is Worth Adding

Foundry is useful when:

- Agents are allowed to run normal git or `gh` workflows from inside the
  sandbox.
- You need a policy boundary around protected branches such as `main`,
  `release/*`, or `production`.
- You want to block pushes that include sensitive file patterns such as
  `.github/workflows/`.
- Multiple sandboxes or agents should not casually inspect or operate on one
  another's branches.
- Repo owners need a declarative `foundry.yaml` that compiles into sandbox
  config, MCP config, Claude Code config, and service proxies.
- You want host-side decision logs for git and GitHub policy enforcement.

Foundry is especially relevant for team repos where "the agent can edit code in
an isolated VM" is not enough by itself. The remaining concern is what that
agent can cause to happen through git, GitHub, CI, and allowed APIs.

## Important Limits

Foundry inherits the `sbx` trust boundary. If `sbx` isolation is bypassed, the
host is compromised, or a trusted human disables the controls, Foundry's
guarantees do not hold.

Foundry also does not stop every local workspace edit. An agent can still create,
modify, or delete files it can see in the sandbox workspace. Foundry's git policy
is about what can be viewed through git, pushed, merged, or sent through selected
GitHub API paths from inside the sandbox.

The git wrapper is a practical control, not a hard kernel boundary. A
root-capable process in the sandbox may remove or bypass `/usr/local/bin/git`.
Foundry mitigates this with startup checks and watchdog reinjection, and marks
the sandbox degraded when enforcement is not available.

## Standalone sbx vs. Docker Desktop Integration

Foundry requires the standalone `sbx` CLI. It intentionally rejects Docker
Desktop's `docker sandbox` plugin shim.

Docker documents the Desktop integration as a convenience command with a subset
of functionality. Foundry targets the standalone CLI because it needs the
fuller `sbx` command surface and predictable lifecycle behavior.

For the supported version range and tested-against matrix, see
[sbx Compatibility](sbx-compatibility.md).

## Primary sbx References

- [Docker Sandboxes overview](https://docs.docker.com/ai/sandboxes/)
- [Docker Sandboxes usage](https://docs.docker.com/ai/sandboxes/usage/)
- [Docker Sandboxes architecture](https://docs.docker.com/ai/sandboxes/architecture/)
- [Docker Sandboxes security model](https://docs.docker.com/ai/sandboxes/security/)
- [Workspace trust](https://docs.docker.com/ai/sandboxes/security/workspace/)
- [Credentials](https://docs.docker.com/ai/sandboxes/security/credentials/)
- [`sbx template` CLI reference](https://docs.docker.com/reference/cli/sbx/template/)
- [`sbx` CLI reference](https://docs.docker.com/reference/cli/sbx/)
