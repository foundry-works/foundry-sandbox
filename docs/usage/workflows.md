# Common Workflows

These examples follow the current flow: create the sandbox first, then attach to it.

## Start a Feature Sandbox

```bash
cast new owner/repo feature-login main
cast attach repo-feature-login
```

Inside the sandbox:

```bash
cd /workspace
git status
claude
```

When you are done:

```bash
cast destroy repo-feature-login --yes
```

## Work From the Current Repo

If you are already inside a local checkout:

```bash
cast new . feature-login main
cast attach repo-feature-login
```

## Keep Multiple Sandboxes Open

Separate worktrees let you work on several branches at once:

```bash
cast new owner/repo feature-auth main
cast new owner/repo feature-ui main
cast new owner/repo fix-login-bug main

cast list
cast attach repo-feature-auth
```

## Review and Comment on a PR

If you need PR-oriented operations from inside the sandbox, create it with `--allow-pr`:

```bash
cast new owner/repo review-pr-123 main --allow-pr
cast attach repo-review-pr-123
```

Inside the sandbox, use your normal git and `gh` workflow.

## Reuse a Known Setup

Reuse the last `cast new` invocation:

```bash
cast new --last
```

Save only CLI flags:

```bash
cast new owner/repo feature-api --wd packages/api --save-as api-work
cast new --preset api-work
```

Snapshot a running sandbox, including runtime state:

```bash
cast preset save api-snapshot --sandbox repo-feature-api
cast new --preset api-snapshot
```

## Pause and Resume

```bash
cast stop repo-feature-login
cast start repo-feature-login
cast attach repo-feature-login
```

`cast start` repairs wrapper drift if needed. Use `cast start <name> --watchdog` or `cast watchdog` for continuous monitoring.
