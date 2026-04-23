# IDE Convenience Plan

## Summary

This plan focuses on developer convenience for host-side IDE usage with
Foundry Sandbox. The goal is not to deepen the sandbox boundary around the IDE.
The goal is to make opening the right worktree in the right editor effectively
zero-friction.

The current product already has basic IDE launch support through
`cast attach --with-ide` and `cast attach --ide-only`, but the experience is
thin:

- IDE selection is ephemeral and not persisted.
- Supported IDEs are hardcoded.
- Detection is mostly CLI-on-PATH based.
- There is no host-only "open this worktree" command.
- The create/start/open/attach flow is still split across multiple commands.

This plan proposes a first convenience-focused step centered on user-level IDE
preferences, better launcher resolution, and a dedicated `cast open` command.

## Goals

- Let a developer set a preferred IDE once and stop retyping it.
- Support IDE aliases, explicit executable paths, and bare commands on `PATH`.
- Make `cast attach` able to use the configured IDE by default.
- Add a host-only `cast open` command for opening the sandbox worktree without
  attaching a shell.
- Keep IDE behavior machine-local and outside repo policy.

## Non-Goals

- No IDE plugin or extension work.
- No attempt to make the host IDE part of the sandbox trust boundary.
- No repo-level IDE policy.
- No remote editor protocol integration.

## Current State

The current implementation has two relevant pieces:

- `foundry_sandbox/commands/attach.py`
  - Supports `--with-ide`, `--ide-only`, and `--no-ide`.
  - Opens the host worktree and then optionally attaches a sandbox shell.
- `foundry_sandbox/ide.py`
  - Hardcodes IDE aliases: `cursor`, `zed`, `code`.
  - Detects IDE availability through `PATH`.
  - Uses `open -a` on macOS as a launch fallback.

The important product boundary is that the IDE is host-side convenience. The
sandbox shell, git wrapper, proxy, and policy server remain the actual safety
mechanisms.

## Proposed Config

Add a user-only `ide` section to `~/.foundry/foundry.yaml`.

Example:

```yaml
version: "1"

ide:
  preferred: /Applications/Cursor.app/Contents/Resources/app/bin/cursor
  args: ["--reuse-window"]
  auto_open_on_attach: true
```

Also valid:

```yaml
version: "1"

ide:
  preferred: cursor
```

### Semantics

- `preferred`
  - May be a known alias such as `cursor`, `zed`, or `code`.
  - May be an absolute executable path.
  - May be a bare command name that should be resolved from `PATH`.
- `args`
  - Optional extra arguments passed when launching the IDE.
- `auto_open_on_attach`
  - If `true`, plain `cast attach <name>` should open the configured IDE unless
    `--no-ide` is passed.

## Config Scope

This config should be user-only.

Repo `foundry.yaml` should not be allowed to configure `ide` because:

- IDE paths are machine-specific.
- IDE preference is personal workflow, not shared sandbox policy.
- Repo config should not decide which host application a developer launches.

If a repo config includes `ide:`, Foundry should ignore it and warn.

## CLI Behavior

## `cast attach`

Keep the current attach command and extend its behavior.

Desired behavior:

- `cast attach foo`
  - If `auto_open_on_attach: true` and `--no-ide` is not passed, open the
    preferred IDE and then attach the sandbox shell.
- `cast attach foo --with-ide`
  - Use the configured preferred IDE.
- `cast attach foo --with-ide cursor`
  - Override the config with the provided alias, path, or command.
- `cast attach foo --ide-only`
  - Use the configured preferred IDE and skip terminal attach.
- `cast attach foo --ide-only /path/to/bin`
  - Override the config and skip terminal attach.
- `cast attach foo --no-ide`
  - Suppress all IDE behavior, even if auto-open is enabled in config.

### Failure behavior

- `--with-ide`
  - IDE launch failure should warn and continue to terminal attach.
- `--ide-only`
  - IDE launch failure should exit non-zero.
- plain `cast attach`
  - If auto-open is config-driven, a launch failure should warn and still attach.

## `cast open`

Add a new host-only command for opening the sandbox worktree in an IDE.

Examples:

```bash
cast open foo
cast open --last
cast open foo --ide cursor
cast open foo --ide /Applications/Cursor.app/Contents/Resources/app/bin/cursor
```

Behavior:

- Resolve sandbox name or `--last`.
- Resolve the host worktree path.
- Launch the requested or configured IDE against that worktree.
- Do not attach a sandbox shell.

This command exists purely for convenience and should be fast and simple.

## IDE Resolution Rules

Resolution order:

1. explicit CLI value
2. user config `ide.preferred`
3. auto-detect

Launcher resolution rules:

- If the value contains `/`, treat it as an explicit executable path.
- Else if it matches a known alias, use alias-aware launch behavior.
- Else try it as a command on `PATH`.

Known aliases should initially include:

- `cursor`
- `zed`
- `code`

Optional future aliases:

- `vscode`
- `code-insiders`
- `windsurf`

## Launcher Behavior

The launcher should distinguish between three cases:

### Alias

Use Foundry's built-in knowledge for known IDEs:

- display name mapping
- macOS app name mapping
- CLI command mapping

### Explicit executable path

Launch the provided binary directly with the worktree path and configured args.
This is the main escape hatch for custom or non-standard installs.

### Bare command

Resolve via `PATH` and launch as a normal command.

## macOS Reliability

The current code already tries `open -a` on macOS, but discovery is still based
on CLI presence. This means installed apps without CLI setup are not currently
discoverable in the auto path.

The improved design should:

- still support `open -a` for known aliases on macOS
- allow configured explicit executable paths to bypass discovery problems
- avoid requiring the IDE CLI to be on `PATH` when the user has configured an
  explicit path

## Interaction With `git-mode`

This plan is convenience-first, not isolation-first. Still, host IDEs often run
host-side Git, indexers, and tooling against the host worktree. Foundry already
has `cast git-mode` for reconciling host-side IDE tooling with sandbox-side Git
expectations.

Phase 1 should not make `git-mode` automatic by default.

Phase 2 can consider:

- optional auto `cast git-mode --mode host` when opening the worktree in an IDE
- optional restoration to sandbox mode when attaching back into the sandbox

That should remain explicitly framed as convenience behavior, not a security
control.

## Presets

Phase 1 should keep IDE config user-level only.

A possible Phase 2 extension is allowing presets to override the user default:

```yaml
ide:
  preferred: cursor
```

for workflows where a specific sandbox profile is commonly associated with a
specific editor.

This is lower priority than getting user-level defaults working well.

## UX Examples

### Example 1: Preferred IDE path

```yaml
version: "1"

ide:
  preferred: /Applications/Cursor.app/Contents/Resources/app/bin/cursor
  auto_open_on_attach: true
```

```bash
cast attach repo-feature-login
```

Result:

- open Cursor on the host worktree
- attach sandbox shell afterward

### Example 2: No shell, just open the worktree

```bash
cast open repo-feature-login
```

Result:

- open the host worktree in the preferred IDE
- do not enter the sandbox shell

### Example 3: One-off override

```bash
cast attach repo-feature-login --with-ide zed
```

Result:

- open the host worktree in Zed
- attach sandbox shell

## Implementation Notes

The implementation should stay close to the existing code shape:

- extend config parsing in `foundry_sandbox/foundry_config.py`
- refactor `foundry_sandbox/ide.py` into a resolver + launcher
- update `foundry_sandbox/commands/attach.py` to consult config
- add a new `foundry_sandbox/commands/open_cmd.py`
- register the new command in `foundry_sandbox/cli.py`

## Phase 1 Deliverables

- user-level `ide` config
- alias/path/command launcher resolution
- attach integration with configured IDE defaults
- new `cast open` command
- tests and docs

## Phase 2 Ideas

- preset-level IDE override
- better alias coverage
- automatic memory of last successful IDE
- optional `git-mode host` on IDE open
- future `cast up` command that wraps create/start/open/attach

## Recommendation

Implement Phase 1 first. It is small, directly useful, and aligned with the
current architecture. It improves convenience without expanding the trust model
or introducing a large new product surface.
