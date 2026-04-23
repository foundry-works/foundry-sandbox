# IDE Convenience Checklist

## Phase 1

- Add a new `IdeConfig` model to `foundry_sandbox/foundry_config.py`.
- Add fields:
  - `preferred: str = ""`
  - `args: list[str] = []`
  - `auto_open_on_attach: bool = False`
- Ensure `ide` is supported only from `~/.foundry/foundry.yaml`.
- If repo `foundry.yaml` contains `ide:`, ignore it and emit a warning.

## IDE Resolution

- Refactor `foundry_sandbox/ide.py` to support:
  - known alias
  - explicit executable path
  - bare command from `PATH`
- Preserve human-readable display names for known aliases.
- Preserve macOS app-name fallback for known aliases.
- Add support for passing extra launcher args.
- Add a small internal resolver object or tuple so launch decisions are explicit.

## Attach Integration

- Update `foundry_sandbox/commands/attach.py` to read user IDE config.
- Keep existing flags:
  - `--with-ide`
  - `--ide-only`
  - `--no-ide`
- Change behavior:
  - `--with-ide` with no value uses configured preferred IDE.
  - `--ide-only` with no value uses configured preferred IDE.
  - plain `cast attach` auto-opens IDE if `auto_open_on_attach: true`.
  - `--no-ide` suppresses config-driven auto-open.
- Failure rules:
  - config-driven auto-open warns and continues
  - `--with-ide` warns and continues
  - `--ide-only` exits non-zero on launch failure

## New Command

- Add `foundry_sandbox/commands/open_cmd.py`.
- Add `cast open [name]`.
- Support:
  - `cast open foo`
  - `cast open --last`
  - `cast open foo --ide cursor`
  - `cast open foo --ide /path/to/bin`
- Resolve the host worktree path and launch the IDE only.
- Do not start or attach a sandbox shell.
- Decide whether `cast open` should auto-start a stopped sandbox.
  - Recommended: no, because it only needs the host worktree.

## CLI Wiring

- Register `open` in `foundry_sandbox/cli.py`.
- Add help text consistent with existing command style.

## Tests

- Add unit tests for IDE config parsing.
- Add unit tests for repo-level `ide:` being ignored or warned.
- Add unit tests for resolver behavior:
  - alias
  - absolute path
  - command on `PATH`
  - invalid executable
- Add unit tests for launcher args propagation.
- Extend attach tests:
  - auto-open from config
  - `--with-ide` using config default
  - explicit override by alias
  - explicit override by path
  - `--ide-only` failure exits non-zero
  - `--no-ide` disables config-driven auto-open
- Add tests for `cast open`.

## Docs

- Update `docs/configuration.md` with the new user-only `ide` section.
- Update `docs/usage/commands.md` with:
  - revised `cast attach` semantics
  - new `cast open` command
- Update `docs/getting-started.md` with one convenience example using IDE config.
- Optionally add a short note to `docs/operations.md` clarifying that IDEs are
  host-side convenience, not part of the sandbox boundary.

## Decisions To Lock Before Coding

- Decide whether `--with-ide` and `--ide-only` should keep their current Click
  parsing style or move to explicit optional values.
- Decide whether a missing configured IDE should fall back to auto-detect or
  fail immediately.
  - Recommended: auto-detect for plain attach, fail for `ide-only`.
- Decide whether `cast open` should honor configured `args`.
  - Recommended: yes.
- Decide whether explicit path support requires the file to be executable.
  - Recommended: yes.

## Nice Phase 2

- Add preset-level IDE override.
- Add more aliases:
  - `vscode`
  - `code-insiders`
  - `windsurf`
- Remember last successful IDE automatically.
- Add optional auto `cast git-mode --mode host` integration.
- Add `cast up` convenience wrapper around create/start/open/attach.
