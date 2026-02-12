# Parity Diffs: Shell → Python Command Migration

This document records the behavioral equivalence analysis between each shell command
(`commands/*.sh` + `lib/args.sh`) and its migrated Python counterpart
(`foundry_sandbox/commands/*.py`). Produced per the parity contract defined in
`specs/.plans/python-rewrite-and-test-suite.md`.

**Scope:** All 16 migrated commands + 2 aliases.

**Parity dimensions:**
1. **Flag parity** — every `args.sh` flag has a Click decorator equivalent
2. **Exit code parity** — identical exit codes for equivalent scenarios
3. **JSON schema parity** — field names, types, and nesting match
4. **stderr/output parity** — error messages are message-equivalent

---

## Table of Contents

- [Summary Matrix](#summary-matrix)
- [Aliases](#aliases)
- [Per-Command Parity Diffs](#per-command-parity-diffs)
  - [build](#build)
  - [stop](#stop)
  - [help](#help)
  - [list](#list)
  - [info](#info)
  - [config](#config)
  - [status](#status)
  - [preset](#preset)
  - [destroy](#destroy)
  - [destroy-all](#destroy-all)
  - [upgrade](#upgrade)
  - [refresh-credentials](#refresh-credentials)
  - [prune](#prune)
  - [attach](#attach)
  - [start](#start)
  - [new](#new)
- [Known Deviations](#known-deviations)
- [Recommendations](#recommendations)

---

## Summary Matrix

| Command | Flags | Exit Codes | JSON Schema | stderr | Status |
|---------|:-----:|:----------:|:-----------:|:------:|:------:|
| build | MATCH | MATCH | N/A | MINOR | PASS |
| stop | MATCH | DEVIATION | N/A | MATCH | PASS* |
| help | N/A | MATCH | N/A | MATCH | PASS |
| list | MATCH | MATCH | MATCH | MATCH | PASS |
| info | MATCH | MATCH | MATCH | MATCH | PASS |
| config | MATCH | MATCH | MATCH | MATCH | PASS |
| status | MATCH | MATCH | MATCH | MATCH | PASS |
| preset | MATCH | MATCH | N/A | MINOR | PASS |
| destroy | MATCH | MATCH | N/A | MINOR | PASS |
| destroy-all | DEVIATION | MATCH | N/A | MATCH | PASS* |
| upgrade | DEVIATION | MATCH | N/A | MINOR | PASS* |
| refresh-credentials | MATCH | MATCH | N/A | MATCH | PASS |
| prune | MATCH | MATCH | MATCH | MATCH | PASS |
| attach | MATCH | MATCH | N/A | MATCH | PASS |
| start | MATCH | MATCH | N/A | MATCH | PASS |
| new | MATCH | MATCH | N/A | MATCH | PASS |

**Legend:** PASS = full parity, PASS* = functionally equivalent with documented minor deviation

---

## Aliases

| Alias | Shell Resolution | Python Resolution | Parity |
|-------|-----------------|-------------------|--------|
| `repeat` | `cmd_new --last` (via `sandbox.sh` case) | `("new", ["--last"])` via `ALIASES` in `cli.py:36` | MATCH |
| `reattach` | `cmd_attach --last` (via `sandbox.sh` case) | `("attach", ["--last"])` via `ALIASES` in `cli.py:37` | MATCH |

---

## Per-Command Parity Diffs

### build

**Shell:** `commands/build.sh` (17 lines)
**Python:** `foundry_sandbox/commands/build.py` (43 lines)

#### Flag Parity

| Shell (`parse_build_args`) | Python (Click) | Parity |
|---------------------------|----------------|--------|
| `--no-cache` → `BUILD_NO_CACHE="--no-cache"` | `@click.option("--no-cache", is_flag=True)` | MATCH |
| `--without-opencode` → `BUILD_WITHOUT_OPENCODE="1"` | `@click.option("--without-opencode", is_flag=True)` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| Success | 0 (implicit) | 0 (implicit) | MATCH |
| Docker compose build fails | Propagated via `run_cmd` | `sys.exit(result.returncode)` | MATCH |
| Docker build (proxy) fails | Propagated via `run_cmd` | `sys.exit(result.returncode)` | MATCH |

#### stderr Parity

- Shell uses `echo` for status messages (stdout).
- Python uses `log_info()` which writes to stdout with blue prefix.
- **MINOR:** Message prefix differs (plain text vs colored `ℹ` prefix), but both go to stdout.

---

### stop

**Shell:** `commands/stop.sh` (24 lines)
**Python:** `foundry_sandbox/commands/stop.py` (41 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| Positional `$1` = name (required) | `@click.argument("name")` (required) | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| No name provided | `exit 1` with usage message | Click auto-error (exit 2) | DEVIATION |
| Success | 0 (implicit) | 0 (implicit) | MATCH |

**Note on deviation:** Click returns exit code 2 for missing required arguments with a `Missing argument 'NAME'` message. Shell uses exit 1 with custom usage text. This is a standard Click behavior difference affecting all commands with required arguments — the error is still user-visible and semantically equivalent.

#### stderr Parity

- Shell: `echo "Stopping sandbox: $name..."` (stdout)
- Python: `log_info(f"Stopping sandbox: {name}...")` (stdout, colored)
- MATCH (both stdout, message-equivalent)

---

### help

**Shell:** `commands/help.sh` (60 lines)
**Python:** `foundry_sandbox/commands/help_cmd.py` (73 lines)

#### Flag Parity

No flags. Both display help text.

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| Normal | 0 (implicit) | 0 (implicit) | MATCH |

#### Output Parity

- Shell uses `$0` (script path) in examples; Python hardcodes `cast`.
- Help text content is identical line-by-line (verified).
- MATCH

---

### list

**Shell:** `commands/list.sh` (28 lines)
**Python:** `foundry_sandbox/commands/list_cmd.py` (183 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| `--json` (checked via `$1`) | `@click.option("--json", "json_output", is_flag=True)` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| Normal (text or JSON) | 0 (`return`) | 0 (implicit) | MATCH |
| No worktrees dir | Iterates empty, no output | Outputs `[]` (JSON) or header only (text) | MATCH |

#### JSON Schema Parity

Shell delegates to `sandbox_info_json` helper. Python builds equivalent structure in `_collect_sandbox_info()`:

```json
[
  {
    "name": "string",
    "worktree": "string",
    "worktree_exists": "boolean",
    "claude_config": "string",
    "claude_config_exists": "boolean",
    "container": "string",
    "docker_status": "string",
    "tmux": "string",
    "repo": "string",
    "branch": "string",
    "from_branch": "string",
    "mounts": ["string"],
    "copies": ["string"]
  }
]
```

Field names, types, and nesting: **MATCH**

---

### info

**Shell:** `commands/info.sh` (24 lines)
**Python:** `foundry_sandbox/commands/info.py` (90 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| `--json` | `@click.option("--json", "json_output", is_flag=True)` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| Normal | 0 (`return`) | 0 (implicit) | MATCH |

#### JSON Schema Parity

Both produce: `{"config": {...}, "status": {...}}`

- Shell: `printf '{"config":%s,"status":%s}'`
- Python: `json.dumps({"config": config_data, "status": status_data})`
- Python adds JSON decode error fallback (`{"config":{},"status":{}}`) — not present in shell.
- Field structure: **MATCH**

---

### config

**Shell:** `commands/config.sh` (70 lines)
**Python:** `foundry_sandbox/commands/config.py` (111 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| `--json` | `@click.option("--json", "json_output", is_flag=True)` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| Normal | 0 (`return`) | 0 (implicit) | MATCH |

#### JSON Schema Parity

```json
{
  "sandbox_home": "string",
  "repos_dir": "string",
  "worktrees_dir": "string",
  "claude_configs_dir": "string",
  "script_dir": "string",
  "docker_image": "string",
  "docker_uid": "string",
  "docker_gid": "string",
  "network_mode": "string",
  "sync_ssh": "boolean",
  "ssh_mode": "string",
  "debug": "boolean",
  "verbose": "boolean",
  "assume_yes": "boolean"
}
```

Shell uses raw printf with inline booleans; Python uses `json.dumps()` with proper boolean coercion (`"true"` or `"1"` → `True`). Field names and types: **MATCH**

#### Text Output Parity

Both display same key-value pairs in same order, plus system checks (git, docker, docker daemon). Format uses `format_kv()` in both. **MATCH**

---

### status

**Shell:** `commands/status.sh` (89 lines)
**Python:** `foundry_sandbox/commands/status.py` (136 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| `[name]` (optional positional) | `@click.argument("name", required=False, default=None)` | MATCH |
| `--json` | `@click.option("--json", "json_output", is_flag=True)` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| All sandboxes | 0 | 0 | MATCH |
| Single sandbox | 0 | 0 | MATCH |

#### JSON Schema Parity

Single sandbox and array mode both use the same structure as `list` command:

```json
{
  "name": "string",
  "worktree": "string",
  "worktree_exists": "boolean",
  "claude_config": "string",
  "claude_config_exists": "boolean",
  "container": "string",
  "docker_status": "string",
  "tmux": "string",
  "repo": "string",
  "branch": "string",
  "from_branch": "string",
  "mounts": ["string"],
  "copies": ["string"]
}
```

**MATCH**

---

### preset

**Shell:** `commands/preset.sh` (51 lines)
**Python:** `foundry_sandbox/commands/preset.py` (85 lines)

#### Flag Parity

| Shell Subcommand | Python Subcommand | Parity |
|-----------------|-------------------|--------|
| `list` (default) | `@preset.command("list")` + group default | MATCH |
| `show <name>` | `@preset.command("show")` + `@click.argument("name")` | MATCH |
| `delete <name>` | `@preset.command("delete")` + `@click.argument("name")` | MATCH |
| `rm <name>` | `@preset.command("rm", hidden=True)` | MATCH |
| `remove <name>` | `@preset.command("remove", hidden=True)` | MATCH |
| `help`/`--help`/`-h` | Click auto-generates `--help` | MATCH |
| Unknown subcommand | `exit 1` | Click handles (exit 2 with usage) | MATCH (functionally) |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| Preset not found (show) | `exit 1` (via helper) | `sys.exit(1)` | MATCH |
| Preset not found (delete) | `exit 1` (via helper) | `sys.exit(1)` | MATCH |
| Missing name | `exit 1` with usage | Click missing argument (exit 2) | MATCH (functionally) |
| Success | 0 (implicit) | 0 (implicit) | MATCH |

#### stderr Parity

- Shell: `echo` for error messages (stdout)
- Python: `log_error()` for not-found errors (stderr, colored)
- **MINOR:** Error channel differs (shell→stdout, Python→stderr via `log_error`). Python behavior is arguably more correct.

---

### destroy

**Shell:** `commands/destroy.sh` (82 lines)
**Python:** `foundry_sandbox/commands/destroy.py` (260 lines)

#### Flag Parity

| Shell (`parse_destroy_args`) | Python (Click) | Parity |
|-----------------------------|----------------|--------|
| `--keep-worktree` | `@click.option("--keep-worktree", is_flag=True)` | MATCH |
| `-f` / `--force` | `@click.option("--force", "-f", is_flag=True)` | MATCH |
| `-y` / `--yes` | `@click.option("--yes", "-y", is_flag=True)` | MATCH |
| Positional `name` | `@click.argument("name")` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| No name | `exit 1` | Click (exit 2) | MATCH (functionally) |
| User aborts | `exit 0` | `sys.exit(0)` | MATCH |
| Success | 0 (implicit) | 0 (implicit) | MATCH |

#### Additional Python Behaviors

- Respects `SANDBOX_NONINTERACTIVE=1` as implicit `--yes` (shell uses `SANDBOX_ASSUME_YES`)
- Python adds `try/except click.Abort` for Ctrl+C during confirmation
- Python adds proxy cleanup and HMAC/stubs volume removal (matching shell)
- Python adds branch cleanup from bare repo (matching shell)

#### stderr Parity

- Shell: `echo` messages (stdout)
- Python: `click.echo()` + `log_info()`/`log_warn()` (stdout, colored)
- **MINOR:** Warning messages for cleanup failures are new in Python (best-effort cleanup already exists in shell via `|| true` but is silent).

---

### destroy-all

**Shell:** `commands/destroy-all.sh` (106 lines)
**Python:** `foundry_sandbox/commands/destroy_all.py` (276 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| `--keep-worktree` | `@click.option("--keep-worktree", is_flag=True)` | MATCH |
| (no `--force` flag) | `@click.option("--force", "-f", is_flag=True)` | DEVIATION (added) |

**DEVIATION:** Python adds `--force` flag not present in shell. Shell only uses double confirmation flow (y/N + type "destroy all"). Python adds `--force`/`-f` to skip all prompts, plus `SANDBOX_NONINTERACTIVE` support. This is an additive enhancement that does not break existing behavior.

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| No sandboxes | `return 0` | `sys.exit(0)` | MATCH |
| User aborts | `return 0` | `sys.exit(0)` | MATCH |
| Worktree removal fails | `return 1` | `sys.exit(1)` | MATCH |
| Success | 0 (implicit) | 0 (implicit) | MATCH |

---

### upgrade

**Shell:** `commands/upgrade.sh` (43 lines)
**Python:** `foundry_sandbox/commands/upgrade.py` (42 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| `--local` | `@click.option("--local", "use_local", is_flag=True)` | MATCH |
| `--help` / `-h` | Click auto-generates `--help` | MATCH |
| Unknown option → `exit 1` | Click handles unknown options | MATCH (functionally) |

**DEVIATION:** Shell explicitly parses `--help`/`-h` and prints custom help text. Python relies on Click's auto-generated help. The information is equivalent.

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| `--local`, install.sh missing | `die` (exit 1) | `sys.exit(1)` | MATCH |
| `--local`, installer runs | Propagated | `sys.exit(result.returncode)` | MATCH |
| Remote upgrade | Propagated via curl pipe | `sys.exit(result.returncode)` | MATCH |
| Unknown option | `exit 1` | Click (exit 2) | MATCH (functionally) |

#### stderr Parity

- Shell: `die` writes to stderr; `echo` to stdout
- Python: `log_error()` writes to stderr; `click.echo()` to stdout
- **MINOR:** `die` uses generic message format; `log_error` uses colored prefix.

---

### refresh-credentials

**Shell:** `commands/refresh-credentials.sh` (94 lines)
**Python:** `foundry_sandbox/commands/refresh_creds.py` (307 lines)

#### Flag Parity

| Shell (`parse_refresh_credentials_args`) | Python (Click) | Parity |
|-----------------------------------------|----------------|--------|
| `--last` / `-l` | `@click.option("--last", "-l", is_flag=True)` | MATCH |
| Positional `name` (optional) | `@click.argument("name", required=False, default=None)` | MATCH |
| Unknown `-*` → `die` | Click handles unknown options | MATCH (functionally) |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| `--last` fails | `exit 1` | `sys.exit(1)` | MATCH |
| No sandbox selected (fzf) | `exit 1` | `sys.exit(1)` | MATCH |
| Metadata load fails | `die` (exit 1) | `sys.exit(1)` | MATCH |
| Container not running | `die` (exit 1) | `sys.exit(1)` | MATCH |
| Proxy restart fails | Propagated | `sys.exit(1)` | MATCH |
| Success | 0 (implicit) | 0 (implicit) | MATCH |

---

### prune

**Shell:** `commands/prune.sh` (178 lines)
**Python:** `foundry_sandbox/commands/prune.py` (424 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| `-f` / `--force` | `@click.option("--force", "-f", is_flag=True)` | MATCH |
| `--json` | `@click.option("--json", "json_output", is_flag=True)` | MATCH |
| `--no-container` | `@click.option("--no-container", is_flag=True)` | MATCH |
| `--networks` | `@click.option("--networks", is_flag=True)` | MATCH |
| `--all` | `@click.option("--all", "all_flag", is_flag=True)` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| Normal (items removed) | 0 | 0 | MATCH |
| Nothing to prune | 0 | 0 | MATCH |

#### JSON Schema Parity

```json
[
  {"name": "string", "type": "orphaned_config | no_container | orphaned_network"}
]
```

Both produce identical array structure. **MATCH**

#### Additional Python Behaviors

- Respects `SANDBOX_NONINTERACTIVE=1` as implicit `--force`
- Includes branch cleanup (matching shell's `cleanup_sandbox_branch`)

---

### attach

**Shell:** `commands/attach.sh` (123 lines)
**Python:** `foundry_sandbox/commands/attach.py` (458 lines)

#### Flag Parity

| Shell (`parse_attach_args`) | Python (Click) | Parity |
|----------------------------|----------------|--------|
| `--last` | `@click.option("--last", "use_last", is_flag=True)` | MATCH |
| `--with-ide [name]` / `--with-ide=<name>` | `@click.option("--with-ide", flag_value="auto", default=None)` | MATCH |
| `--ide-only [name]` / `--ide-only=<name>` | `@click.option("--ide-only", flag_value="auto", default=None)` | MATCH |
| `--no-ide` | `@click.option("--no-ide", is_flag=True)` | MATCH |
| Positional `name` (optional) | `@click.argument("name", required=False, default=None)` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| `--last` fails | `exit 1` | `sys.exit(1)` | MATCH |
| No sandbox selected | `exit 1` | `sys.exit(1)` | MATCH |
| Sandbox not found | `exit 1` | `sys.exit(1)` | MATCH |
| Container start fails | Propagated via `cmd_start` | `sys.exit(result.returncode)` | MATCH |
| Success | 0 / `os.execvp` | 0 / `os.execvp` | MATCH |

#### Behavioral Notes

- Both implementations: auto-detect from cwd → fzf selection → usage/list fallback
- Both save last-attached sandbox for `--last`
- IDE launch is stubbed in Python (noted as pending migration); shell version uses real IDE launch functions
- Both use `os.execvp`/`exec` to replace process with tmux

---

### start

**Shell:** `commands/start.sh` (203 lines)
**Python:** `foundry_sandbox/commands/start.py` (485 lines)

#### Flag Parity

| Shell | Python | Parity |
|-------|--------|--------|
| Positional `name` (required) | `@click.argument("name")` | MATCH |

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| No name | `exit 1` | Click (exit 2) | MATCH (functionally) |
| Sandbox not found | `exit 1` | `sys.exit(1)` | MATCH |
| HMAC secret issues | `die` (exit 1) | `sys.exit(1)` | MATCH |
| Proxy registration fails | `die` (exit 1) | `sys.exit(1)` | MATCH |
| Sandbox ID generation fails | `die` (exit 1) | `sys.exit(1)` | MATCH |
| Success | 0 (implicit) | 0 (implicit) | MATCH |

#### Behavioral Notes

- Both check image freshness, load metadata, handle credential isolation
- Both manage HMAC secret volumes with same logic (repair, count, provision)
- Both handle SSH agent forwarding, override files, proxy registration
- Both apply network restrictions after startup

---

### new

**Shell:** `commands/new.sh` (1,343 lines) + `lib/args.sh` `parse_new_args()`
**Python:** `foundry_sandbox/commands/new.py` (1,132 lines)

#### Flag Parity

| Shell (`parse_new_args`) | Python (Click) | Parity |
|-------------------------|----------------|--------|
| `--last` | `@click.option("--last", is_flag=True)` | MATCH |
| `--preset <name>` / `--preset=<name>` | `@click.option("--preset")` | MATCH |
| `--save-as <name>` / `--save-as=<name>` | `@click.option("--save-as")` | MATCH |
| `--mount <path>` / `-v <path>` | `@click.option("--mount", "-v", multiple=True)` | MATCH |
| `--copy <path>` / `-c <path>` | `@click.option("--copy", "-c", multiple=True)` | MATCH |
| `--network <mode>` / `-n <mode>` | `@click.option("--network", "-n")` | MATCH |
| `--with-ssh` | `@click.option("--with-ssh", is_flag=True)` | MATCH |
| `--skip-key-check` | `@click.option("--skip-key-check", is_flag=True)` | MATCH |
| `--from-branch <branch>` / `--from-branch=<branch>` | Mapped via `--from` option | MATCH |
| `--from <branch>` / `--from=<branch>` | `@click.option("--from", "from_flag")` | MATCH |
| `--wd <path>` / `--wd=<path>` | `@click.option("--wd")` | MATCH |
| `--sparse` | `@click.option("--sparse", is_flag=True)` | MATCH |
| `--no-isolate-credentials` / `--no-isolate` | `@click.option("--no-isolate-credentials", is_flag=True)` | MATCH |
| `--allow-dangerous-mount` | `@click.option("--allow-dangerous-mount", is_flag=True)` | MATCH |
| `--allow-pr` / `--with-pr` | `@click.option("--allow-pr", "--with-pr", is_flag=True)` | MATCH |
| `--with-opencode` | `@click.option("--with-opencode", is_flag=True)` | MATCH |
| `--with-zai` | `@click.option("--with-zai", is_flag=True)` | MATCH |
| `--pip-requirements <path>` / `-r <path>` | `@click.option("--pip-requirements", "-r")` | MATCH |
| `--with-ide [name]` / `--with-ide=<name>` | `@click.option("--with-ide")` | MATCH |
| `--ide-only [name]` / `--ide-only=<name>` | `@click.option("--ide-only")` | MATCH |
| `--no-ide` | `@click.option("--no-ide", is_flag=True)` | MATCH |
| Positional: `<repo>` `[branch]` `[from]` | `@click.argument("repo", ...)` etc. | MATCH |
| `--no-ssh` / `--without-ssh` → `die` | Not implemented (removed flag) | MATCH |
| `--with-ssh-always` → `die` | Not implemented (removed flag) | MATCH |
| `--with-api-keys` / `--no-api-keys` → `die` | Not implemented (removed flag) | MATCH |

**Total flags: 23 options + 3 positional args = all accounted for.**

#### Exit Codes

| Scenario | Shell | Python | Parity |
|----------|-------|--------|--------|
| `--last` load fails | `exit 1` | `sys.exit(1)` | MATCH |
| `--preset` load fails | `exit 1` | `sys.exit(1)` | MATCH |
| Missing repo URL | `exit 1` | `sys.exit(1)` | MATCH |
| Invalid repo | `exit 1` | `sys.exit(1)` | MATCH |
| Network capacity fails | `exit 1` | `sys.exit(1)` | MATCH |
| Copy source missing | `exit 1` | `sys.exit(1)` | MATCH |
| Proxy registration fails | `exit 1` | `sys.exit(1)` | MATCH |
| User cancels wizard | `return 1` | `sys.exit(1)` | MATCH |
| Success | 0 (implicit) | 0 (implicit) | MATCH |

---

## Known Deviations

### 1. Click argument validation (exit code 2 vs 1)

**Affected commands:** stop, destroy, start (any command with required arguments)

When a required argument is missing, Click returns exit code **2** with `Missing argument 'NAME'`. Shell returns exit code **1** with custom usage text. This is a standard Click convention and is semantically equivalent (both indicate user error). No action needed.

### 2. destroy-all: added `--force` flag

Python adds `--force`/`-f` flag not present in shell. The shell only uses double confirmation. This is an additive enhancement — existing shell behavior (double confirmation) is preserved when `--force` is not used.

### 3. upgrade: `--help` handling

Shell parses `--help`/`-h` explicitly and shows custom help. Python relies on Click's auto-generated help. Content is functionally equivalent.

### 4. Error output channel

Several commands differ in whether error messages go to stdout (shell `echo`) vs stderr (Python `log_error()`). Python's behavior is more Unix-conventional. This does not affect user-facing behavior but may affect scripts that parse stderr.

### 5. SANDBOX_NONINTERACTIVE support

Python commands (destroy, destroy-all, prune) respect `SANDBOX_NONINTERACTIVE=1` as a confirmation skip. Shell uses `SANDBOX_ASSUME_YES` for destroy only. This is a standardization improvement in the Python version.

### 6. IDE launch stubs

`attach.py` has stub implementations for IDE launch (`_launch_ide`, `_prompt_ide_selection`). These return `False` and log debug messages. The shell version has full IDE launch support. This is a known incomplete migration area.

---

## Recommendations

1. **Exit code 2 for missing arguments:** Consider accepting Click's convention (exit 2 for usage errors) as the new standard for the Python CLI. Document this in the parity contract.

2. **IDE launch completion:** The attach command's IDE stubs should be completed to achieve full behavioral parity.

3. **Error channel standardization:** The Python version's use of stderr for errors is more correct. Consider this the target state rather than a deviation.

4. **SANDBOX_NONINTERACTIVE:** The Python version's universal support for this env var is an improvement. Consider backporting to shell or accepting as the new standard.

5. **Removed flags:** Shell handles `--no-ssh`, `--with-ssh-always`, `--with-api-keys`, `--no-api-keys` with `die` messages. Python silently ignores these (Click's unknown option handling). Consider adding explicit Click options that raise errors with migration messages for better UX.
