# sbx run

Run an agent in a sandbox.

## Usage

```bash
sbx run [flags] SANDBOX | AGENT [PATH...] [-- AGENT_ARGS...]
```

## Description

Run an agent in a sandbox, creating the sandbox if it does not already exist.

Pass agent arguments after the `--` separator. Additional workspaces can be provided as extra arguments. Append `:ro` to mount them read-only.

To create a sandbox without attaching, use `sbx create` instead.

Available agents: `claude`, `codex`, `copilot`, `docker-agent`, `gemini`, `kiro`, `opencode`, `shell`

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--branch` | | Create a Git worktree on the given branch (use `--branch auto` to auto-generate) |
| `--cpus` | `0` | Number of CPUs to allocate to the sandbox (0 = auto: N-1 host CPUs, min 1) |
| `-m, --memory` | | Memory limit in binary units (e.g., `1024m`, `8g`). Default: 50% of host memory, max 32 GiB |
| `--name` | | Name for the sandbox (default: `<agent>-<workdir>`) |
| `-t, --template` | | Container image to use for the sandbox (default: agent-specific image) |

## Global options

| Option | Default | Description |
|--------|---------|-------------|
| `-D, --debug` | | Enable debug logging |

## Examples

```bash
# Create and run a sandbox with claude in current directory
sbx run claude

# Create and run with additional workspaces (read-only)
sbx run claude . /path/to/docs:ro

# Run an existing sandbox
sbx run existing-sandbox

# Run a sandbox with agent arguments
sbx run claude -- --continue
```
