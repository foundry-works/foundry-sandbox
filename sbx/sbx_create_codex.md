# sbx create codex

|  |  |
| --- | --- |
| Description | Create a sandbox for codex |
| Usage | `sbx create codex PATH [PATH...] [flags]` |

## Description

Create a sandbox with access to a host workspace for codex.

The workspace path is required and will be mounted inside the sandbox at the
same path as on the host. Additional workspaces can be provided as extra
arguments. Append ":ro" to mount them read-only.

Use "sbx run SANDBOX" to attach to the agent after creation.

## Global options

| Option | Default | Description |
| --- | --- | --- |
| `--branch` |  | Create a Git worktree on the given branch |
| `--cpus` | `0` | Number of CPUs to allocate to the sandbox (0 = auto: N-1 host CPUs, min 1) |
| `-D, --debug` |  | Enable debug logging |
| `-m, --memory` |  | Memory limit in binary units (e.g., 1024m, 8g). Default: 50% of host memory, max 32 GiB |
| `--name` |  | Name for the sandbox (default: <agent>-<workdir>, letters, numbers, hyphens, periods, plus signs and minus signs only) |
| `-q, --quiet` |  | Suppress verbose output |
| `-t, --template` |  | Container image to use for the sandbox (default: agent-specific image) |

## Examples

```
# Create in the current directory
sbx create codex .

# Create with a specific path
sbx create codex /path/to/project

# Create with additional read-only workspaces
sbx create codex . /path/to/docs:ro
```
