# sbx create

|  |  |
| --- | --- |
| Description | Create a sandbox for an agent |
| Usage | `sbx create [flags] AGENT PATH [PATH...]` |

## Description

Create a sandbox with access to a host workspace for an agent.

Use "sbx run SANDBOX" to attach to the agent after creation.

## Commands

| Command | Description |
| --- | --- |
| `sbx create claude` | Create a sandbox for claude |
| `sbx create codex` | Create a sandbox for codex |
| `sbx create copilot` | Create a sandbox for copilot |
| `sbx create docker-agent` | Create a sandbox for docker-agent |
| `sbx create gemini` | Create a sandbox for gemini |
| `sbx create kiro` | Create a sandbox for kiro |
| `sbx create opencode` | Create a sandbox for opencode |
| `sbx create shell` | Create a sandbox for shell |

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--branch` |  | Create a Git worktree on the given branch |
| `--cpus` | `0` | Number of CPUs to allocate to the sandbox (0 = auto: N-1 host CPUs, min 1) |
| `-m, --memory` |  | Memory limit in binary units (e.g., 1024m, 8g). Default: 50% of host memory, max 32 GiB |
| `--name` |  | Name for the sandbox (default: <agent>-<workdir>, letters, numbers, hyphens, periods, plus signs and minus signs only) |
| `-q, --quiet` |  | Suppress verbose output |
| `-t, --template` |  | Container image to use for the sandbox (default: agent-specific image) |

## Global options

| Option | Default | Description |
| --- | --- | --- |
| `-D, --debug` |  | Enable debug logging |

## Examples

```
# Create a sandbox for Claude in the current directory
sbx create claude .

# Create a sandbox with a custom name
sbx create --name my-project claude /path/to/project

# Create with additional read-only workspaces
sbx create claude . /path/to/docs:ro

# Create with a Git worktree for isolated changes
sbx create --branch=feature/login claude .
```
