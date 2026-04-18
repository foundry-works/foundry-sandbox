# Contributing Guide

This guide covers how to contribute to Foundry Sandbox.

## Code Organization

```
foundry-sandbox/
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Container runtime config
├── entrypoint.sh           # Container startup script (user)
├── entrypoint-root.sh      # Root wrapper (credential isolation)
├── install.sh              # Installation script
├── completion.bash         # Bash tab completion
├── pyproject.toml          # Python package definition (entry point: cast)
│
├── foundry_sandbox/        # Python package (orchestration layer)
│   ├── cli.py              # Click CLI group with alias resolution
│   ├── constants.py        # Configuration defaults
│   ├── config.py           # JSON config I/O utilities
│   ├── models.py           # Pydantic data models
│   ├── paths.py            # Path resolution (SandboxPaths)
│   ├── utils.py            # Logging/formatting helpers
│   ├── docker.py           # Docker/compose operations
│   ├── git.py              # Git operations with retry
│   ├── git_worktree.py     # Worktree management
│   ├── state.py            # Metadata persistence (JSON, atomic writes)
│   ├── network.py          # Docker network configuration
│   ├── proxy.py            # Unified proxy registration
│   ├── validate.py         # Input validation
│   ├── credential_setup.py # Container credential provisioning
│   ├── container_io.py     # Container I/O primitives
│   ├── container_setup.py  # Container setup orchestration
│   ├── tool_configs.py     # Tool configuration (Claude, Codex, etc.)
│   ├── foundry_plugin.py   # Foundry MCP plugin setup
│   ├── permissions.py      # Workspace permission rules
│   └── commands/           # Click command implementations
│       ├── new.py          # cast new
│       ├── attach.py       # cast attach
│       ├── list_cmd.py     # cast list
│       ├── destroy.py      # cast destroy
│       └── ...             # Other commands
│
├── unified-proxy/          # Credential isolation proxy
│   ├── addons/             # mitmproxy addons
│   ├── branch_isolation.py # Cross-sandbox branch isolation
│   ├── git_operations.py   # Sandboxed git command execution
│   ├── git_policies.py     # Protected branch enforcement
│   ├── git_api.py          # Git API TCP server (port 8083)
│   └── ...
│
├── safety/                 # Security controls
│   ├── sudoers-allowlist   # Sudo command restrictions
│   ├── network-firewall.sh # iptables rules
│   └── ...
│
├── tests/                  # Test suite
│
└── docs/                   # Documentation (you are here)
```

## Adding a New Command

### 1. Create the Command Module

Create `foundry_sandbox/commands/mycommand.py`:

```python
"""cast mycommand — Brief description."""

import click

from foundry_sandbox.cli import cli


@cli.command()
@click.argument("name")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
def mycommand(name: str, json_output: bool) -> None:
    """Brief description of what it does."""
    click.echo(f"Running mycommand with: {name}")
```

### 2. Register in cli.py

Import the command module in `foundry_sandbox/cli.py` so Click discovers it:

```python
from foundry_sandbox.commands import mycommand  # noqa: F401
```

### 3. Add Bash Completion

Edit `completion.bash` to add the new command name:

```bash
local commands="new list attach start stop destroy ... mycommand"
```

## Adding a Library Module

### 1. Create the Module

Create `foundry_sandbox/mymodule.py`:

```python
"""Brief description of the module."""


def my_function(input_value: str) -> str:
    """What it does."""
    return f"result: {input_value}"
```

### 2. Use It

Import from your command or other modules:

```python
from foundry_sandbox.mymodule import my_function
```

## Modifying Safety Layers

### Sudoers Allowlist

Edit `safety/sudoers-allowlist` to permit new sudo commands:

```
# Allow specific command
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/specific-command *
```

Rebuild the image after changes: `cast build`

## Testing Changes

### Manual Testing

```bash
# Rebuild image with your changes
cast build

# Create a test sandbox
cast new owner/repo test-branch

# Test your changes
cast mycommand arg

# Clean up
cast destroy repo-test-branch --yes
```

### Debug Mode

```bash
# Enable debug output
SANDBOX_DEBUG=1 cast mycommand arg

# Enable verbose output
SANDBOX_VERBOSE=1 cast mycommand arg
```

### Testing Inside Container

```bash
# Get a shell in the container
cast attach mybox

# Test read-only filesystem
rm -rf /  # Should fail with "Read-only file system"

# Test sudoers
sudo apt-get update  # Should work
sudo rm /tmp/x  # Should fail
```

## Style Guidelines

### Python Conventions

- Use [ruff](https://docs.astral.sh/ruff/) for linting and formatting
- Use type annotations (enforced by `mypy --strict`)
- Use `click` for CLI argument parsing
- Use Pydantic models for structured data
- Use `pathlib.Path` over `os.path`
- Prefer `subprocess.run()` with explicit args over shell=True

### Naming

```python
# Modules: snake_case
container_setup.py

# Classes: PascalCase
class SandboxPaths: ...

# Functions/variables: snake_case
def validate_git_url(url: str) -> bool: ...

# Constants: UPPER_SNAKE_CASE
DEFAULT_NETWORK_MODE = "limited"
```

### Error Handling

```python
# Use click.echo for user-facing output
click.echo("Running command...")

# Errors go to stderr
click.echo("Error: something went wrong", err=True)

# Use sys.exit for fatal errors
import sys
sys.exit(1)
```

## Documentation

When adding features:

1. Update relevant docs in `docs/`
2. Add examples to `docs/usage/commands.md`
3. Update `docs/usage/workflows.md` if it enables new patterns

## Pull Request Process

1. Create a feature branch
2. Make your changes
3. Test manually
4. Update documentation
5. Submit PR with clear description

## Questions?

Open an issue on GitHub for discussion.
