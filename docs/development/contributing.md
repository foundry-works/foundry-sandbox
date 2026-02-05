# Contributing Guide

This guide covers how to contribute to Foundry Sandbox.

## Code Organization

```
foundry-sandbox/
├── sandbox.sh              # Main entry point
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Container runtime config
├── entrypoint.sh           # Container startup script
├── completion.bash         # Bash tab completion
│
├── lib/                    # Library modules
│   ├── constants.sh        # Global variables and defaults
│   ├── utils.sh            # General helper functions
│   ├── fs.sh               # Filesystem operations
│   ├── format.sh           # Output formatting
│   ├── validate.sh         # Input validation
│   ├── api_keys.sh         # API key management
│   ├── args.sh             # Argument parsing
│   ├── prompt.sh           # User prompts
│   ├── git.sh              # Git operations
│   ├── git_worktree.sh     # Worktree management
│   ├── docker.sh           # Docker/compose helpers
│   ├── image.sh            # Image management
│   ├── host_config.sh      # Host-side config
│   ├── container_config.sh # Container config
│   ├── tmux.sh             # Tmux session management
│   ├── paths.sh            # Path derivation
│   ├── state.sh            # Sandbox state management
│   ├── runtime.sh          # Runtime operations
│   ├── ide.sh              # IDE integration (Cursor, Zed, VS Code)
│   ├── json.sh             # JSON output helpers
│   ├── inspect.sh          # Sandbox inspection
│   ├── network.sh          # Network configuration
│   ├── permissions.sh      # Permission management
│   └── proxy.sh            # Unified proxy registration (container lifecycle)
│
├── commands/               # Command implementations
│   ├── new.sh              # cast new
│   ├── attach.sh           # cast attach
│   ├── list.sh             # cast list
│   ├── start.sh            # cast start
│   ├── stop.sh             # cast stop
│   ├── destroy.sh          # cast destroy
│   ├── destroy-all.sh      # cast destroy-all
│   ├── build.sh            # cast build
│   ├── status.sh           # cast status
│   ├── config.sh           # cast config
│   ├── prune.sh            # cast prune
│   ├── info.sh             # cast info
│   ├── preset.sh           # cast preset
│   ├── refresh-credentials.sh # cast refresh-credentials
│   ├── upgrade.sh          # cast upgrade
│   └── help.sh             # cast help
│
├── safety/                     # Security guardrails
│   ├── credential-redaction.sh # Credential masking
│   ├── operator-approve        # Human approval wrapper
│   ├── sudoers-allowlist       # Sudo restrictions
│   ├── network-firewall.sh     # Network isolation rules
│   └── network-mode            # Network mode switcher
│
├── tests/                  # Test suite
│
└── docs/                   # Documentation (you are here)
```

## Adding a New Command

### 1. Create the Command File

Create `commands/mycommand.sh`:

```bash
#!/bin/bash

cmd_mycommand() {
    local arg1="$1"
    local json_output=false

    # Parse options
    while [ $# -gt 0 ]; do
        case "$1" in
            --json) json_output=true ;;
            *) [ -z "$arg1" ] && arg1="$1" ;;
        esac
        shift
    done

    # Validate
    if [ -z "$arg1" ]; then
        echo "Usage: $0 mycommand <arg>"
        exit 1
    fi

    # Implementation
    echo "Running mycommand with: $arg1"
}
```

### 2. Register in sandbox.sh

Edit `sandbox.sh` to add the command to the case statement:

```bash
case "$cmd" in
    new|list|attach|start|stop|destroy|build|help|status|config|prune|info|upgrade|preset|mycommand)
        source "$SCRIPT_DIR/commands/$cmd.sh"
        "cmd_$cmd" "$@"
        ;;
    refresh-credentials)
        source "$SCRIPT_DIR/commands/refresh-credentials.sh"
        cmd_refresh_credentials "$@"
        ;;
    destroy-all)
        source "$SCRIPT_DIR/commands/destroy-all.sh"
        cmd_destroy_all "$@"
        ;;
    ...
esac
```

### 3. Update Help

Edit `commands/help.sh` to document the new command:

```bash
echo "  mycommand <arg>        Description of what it does"
```

### 4. Add Bash Completion

Edit `completion.bash` to add completion for the new command:

```bash
local commands="new list attach start stop destroy destroy-all build help status config prune info preset refresh-credentials upgrade mycommand"
```

## Adding a Library Module

### 1. Create the Module

Create `lib/mymodule.sh`:

```bash
#!/bin/bash

# mymodule.sh - Brief description
#
# Functions:
#   my_function - What it does

my_function() {
    local input="$1"
    # Implementation
    echo "result"
}
```

### 2. Source in sandbox.sh

Add to the source block in `sandbox.sh`:

```bash
source "$SCRIPT_DIR/lib/mymodule.sh"
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
./sandbox.sh build

# Create a test sandbox
./sandbox.sh new owner/repo test-branch

# Test your changes
./sandbox.sh mycommand arg

# Clean up
./sandbox.sh destroy repo-test-branch --yes
```

### Debug Mode

```bash
# Enable debug output
SANDBOX_DEBUG=1 ./sandbox.sh mycommand arg

# Enable verbose output
SANDBOX_VERBOSE=1 ./sandbox.sh mycommand arg
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

### Bash Conventions

```bash
# Use lowercase for local variables
local my_variable="value"

# Use UPPERCASE for exported/global variables
export MY_CONSTANT="value"

# Quote variables to prevent word splitting
echo "$my_variable"

# Use [[ ]] for conditionals (bash-specific, safer)
if [[ "$var" == "value" ]]; then
    ...
fi

# Use $() for command substitution (not backticks)
result=$(some_command)
```

### Function Naming

```bash
# Commands: cmd_<name>
cmd_mycommand() { ... }

# Library functions: descriptive_name
validate_git_url() { ... }
derive_sandbox_paths() { ... }

# Internal helpers: _prefixed
_helper_function() { ... }
```

### Error Handling

```bash
# Use set -e at script top (already set in sandbox.sh)
set -e

# For functions that shouldn't exit on error
some_command || true

# Provide helpful error messages
if [ ! -f "$file" ]; then
    echo "Error: File not found: $file" >&2
    exit 1
fi
```

### Output Conventions

```bash
# Use format_* functions for consistent output
format_header "Section Title"
format_kv "Key" "$value"

# Errors go to stderr
echo "Error: something went wrong" >&2

# Support JSON output where appropriate
if [ "$json_output" = true ]; then
    printf '{"key":"%s"}\n' "$value"
else
    format_kv "Key" "$value"
fi
```

## Documentation

When adding features:

1. Update relevant docs in `docs/`
2. Add examples to `docs/usage/commands.md`
3. Update `docs/usage/workflows.md` if it enables new patterns
4. Update `commands/help.sh` with usage info

## Pull Request Process

1. Create a feature branch
2. Make your changes
3. Test manually
4. Update documentation
5. Submit PR with clear description

## Questions?

Open an issue on GitHub for discussion.
