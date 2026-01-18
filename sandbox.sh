#!/bin/bash

# AI Dev Sandbox - Ephemeral worktree-based development environments

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

source "$SCRIPT_DIR/lib/constants.sh"
source "$SCRIPT_DIR/lib/utils.sh"
source "$SCRIPT_DIR/lib/fs.sh"
source "$SCRIPT_DIR/lib/format.sh"
source "$SCRIPT_DIR/lib/validate.sh"
source "$SCRIPT_DIR/lib/api_keys.sh"
source "$SCRIPT_DIR/lib/args.sh"
source "$SCRIPT_DIR/lib/prompt.sh"
source "$SCRIPT_DIR/lib/git.sh"
source "$SCRIPT_DIR/lib/git_worktree.sh"
source "$SCRIPT_DIR/lib/docker.sh"
source "$SCRIPT_DIR/lib/image.sh"
source "$SCRIPT_DIR/lib/host_config.sh"
source "$SCRIPT_DIR/lib/container_config.sh"
source "$SCRIPT_DIR/lib/tmux.sh"
source "$SCRIPT_DIR/lib/paths.sh"
source "$SCRIPT_DIR/lib/state.sh"
source "$SCRIPT_DIR/lib/runtime.sh"
source "$SCRIPT_DIR/lib/json.sh"
source "$SCRIPT_DIR/lib/inspect.sh"
source "$SCRIPT_DIR/lib/network.sh"
source "$SCRIPT_DIR/commands/build.sh"

export_docker_env
validate_environment

cmd="${1:-help}"
shift 2>/dev/null || true

case "$cmd" in
    new|list|attach|start|stop|destroy|build|help|status|config|prune|info)
        source "$SCRIPT_DIR/commands/$cmd.sh"
        "cmd_$cmd" "$@"
        ;;
    destroy-all)
        source "$SCRIPT_DIR/commands/destroy-all.sh"
        cmd_destroy_all "$@"
        ;;
    --help|-h)
        source "$SCRIPT_DIR/commands/help.sh"
        cmd_help
        ;;
    *)
        die "Unknown command: $cmd"
        ;;
esac
