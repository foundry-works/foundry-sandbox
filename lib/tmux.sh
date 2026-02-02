#!/bin/bash

tmux_session_exists() {
    local session="$1"
    tmux has-session -t "$session" 2>/dev/null
}

tmux_create_session() {
    local session="$1"
    local worktree_path="$2"
    local container="$3"
    local working_dir="${4:-}"
    local exec_cmd="bash"
    if [ -n "$working_dir" ]; then
        exec_cmd="bash -c 'cd /workspace/$working_dir 2>/dev/null; exec bash'"
    fi
    local scrollback="${SANDBOX_TMUX_SCROLLBACK:-200000}"
    local mouse="${SANDBOX_TMUX_MOUSE:-1}"

    # Use -u to run as the sandbox user (not root, even though container starts as root for DNS setup)
    tmux new-session -d -s "$session" -c "$worktree_path" \
        "docker exec -u ${CONTAINER_USER:-ubuntu} -it ${container}-dev-1 $exec_cmd; echo 'Container exited. Press enter to close.'; read"
    tmux set-option -t "$session" history-limit "$scrollback" 2>/dev/null || true
    if [ "$mouse" = "1" ]; then
        tmux set-option -t "$session" mouse on 2>/dev/null || true
    else
        tmux set-option -t "$session" mouse off 2>/dev/null || true
    fi
    exec tmux attach-session -t "$session"
}

tmux_attach_session() {
    local session="$1"
    tmux attach-session -t "$session"
}

# Create or attach to tmux session for sandbox
tmux_attach() {
    local name="$1"
    local working_dir="${2:-}"
    local container
    container=$(container_name "$name")
    local session
    session=$(tmux_session_name "$name")

    if tmux_session_exists "$session"; then
        log_info "Attaching to existing tmux session: $session"
        tmux_attach_session "$session"
    else
        log_info "Creating tmux session: $session"
        tmux_create_session "$session" "$WORKTREES_DIR/$name" "$container" "$working_dir"
    fi
}

# Get tmux session name (just use sandbox name directly)
tmux_session_name() {
    echo "$1"
}
