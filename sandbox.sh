#!/bin/bash

# AI Dev Sandbox - Ephemeral worktree-based development environments

set -e

SANDBOX_HOME="${SANDBOX_HOME:-$HOME/.sandboxes}"
REPOS_DIR="$SANDBOX_HOME/repos"
WORKTREES_DIR="$SANDBOX_HOME/worktrees"
CLAUDE_CONFIGS_DIR="$SANDBOX_HOME/claude-config"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Export UID/GID/username for docker-compose
export DOCKER_UID=$(id -u)
export DOCKER_GID=$(id -g)
export HOST_USER=$(whoami)

# Ensure directories exist
mkdir -p "$REPOS_DIR" "$WORKTREES_DIR" "$CLAUDE_CONFIGS_DIR"
mkdir -p "$HOME/GitHub/_bikelane"

# Check if image needs rebuilding (Dockerfile newer than image)
check_image_freshness() {
    # Get Dockerfile modification time (Linux: -c %Y, macOS: -f %m)
    local dockerfile_time
    dockerfile_time=$(stat -c %Y "$SCRIPT_DIR/Dockerfile" 2>/dev/null) || \
    dockerfile_time=$(stat -f %m "$SCRIPT_DIR/Dockerfile" 2>/dev/null) || return 0

    # Get image creation time as Unix timestamp
    local image_created
    image_created=$(docker inspect ai-dev-sandbox:latest --format '{{.Created}}' 2>/dev/null) || {
        echo ""
        echo "⚠ Sandbox image not found."
        read -p "Build image now? [Y/n] " rebuild
        if [[ ! "$rebuild" =~ ^[Nn]$ ]]; then
            cmd_build
        fi
        return 0
    }

    # Parse ISO 8601 timestamp to Unix timestamp
    local image_time
    image_time=$(date -d "$image_created" +%s 2>/dev/null) || \
    image_time=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${image_created%%.*}" +%s 2>/dev/null) || return 0

    # If Dockerfile is newer than image
    if [ "$dockerfile_time" -gt "$image_time" ]; then
        echo ""
        echo "⚠ Dockerfile has changed since the image was built."
        read -p "Rebuild image now? [Y/n] " rebuild
        if [[ ! "$rebuild" =~ ^[Nn]$ ]]; then
            cmd_build
        fi
    fi
}

# Copy config files into container
copy_configs_to_container() {
    local container_id="$1"

    echo "Copying config files into container..."

    # Create necessary directories
    docker exec "$container_id" mkdir -p \
        /home/ubuntu/.claude \
        /home/ubuntu/.config/gh \
        /home/ubuntu/.config/ccstatusline \
        /home/ubuntu/.gemini \
        /home/ubuntu/.config/opencode \
        /home/ubuntu/.local/share/opencode \
        /home/ubuntu/.cursor \
        /home/ubuntu/.codex \
        /home/ubuntu/.ssh

    # Claude CLI config (per-sandbox copy)
    [ -d "$CLAUDE_CONFIG_PATH" ] && docker cp "$CLAUDE_CONFIG_PATH"/. "$container_id:/home/ubuntu/.claude/"

    # GitHub CLI auth
    [ -d ~/.config/gh ] && docker cp ~/.config/gh/. "$container_id:/home/ubuntu/.config/gh/"

    # ccstatusline config (for custom Claude statusline layouts)
    [ -d ~/.config/ccstatusline ] && docker cp ~/.config/ccstatusline/. "$container_id:/home/ubuntu/.config/ccstatusline/"

    # Gemini CLI
    [ -d ~/.gemini ] && docker cp ~/.gemini/. "$container_id:/home/ubuntu/.gemini/"

    # OpenCode config and auth
    [ -d ~/.config/opencode ] && docker cp ~/.config/opencode/. "$container_id:/home/ubuntu/.config/opencode/"
    [ -f ~/.local/share/opencode/auth.json ] && docker cp ~/.local/share/opencode/auth.json "$container_id:/home/ubuntu/.local/share/opencode/auth.json"

    # Cursor CLI config
    [ -d ~/.cursor ] && docker cp ~/.cursor/. "$container_id:/home/ubuntu/.cursor/"

    # Codex CLI config
    [ -d ~/.codex ] && docker cp ~/.codex/. "$container_id:/home/ubuntu/.codex/"

    # Git config
    [ -f ~/.gitconfig ] && docker cp ~/.gitconfig "$container_id:/home/ubuntu/.gitconfig"

    # SSH keys
    [ -d ~/.ssh ] && docker cp ~/.ssh/. "$container_id:/home/ubuntu/.ssh/"

    # API keys file
    [ -f ~/.api_keys ] && docker cp ~/.api_keys "$container_id:/home/ubuntu/.api_keys"

    # Git bare repos (for worktree support)
    [ -d ~/.sandboxes/repos ] && {
        docker exec "$container_id" mkdir -p "/home/ubuntu/.sandboxes"
        docker cp ~/.sandboxes/repos/. "$container_id:/home/ubuntu/.sandboxes/repos/"
    }

    # Fix ownership and permissions (single exec for speed)
    echo "Fixing ownership..."
    docker exec "$container_id" sh -c '
        chown -R ubuntu:ubuntu \
            /home/ubuntu/.claude \
            /home/ubuntu/.config \
            /home/ubuntu/.gemini \
            /home/ubuntu/.cursor \
            /home/ubuntu/.codex \
            /home/ubuntu/.ssh \
            /home/ubuntu/.sandboxes \
            /home/ubuntu/.local/share/opencode \
            2>/dev/null
        chown ubuntu:ubuntu /home/ubuntu/.gitconfig /home/ubuntu/.api_keys 2>/dev/null
        chmod 700 /home/ubuntu/.ssh 2>/dev/null
        chmod 600 /home/ubuntu/.ssh/* 2>/dev/null
    ' || true
}

# Cross-platform sed in-place edit (GNU vs BSD)
sed_inplace() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# Convert repo URL to bare clone path
# e.g., https://github.com/user/repo -> ~/.sandboxes/repos/github.com/user/repo.git
repo_to_path() {
    local url="$1"
    # Remove protocol
    local path="${url#https://}"
    path="${path#git@}"
    # Convert git@github.com:user/repo to github.com/user/repo
    path="${path/://}"
    # Remove .git suffix if present, we'll add it back
    path="${path%.git}"
    echo "$REPOS_DIR/${path}.git"
}

# Get sandbox name from repo and branch
sandbox_name() {
    local repo_path="$1"
    local branch="$2"
    local repo_name=$(basename "$repo_path" .git)
    # Sanitize: replace / with - for Docker compatibility
    local safe_branch="${branch//\//-}"
    echo "${repo_name}-${safe_branch}"
}

# Get container name
container_name() {
    echo "sandbox-$1"
}

# Get tmux session name (just use sandbox name directly)
tmux_session_name() {
    echo "$1"
}

# Create or attach to tmux session for sandbox
tmux_attach() {
    local name="$1"
    local container=$(container_name "$name")
    local session=$(tmux_session_name "$name")

    # Check if session already exists
    if tmux has-session -t "$session" 2>/dev/null; then
        echo "Attaching to existing tmux session: $session"
        tmux attach-session -t "$session"
    else
        echo "Creating tmux session: $session"
        tmux new-session -s "$session" -c "$WORKTREES_DIR/$name" \
            "docker exec -it ${container}-dev-1 bash; echo 'Container exited. Press enter to close.'; read"
    fi
}

cmd_new() {
    local repo_url=""
    local branch=""
    local from_branch=""
    local mounts=()
    local copies=()

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --mount|-v)
                shift
                [ -n "$1" ] && mounts+=("$1")
                ;;
            --copy|-c)
                shift
                [ -n "$1" ] && copies+=("$1")
                ;;
            *)
                # Positional args: repo, branch, from_branch
                if [ -z "$repo_url" ]; then
                    repo_url="$1"
                elif [ -z "$branch" ]; then
                    branch="$1"
                elif [ -z "$from_branch" ]; then
                    from_branch="$1"
                fi
                ;;
        esac
        shift
    done

    # If no branch specified, auto-generate a sandbox branch name from main
    if [ -z "$branch" ]; then
        local timestamp=$(date +%Y%m%d-%H%M)
        local repo_name=$(basename "${repo_url%.git}" | sed 's/.*\///')
        branch="sandbox/${repo_name}-${timestamp}"
        from_branch="main"
    fi

    if [ -z "$repo_url" ]; then
        echo "Usage: $0 new <repo> [branch] [from-branch] [options]"
        echo ""
        echo "Options:"
        echo "  --mount, -v host:container[:ro]  Mount host path into container"
        echo "  --copy, -c  host:container       Copy host path into container (once at creation)"
        echo ""
        echo "Examples:"
        echo "  $0 new user/repo                     # auto-create sandbox branch from main"
        echo "  $0 new user/repo feature-branch      # checkout existing branch"
        echo "  $0 new user/repo new-feature main    # create new branch from main"
        echo "  $0 new user/repo feature --mount /data:/data --mount /models:/models:ro"
        echo "  $0 new user/repo feature --copy /path/to/models:/models"
        exit 1
    fi

    # Shorthand: user/repo -> https://github.com/user/repo
    if [[ "$repo_url" != http* && "$repo_url" != git@* ]]; then
        repo_url="https://github.com/$repo_url"
    fi

    # Check if image needs rebuilding before proceeding
    check_image_freshness

    local bare_path=$(repo_to_path "$repo_url")
    local name=$(sandbox_name "$bare_path" "$branch")
    local worktree_path="$WORKTREES_DIR/$name"
    local container=$(container_name "$name")

    echo "Creating sandbox: $name"

    # Clone bare repo if it doesn't exist
    if [ ! -d "$bare_path" ]; then
        echo "Cloning bare repo to $bare_path..."
        mkdir -p "$(dirname "$bare_path")"
        git clone --bare "$repo_url" "$bare_path"
    else
        echo "Bare repo exists, fetching latest..."
        git -C "$bare_path" fetch --all --prune
    fi

    # Create worktree if it doesn't exist
    if [ ! -d "$worktree_path" ]; then
        if [ -n "$from_branch" ]; then
            # Create new branch from base
            echo "Creating new branch '$branch' from '$from_branch'..."
            # Ensure we have the base branch
            git -C "$bare_path" fetch origin "$from_branch:$from_branch" 2>/dev/null || true
            git -C "$bare_path" worktree add -b "$branch" "$worktree_path" "$from_branch"
        else
            # Checkout existing branch
            echo "Creating worktree for branch: $branch..."
            if ! git -C "$bare_path" worktree add "$worktree_path" "$branch" 2>/dev/null; then
                echo "Branch not found locally, fetching..."
                git -C "$bare_path" fetch origin "$branch:$branch" 2>/dev/null || \
                git -C "$bare_path" fetch origin "refs/heads/$branch:refs/heads/$branch"
                git -C "$bare_path" worktree add "$worktree_path" "$branch"
            fi
        fi
    else
        echo "Worktree already exists at $worktree_path"
        echo "Pulling latest changes..."
        if git -C "$worktree_path" diff --quiet && git -C "$worktree_path" diff --cached --quiet; then
            git -C "$worktree_path" pull --ff-only || echo "Warning: Could not fast-forward. You may need to pull manually."
        else
            echo "Warning: Uncommitted changes detected. Skipping pull."
        fi
    fi

    # Create Claude config (auth, settings, and plugins)
    local claude_config_path="$CLAUDE_CONFIGS_DIR/$name"
    if [ ! -d "$claude_config_path" ]; then
        echo "Setting up Claude config for sandbox..."
        mkdir -p "$claude_config_path"
        cp "$HOME/.claude/.claude.json" "$claude_config_path/" 2>/dev/null || true
        cp "$HOME/.claude/settings.json" "$claude_config_path/" 2>/dev/null || true
        cp "$HOME/.claude/settings.local.json" "$claude_config_path/" 2>/dev/null || true
        cp "$HOME/.claude/.credentials.json" "$claude_config_path/" 2>/dev/null || true
        cp -rL "$HOME/.claude/plugins" "$claude_config_path/" 2>/dev/null || true
        # Fix plugin paths for container (host path -> container path)
        for f in "$claude_config_path/plugins/installed_plugins.json" "$claude_config_path/plugins/known_marketplaces.json"; do
            [ -f "$f" ] && sed_inplace "s|$HOME/.claude|/home/ubuntu/.claude|g" "$f"
        done
    fi

    # Create docker-compose override file if custom mounts specified
    local override_file="$claude_config_path/docker-compose.override.yml"
    if [ ${#mounts[@]} -gt 0 ]; then
        echo "Adding custom mounts..."
        cat > "$override_file" <<EOF
services:
  dev:
    volumes:
EOF
        for mount in "${mounts[@]}"; do
            echo "      - $mount" >> "$override_file"
        done
    fi

    # Start container
    echo "Starting container: $container..."
    export WORKSPACE_PATH="$worktree_path"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    export CONTAINER_NAME="$container"
    local compose_cmd="docker compose -f $SCRIPT_DIR/docker-compose.yml"
    [ -f "$override_file" ] && compose_cmd="$compose_cmd -f $override_file"
    $compose_cmd -p "$container" up -d

    # Copy config files into container
    local container_id="${container}-dev-1"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    copy_configs_to_container "$container_id"

    # Copy files into container if --copy was specified
    if [ ${#copies[@]} -gt 0 ]; then
        echo "Copying files into container..."
        for copy_spec in "${copies[@]}"; do
            local src="${copy_spec%%:*}"
            local dst="${copy_spec#*:}"
            if [ ! -e "$src" ]; then
                echo "  Warning: Source '$src' does not exist, skipping"
                continue
            fi
            echo "  $src -> $dst"
            # Create parent directory in container
            docker exec "$container_id" mkdir -p "$(dirname "$dst")"
            docker cp "$src" "$container_id:$dst"
        done
    fi

    echo ""
    echo "Sandbox '$name' is ready!"
    echo "  Attach:  $0 attach $name"
    echo "  Stop:    $0 stop $name"
    echo "  Destroy: $0 destroy $name"
    echo ""

    # Create and attach to tmux session
    tmux_attach "$name"
}

cmd_list() {
    echo "Sandboxes:"
    echo ""

    # List worktrees and their container status
    for worktree in "$WORKTREES_DIR"/*/; do
        [ -d "$worktree" ] || continue
        local name=$(basename "$worktree")
        local container=$(container_name "$name")
        local session=$(tmux_session_name "$name")
        local status=$(docker ps -a --filter "name=^${container}-dev" --format "{{.Status}}" 2>/dev/null | head -1)
        local tmux_status=""

        if [ -z "$status" ]; then
            status="no container"
        fi

        if tmux has-session -t "$session" 2>/dev/null; then
            tmux_status=" [tmux]"
        fi

        printf "  %-30s %s%s\n" "$name" "$status" "$tmux_status"
    done
}

cmd_attach() {
    local name="$1"

    # If no name provided, use fzf to pick one
    if [ -z "$name" ]; then
        if command -v fzf &>/dev/null && [ -d "$WORKTREES_DIR" ]; then
            name=$(ls -1 "$WORKTREES_DIR" 2>/dev/null | fzf --prompt="Select sandbox: " --height=10 --reverse)
            if [ -z "$name" ]; then
                echo "No sandbox selected."
                exit 1
            fi
        else
            echo "Usage: $0 attach <sandbox-name>"
            echo ""
            cmd_list
            exit 1
        fi
    fi

    local worktree_path="$WORKTREES_DIR/$name"
    local container=$(container_name "$name")

    if [ ! -d "$worktree_path" ]; then
        echo "Error: Sandbox '$name' not found"
        cmd_list
        exit 1
    fi

    # Check if container is running
    local container_id="${container}-dev-1"
    if ! docker ps --filter "name=^${container}-dev" --format "{{.Names}}" | grep -q .; then
        echo "Container not running. Starting..."
        cmd_start "$name"
    else
        # Sync credentials into running container (tokens may have been refreshed)
        local claude_config_path="$CLAUDE_CONFIGS_DIR/$name"
        cp "$HOME/.claude/.credentials.json" "$claude_config_path/" 2>/dev/null || true
        docker cp "$claude_config_path/.credentials.json" "$container_id:/home/ubuntu/.claude/.credentials.json" 2>/dev/null || true

        # Sync other credentials that may have changed
        [ -d ~/.codex ] && docker cp ~/.codex/. "$container_id:/home/ubuntu/.codex/" 2>/dev/null
        [ -d ~/.config/gh ] && docker cp ~/.config/gh/. "$container_id:/home/ubuntu/.config/gh/" 2>/dev/null
        [ -d ~/.gemini ] && docker cp ~/.gemini/. "$container_id:/home/ubuntu/.gemini/" 2>/dev/null
        [ -d ~/.config/opencode ] && docker cp ~/.config/opencode/. "$container_id:/home/ubuntu/.config/opencode/" 2>/dev/null
        [ -f ~/.local/share/opencode/auth.json ] && docker cp ~/.local/share/opencode/auth.json "$container_id:/home/ubuntu/.local/share/opencode/auth.json" 2>/dev/null
        [ -d ~/.cursor ] && docker cp ~/.cursor/. "$container_id:/home/ubuntu/.cursor/" 2>/dev/null
        [ -f ~/.api_keys ] && docker cp ~/.api_keys "$container_id:/home/ubuntu/.api_keys" 2>/dev/null
    fi

    # Attach via tmux session
    tmux_attach "$name"
}

cmd_stop() {
    local name="$1"

    if [ -z "$name" ]; then
        echo "Usage: $0 stop <sandbox-name>"
        exit 1
    fi

    local worktree_path="$WORKTREES_DIR/$name"
    local container=$(container_name "$name")
    local session=$(tmux_session_name "$name")
    local claude_config_path="$CLAUDE_CONFIGS_DIR/$name"
    local override_file="$claude_config_path/docker-compose.override.yml"

    echo "Stopping sandbox: $name..."

    # Kill tmux session if it exists
    tmux kill-session -t "$session" 2>/dev/null || true

    export WORKSPACE_PATH="$worktree_path"
    export CONTAINER_NAME="$container"
    local compose_cmd="docker compose -f $SCRIPT_DIR/docker-compose.yml"
    [ -f "$override_file" ] && compose_cmd="$compose_cmd -f $override_file"
    $compose_cmd -p "$container" down
}

cmd_start() {
    local name="$1"

    if [ -z "$name" ]; then
        echo "Usage: $0 start <sandbox-name>"
        exit 1
    fi

    local worktree_path="$WORKTREES_DIR/$name"
    local container=$(container_name "$name")
    local claude_config_path="$CLAUDE_CONFIGS_DIR/$name"

    if [ ! -d "$worktree_path" ]; then
        echo "Error: Sandbox '$name' not found"
        exit 1
    fi

    # Check if image needs rebuilding before starting
    check_image_freshness

    # Ensure Claude config exists (auth, settings, and plugins)
    if [ ! -d "$claude_config_path" ]; then
        echo "Setting up Claude config for sandbox..."
        mkdir -p "$claude_config_path"
        cp "$HOME/.claude/.claude.json" "$claude_config_path/" 2>/dev/null || true
        cp "$HOME/.claude/settings.json" "$claude_config_path/" 2>/dev/null || true
        cp "$HOME/.claude/settings.local.json" "$claude_config_path/" 2>/dev/null || true
        cp "$HOME/.claude/.credentials.json" "$claude_config_path/" 2>/dev/null || true
        cp -rL "$HOME/.claude/plugins" "$claude_config_path/" 2>/dev/null || true
        # Fix plugin paths for container (host path -> container path)
        for f in "$claude_config_path/plugins/installed_plugins.json" "$claude_config_path/plugins/known_marketplaces.json"; do
            [ -f "$f" ] && sed_inplace "s|$HOME/.claude|/home/ubuntu/.claude|g" "$f"
        done
    fi

    # Always sync credentials (tokens may have been refreshed on host)
    cp "$HOME/.claude/.credentials.json" "$claude_config_path/" 2>/dev/null || true

    echo "Starting sandbox: $name..."
    export WORKSPACE_PATH="$worktree_path"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    export CONTAINER_NAME="$container"
    local override_file="$claude_config_path/docker-compose.override.yml"
    local compose_cmd="docker compose -f $SCRIPT_DIR/docker-compose.yml"
    [ -f "$override_file" ] && compose_cmd="$compose_cmd -f $override_file"
    $compose_cmd -p "$container" up -d

    # Copy config files into container
    local container_id="${container}-dev-1"
    copy_configs_to_container "$container_id"
}

cmd_destroy() {
    local name=""
    local keep_worktree=false
    local force=false

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --keep-worktree) keep_worktree=true ;;
            -f|--force) force=true ;;
            *) [ -z "$name" ] && name="$1" ;;
        esac
        shift
    done

    if [ -z "$name" ]; then
        echo "Usage: $0 destroy <sandbox-name> [--keep-worktree] [-f|--force]"
        exit 1
    fi

    local worktree_path="$WORKTREES_DIR/$name"
    local container=$(container_name "$name")
    local session=$(tmux_session_name "$name")
    local claude_config_path="$CLAUDE_CONFIGS_DIR/$name"

    # Confirm destruction unless --force is used
    if [ "$force" = false ]; then
        echo "This will destroy sandbox '$name' including:"
        echo "  - Docker container and volumes"
        [ "$keep_worktree" = false ] && echo "  - Worktree at $worktree_path"
        [ "$keep_worktree" = false ] && echo "  - Claude config at $claude_config_path"
        echo ""
        read -p "Are you sure? [y/N] " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "Aborted."
            exit 0
        fi
    fi

    echo "Destroying sandbox: $name..."

    # Kill tmux session if it exists
    tmux kill-session -t "$session" 2>/dev/null || true

    # Stop and remove container
    export WORKSPACE_PATH="$worktree_path"
    export CLAUDE_CONFIG_PATH="$claude_config_path"
    export CONTAINER_NAME="$container"
    local override_file="$claude_config_path/docker-compose.override.yml"
    local compose_cmd="docker compose -f $SCRIPT_DIR/docker-compose.yml"
    [ -f "$override_file" ] && compose_cmd="$compose_cmd -f $override_file"
    $compose_cmd -p "$container" down -v 2>/dev/null || true

    # Remove Claude config directory
    if [ "$keep_worktree" = false ] && [ -d "$claude_config_path" ]; then
        echo "Removing Claude config..."
        rm -rf "$claude_config_path"
    fi

    # Remove worktree
    if [ "$keep_worktree" = false ] && [ -d "$worktree_path" ]; then
        echo "Removing worktree..."
        # Find the bare repo and remove worktree properly
        local git_dir=$(git -C "$worktree_path" rev-parse --git-dir 2>/dev/null)
        if [ -n "$git_dir" ]; then
            local bare_path=$(dirname "$(dirname "$git_dir")")
            git -C "$bare_path" worktree remove "$worktree_path" --force 2>/dev/null || rm -rf "$worktree_path"
        else
            rm -rf "$worktree_path"
        fi
    fi

    echo "Sandbox '$name' destroyed."
}

cmd_build() {
    local no_cache=""
    if [ "$1" = "--no-cache" ]; then
        no_cache="--no-cache"
    fi
    echo "Building sandbox image..."
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" build $no_cache
}

cmd_help() {
    echo "AI Dev Sandbox - Ephemeral worktree-based development environments"
    echo ""
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  new <repo> [branch] [from] [--mount|-v src:dst] [--copy|-c src:dst]
                            Create new sandbox from repo/branch"
    echo "  list                      List all sandboxes"
    echo "  attach <name>             Attach to a sandbox"
    echo "  start <name>              Start a stopped sandbox"
    echo "  stop <name>               Stop a sandbox (keeps worktree)"
    echo "  destroy <name> [-f]       Destroy sandbox and worktree (confirms first)"
    echo "  build                     Build/rebuild the sandbox image"
    echo "  help                      Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 new user/repo                      # checkout main"
    echo "  $0 new user/repo feature-branch       # checkout existing branch"
    echo "  $0 new user/repo my-feature main      # new branch from main"
    echo "  $0 new user/repo feat --mount /data:/data  # with extra mount"
    echo "  $0 new user/repo feat --copy ~/models:/models  # copy into container"
    echo "  $0 attach repo-feature-branch"
    echo "  $0 list"
}

# Main command dispatch
case "${1:-help}" in
    new)     shift; cmd_new "$@" ;;
    list)    cmd_list ;;
    attach)  shift; cmd_attach "$@" ;;
    start)   shift; cmd_start "$@" ;;
    stop)    shift; cmd_stop "$@" ;;
    destroy) shift; cmd_destroy "$@" ;;
    build)   cmd_build ;;
    help|--help|-h) cmd_help ;;
    *)
        echo "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
