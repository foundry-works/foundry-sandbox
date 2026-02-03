#!/bin/bash

# Terminal colors for guided mode
GREEN='\033[0;32m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
ITALIC='\033[3m'
NC='\033[0m' # No Color

# ============================================================================
# TUI Wrapper Functions (gum with read fallback)
# ============================================================================

# Check if gum is available
has_gum() {
    command -v gum &>/dev/null
}

# Text input with placeholder
tui_input() {
    local placeholder="$1"
    local default="$2"
    if has_gum; then
        gum input --placeholder "$placeholder" --value "$default"
    else
        local result
        read -p "$placeholder: " result
        echo "${result:-$default}"
    fi
}

# Question with hint - friendly questionnaire style
# Note: question/hint go to stderr so they display when called via $(...)
tui_question() {
    local question="$1"
    local hint="$2"
    local default="$3"
    local placeholder="${4:-...}"

    if has_gum; then
        echo "" >&2
        gum style --foreground 255 --bold "  $question" >&2
        [[ -n "$hint" ]] && gum style --foreground 240 --italic "  $hint" >&2
        gum input --placeholder "$placeholder" --value "$default" --width 50
    else
        echo "" >&2
        echo -e "  ${BOLD}$question${NC}" >&2
        [[ -n "$hint" ]] && echo -e "  ${DIM}${ITALIC}$hint${NC}" >&2
        local result
        read -p "  > " result
        echo "${result:-$default}"
    fi
}

# Yes/No confirmation
tui_confirm() {
    local prompt="$1"
    local default="${2:-n}"  # default to no
    if has_gum; then
        if [[ "$default" == "y" ]]; then
            gum confirm --default=yes "$prompt"
        else
            gum confirm "$prompt"
        fi
    else
        local response
        if [[ "$default" == "y" ]]; then
            read -p "$prompt [Y/n]: " response
            [[ ! "$response" =~ ^[nN] ]]
        else
            read -p "$prompt [y/N]: " response
            [[ "$response" =~ ^[yY] ]]
        fi
    fi
}

# Yes/No confirmation with question style (for guided mode)
tui_confirm_question() {
    local question="$1"
    local hint="$2"
    local default="${3:-n}"

    if has_gum; then
        echo ""
        # Show question and hint styled, then minimal confirm prompt
        gum style --foreground 255 --bold "  $question"
        [[ -n "$hint" ]] && gum style --foreground 240 --italic "  $hint"
        if [[ "$default" == "y" ]]; then
            gum confirm --default=yes ""
        else
            gum confirm ""
        fi
    else
        echo ""
        echo -e "  ${BOLD}$question${NC}"
        [[ -n "$hint" ]] && echo -e "  ${DIM}${ITALIC}$hint${NC}"
        local response
        if [[ "$default" == "y" ]]; then
            read -p "  [Y/n]: " response
            [[ ! "$response" =~ ^[nN] ]]
        else
            read -p "  [y/N]: " response
            [[ "$response" =~ ^[yY] ]]
        fi
    fi
}

# Styled header - welcoming message
tui_header() {
    local title="$1"
    if has_gum; then
        gum style --border rounded --padding "0 1" --margin "1 0" \
            --foreground 86 --bold "  $title"
    else
        local width=37
        local title_len=${#title}
        local padding=$((width - 4 - title_len))  # 4 = "│  " + "│"
        [[ $padding -lt 0 ]] && padding=0
        echo ""
        printf "╭%s╮\n" "$(printf '─%.0s' $(seq 1 $((width - 2))))"
        printf "│  ${CYAN}${BOLD}%s${NC}%*s│\n" "$title" "$padding" ""
        printf "╰%s╯\n" "$(printf '─%.0s' $(seq 1 $((width - 2))))"
    fi
}

# Styled summary box - friendly recap
tui_summary() {
    local title="$1"
    local content="$2"
    if has_gum; then
        echo ""
        gum style --foreground 86 --bold "  $title"
        echo "$content" | gum style --border rounded --padding "0 2" --margin "0 2" \
            --foreground 255
    else
        local width=42
        local inner=$((width - 4))  # space for "│  " and "│"
        local title_len=${#title}
        local title_padding=$((inner - title_len))
        [[ $title_padding -lt 0 ]] && title_padding=0
        echo ""
        printf "╭%s╮\n" "$(printf '─%.0s' $(seq 1 $((width - 2))))"
        printf "│  ${CYAN}${BOLD}%s${NC}%*s│\n" "$title" "$title_padding" ""
        printf "├%s┤\n" "$(printf '─%.0s' $(seq 1 $((width - 2))))"
        while IFS= read -r line; do
            local line_len=${#line}
            local line_padding=$((inner - line_len))
            [[ $line_padding -lt 0 ]] && line_padding=0
            printf "│  %s%*s│\n" "$line" "$line_padding" ""
        done <<< "$content"
        printf "╰%s╯\n" "$(printf '─%.0s' $(seq 1 $((width - 2))))"
    fi
}

# Spinner for long-running operations
tui_spin() {
    local title="$1"
    shift
    if has_gum; then
        gum spin --spinner dot --title "$title" -- "$@"
    else
        echo "$title"
        "$@"
    fi
}

# ============================================================================
# Guided Interactive Mode
# ============================================================================

# Guided interactive mode for sandbox creation
guided_new() {
    tui_header "Let's set up your sandbox"

    # 1. Repository (required)
    local repo=""
    while [[ -z "$repo" ]]; do
        repo=$(tui_question \
            "What repo are you working with?" \
            "owner/repo, full URL, or '.' for current directory" \
            "" "owner/repo")
        if [[ -z "$repo" ]]; then
            echo -e "  ${DIM}We need a repo to continue.${NC}"
        fi
    done

    # 2. Branch selection - ask intent first
    local branch=""
    local from_branch=""
    local create_branch=false

    if tui_confirm_question \
        "Create a new branch?" \
        "No = checkout existing, Yes = create new" \
        "y"; then
        # Creating a new branch
        create_branch=true
        branch=$(tui_question \
            "Name for new branch?" \
            "Leave blank to auto-generate" \
            "" "my-new-branch")
        from_branch=$(tui_question \
            "Base it on?" \
            "The existing branch to start from" \
            "main" "main")
    else
        # Checkout existing branch
        branch=$(tui_question \
            "Which branch to checkout?" \
            "Enter the name of an existing branch" \
            "" "main")
    fi

    # 4. Working directory
    local working_dir
    working_dir=$(tui_question \
        "Working directory?" \
        "For monorepos - leave blank for repo root" \
        "" "packages/app")

    # 5. Sparse checkout (only if working_dir set)
    local sparse=false
    if [[ -n "$working_dir" ]]; then
        if tui_confirm_question \
            "Only clone that directory?" \
            "Faster for large repos (sparse checkout)" \
            "n"; then
            sparse=true
        fi
    fi

    # 6. Pip requirements
    local pip_req=""
    if tui_confirm_question \
        "Install Python dependencies?" \
        "From requirements.txt or similar" \
        "n"; then
        pip_req=$(tui_question \
            "Where's your requirements file?" \
            "'auto' to detect automatically" \
            "auto" "requirements.txt")
    fi

    # 7. PR operations
    local allow_pr=false
    if tui_confirm_question \
        "Allow PR operations?" \
        "Create PRs, add comments, request reviews" \
        "n"; then
        allow_pr=true
    fi

    # Build friendly summary
    local branch_display
    if [[ "$create_branch" == true ]]; then
        if [[ -n "$branch" ]]; then
            branch_display="$branch (new, from ${from_branch:-main})"
        else
            branch_display="(auto-generated from ${from_branch:-main})"
        fi
    else
        branch_display="$branch (existing)"
    fi

    local pip_display
    if [[ -n "$pip_req" ]]; then
        pip_display="$pip_req"
    else
        pip_display="no"
    fi

    local pr_display
    if [[ "$allow_pr" == true ]]; then
        pr_display="yes"
    else
        pr_display="no"
    fi

    local summary="Repository    $repo"
    summary+="\nBranch        $branch_display"
    [[ -n "$working_dir" ]] && summary+="\nDirectory     $working_dir"
    [[ "$sparse" == true ]] && summary+="\nSparse clone  yes"
    summary+="\nPython deps   $pip_display"
    summary+="\nPR access     $pr_display"

    tui_summary "Here's what we'll create:" "$(echo -e "$summary")"

    echo ""
    if ! tui_confirm_question "Ready to go?" "" "y"; then
        echo ""
        echo "  Cancelled. Run 'cast new' again when you're ready."
        return 1
    fi

    # Build arguments array
    local args=("$repo")
    [[ -n "$branch" ]] && args+=("$branch")
    [[ -n "$from_branch" ]] && args+=("$from_branch")
    [[ -n "$working_dir" ]] && args+=("--wd" "$working_dir")
    [[ "$sparse" == true ]] && args+=("--sparse")
    [[ -n "$pip_req" ]] && args+=("--pip-requirements" "$pip_req")
    [[ "$allow_pr" == true ]] && args+=("--allow-pr")

    echo ""
    # Call cmd_new with assembled arguments
    cmd_new "${args[@]}"
}

cmd_new() {
    # Detect no-args mode and launch guided wizard
    if [[ $# -eq 0 ]]; then
        guided_new
        return
    fi
    parse_new_args "$@"
    local repo_url="$NEW_REPO_URL"
    local branch="$NEW_BRANCH"
    local from_branch="$NEW_FROM_BRANCH"
    local mounts=("${NEW_MOUNTS[@]}")
    local copies=("${NEW_COPIES[@]}")
    local network_mode="$NEW_NETWORK_MODE"
    local sync_ssh="$NEW_SYNC_SSH"
    local ssh_mode="$NEW_SSH_MODE"
    local skip_key_check="$NEW_SKIP_KEY_CHECK"
    local working_dir="$NEW_WORKING_DIR"
    local sparse_checkout="$NEW_SPARSE_CHECKOUT"
    local pip_requirements="$NEW_PIP_REQUIREMENTS"
    local isolate_credentials="$NEW_ISOLATE_CREDENTIALS"
    local allow_dangerous_mount="$NEW_ALLOW_DANGEROUS_MOUNT"
    local allow_pr="$NEW_ALLOW_PR"
    local ssh_agent_sock=""
    local repo_root=""
    local current_branch=""

    if [ -n "$repo_url" ]; then
        case "$repo_url" in
            .|/*|./*|../*|~/*)
                repo_root=$(git -C "$repo_url" rev-parse --show-toplevel 2>/dev/null || true)
                if [ -z "$repo_root" ]; then
                    die "Not a git repository: $repo_url"
                fi
                current_branch=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
                if [ -z "$current_branch" ] || [ "$current_branch" = "HEAD" ]; then
                    die "Repository is in a detached HEAD state; specify a base branch."
                fi
                if [ -z "$branch" ] && [ -z "$from_branch" ]; then
                    from_branch="$current_branch"
                fi
                local origin_url
                origin_url=$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)
                if [ -n "$origin_url" ]; then
                    repo_url="$origin_url"
                else
                    repo_url="$repo_root"
                fi
                ;;
        esac
    fi

    if [ -z "$branch" ]; then
        local timestamp
        timestamp=$(date +%Y%m%d-%H%M)
        local repo_name
        repo_name=$(basename "${repo_url%.git}" | sed 's/.*\///')
        local user_segment="${USER:-}"
        if [ -z "$user_segment" ]; then
            user_segment=$(id -un 2>/dev/null || true)
        fi
        if [ -z "$user_segment" ]; then
            user_segment=$(whoami 2>/dev/null || true)
        fi
        user_segment=$(sanitize_ref_component "$user_segment")
        local safe_repo_name
        safe_repo_name=$(sanitize_ref_component "$repo_name")
        if [ -z "$user_segment" ]; then
            user_segment="user"
        fi
        if [ -z "$safe_repo_name" ]; then
            safe_repo_name="repo"
        fi
        branch="${user_segment}/${safe_repo_name}-${timestamp}"
        if ! git check-ref-format --branch "$branch" >/dev/null 2>&1; then
            local fallback_branch="${safe_repo_name}-${timestamp}"
            if git check-ref-format --branch "$fallback_branch" >/dev/null 2>&1; then
                branch="$fallback_branch"
            else
                branch="sandbox-${timestamp}"
            fi
        fi
        from_branch="${from_branch:-main}"
    fi

    if [ -z "$repo_url" ]; then
        echo "Usage: $0 new <repo> [branch] [from-branch] [options]"
        echo ""
        echo "Options:"
        echo "  --mount, -v host:container[:ro]  Mount host path into container"
        echo "  --copy, -c  host:container       Copy host path into container (once at creation)"
        echo "  --network, -n <mode>             Network isolation mode (default: limited)"
        echo "                                   Modes: limited, host-only, none"
        echo "  --with-ssh                       Enable SSH agent forwarding (opt-in, agent-only)"
        echo "  --skip-key-check                 Skip API key validation"
        echo "  --wd <path>                      Working directory within repo (relative path)"
        echo "  --sparse                         Enable sparse checkout (requires --wd)"
        echo "  --pip-requirements, -r <path>    Install Python packages from requirements.txt"
        echo "                                   Use 'auto' to detect /workspace/requirements.txt"
        echo "  --no-isolate-credentials         Disable credential isolation (enabled by default)"
        echo "                                   Pass API keys directly to sandbox"
        echo "  --allow-dangerous-mount          Bypass credential directory protection blocklist"
        echo "                                   (dangerous - use only with caution)"
        echo "  --allow-pr, --with-pr            Allow PR operations (create/comment/review)"
        echo "                                   By default, PR operations are blocked"
        echo ""
        echo "Examples:"
        echo "  $0 new user/repo                     # auto-create sandbox branch from main"
        echo "  $0 new .                             # use current repo/branch"
        echo "  $0 new user/repo feature-branch      # checkout existing branch"
        echo "  $0 new user/repo new-feature main    # create new branch from main"
        echo "  $0 new user/repo feature --mount /data:/data --mount /models:/models:ro"
        echo "  $0 new user/repo feature --copy /path/to/models:/models"
        echo "  $0 new user/repo feature --network=limited  # restrict network to whitelist"
        echo "  $0 new user/monorepo feature --wd packages/backend"
        echo "  $0 new user/monorepo feature --wd packages/backend --sparse"
        echo "  $0 new user/repo feature --no-isolate-credentials  # pass keys directly"
        exit 1
    fi

    # Check API keys unless skipped (keys are expected in the environment)
    if [ "$skip_key_check" != "true" ]; then
        if ! check_any_ai_key; then
            # No AI key - prompt to continue
            if ! prompt_missing_keys; then
                die "Sandbox creation cancelled."
            fi
        elif ! check_any_search_key; then
            # AI key present but no search key - just warn
            show_missing_search_keys_warning
        fi
    fi

    # Validate --copy source paths exist before creating anything
    if [ ${#copies[@]} -gt 0 ]; then
        for copy_spec in "${copies[@]}"; do
            local src="${copy_spec%%:*}"
            if [ ! -e "$src" ]; then
                die "Copy source does not exist: $src"
            fi
        done
    fi

    # Validate --wd path
    if [ -n "$working_dir" ]; then
        case "$working_dir" in
            /*) die "Working directory must be relative, not absolute: $working_dir" ;;
            ../*|*/../*) die "Working directory cannot contain parent traversal: $working_dir" ;;
        esac
        working_dir="${working_dir#./}"  # Strip leading ./
    fi

    # Validate --sparse requires --wd
    if [ "$sparse_checkout" = "true" ] && [ -z "$working_dir" ]; then
        die "--sparse requires --wd to specify which directory to include"
    fi

    if [[ "$repo_url" != http* && "$repo_url" != git@* && "$repo_url" != *"://"* && "$repo_url" != /* && "$repo_url" != ./* && "$repo_url" != ../* && "$repo_url" != ~/* ]]; then
        repo_url="https://github.com/$repo_url"
    fi

    validate_git_url "$repo_url"
    check_image_freshness

    SANDBOX_NETWORK_MODE="$network_mode"
    SANDBOX_SYNC_SSH="$sync_ssh"
    SANDBOX_SSH_MODE=""
    if [ "$SANDBOX_SYNC_SSH" = "1" ]; then
        if [ "$ssh_mode" = "init" ] || [ "$ssh_mode" = "disabled" ]; then
            log_warn "SSH mode '$ssh_mode' disables forwarding; use --with-ssh to enable."
            SANDBOX_SYNC_SSH="0"
        else
            SANDBOX_SSH_MODE="always"
        fi
    fi
    if [ "$SANDBOX_SYNC_SSH" != "1" ]; then
        SANDBOX_SSH_MODE="disabled"
    fi
    if [ "$SANDBOX_SYNC_SSH" = "1" ]; then
        ssh_agent_sock=$(resolve_ssh_agent_sock) || ssh_agent_sock=""
    fi

    local bare_path
    bare_path=$(repo_to_path "$repo_url")
    local name
    name=$(sandbox_name "$bare_path" "$branch")
    local worktree_dir
    worktree_dir=$(path_worktree "$name")
    local metadata_path
    local legacy_metadata_path
    metadata_path=$(path_metadata_file "$name")
    legacy_metadata_path=$(path_metadata_legacy_file "$name")
    if [ -f "$metadata_path" ] || [ -f "$legacy_metadata_path" ]; then
        if ! load_sandbox_metadata "$name"; then
            die "Sandbox name collision: existing metadata for '$name' cannot be read."
        fi
        if [ -n "$SANDBOX_REPO_URL" ]; then
            local existing_bare
            existing_bare=$(repo_to_path "$SANDBOX_REPO_URL")
            if [ "$existing_bare" != "$bare_path" ]; then
                die "Sandbox name collision: '$name' already used for $SANDBOX_REPO_URL. Pick a different branch name."
            fi
        fi
    fi
    if dir_exists "$worktree_dir"; then
        local worktree_git="$worktree_dir/.git"
        if [ -f "$worktree_git" ]; then
            local gitdir=""
            gitdir=$(sed -n 's/^gitdir: //p' "$worktree_git" 2>/dev/null || true)
            if [ -n "$gitdir" ]; then
                if [[ "$gitdir" != /* ]]; then
                    gitdir="$worktree_dir/$gitdir"
                fi
                case "$gitdir" in
                    "$bare_path"/*) ;;
                    *)
                        die "Sandbox name collision: '$name' already points to another repo worktree."
                        ;;
                esac
            else
                die "Sandbox name collision: '$name' already exists but is not a sandbox worktree."
            fi
        else
            die "Sandbox name collision: '$name' already exists at $worktree_dir."
        fi
    fi
    local container
    container=$(container_name "$name")

    echo ""
    echo "Setting up your sandbox: $name"

    ensure_bare_repo "$repo_url" "$bare_path"
    local sparse_flag="0"
    if [ "$sparse_checkout" = "true" ]; then
        sparse_flag="1"
    fi
    create_worktree "$bare_path" "$worktree_dir" "$branch" "$from_branch" "$sparse_flag" "$working_dir"

    # Add specs/.backups to worktree gitignore (for foundry spec backups)
    local gitignore_file="$worktree_dir/.gitignore"
    if ! grep -qxF 'specs/.backups' "$gitignore_file" 2>/dev/null; then
        echo 'specs/.backups' >> "$gitignore_file"
    fi

    local claude_config_path
    claude_config_path=$(path_claude_config "$name")
    ensure_dir "$claude_config_path"

    local override_file
    override_file=$(path_override_file "$name")
    local claude_home_path

    # Validate mount paths against dangerous path blocklist
    if [ "$allow_dangerous_mount" != "true" ] && [ ${#mounts[@]} -gt 0 ]; then
        for mount in "${mounts[@]}"; do
            # Extract source path (before first colon)
            local source_path="${mount%%:*}"
            if ! validate_mount_path "$source_path"; then
                echo "Use --allow-dangerous-mount to bypass this check (not recommended)"
                exit 1
            fi
        done
    fi

    if [ ${#mounts[@]} -gt 0 ]; then
        echo "Adding custom mounts..."
        if [ "$allow_dangerous_mount" = "true" ]; then
            echo "WARNING: --allow-dangerous-mount bypasses credential directory protection. Use with caution."
        fi
        cat > "$override_file" <<OVERRIDES
services:
  dev:
    volumes:
OVERRIDES
        for mount in "${mounts[@]}"; do
            echo "      - $mount" >> "$override_file"
        done
    fi

    # Add network mode configuration
    if [ -n "$network_mode" ]; then
        echo "Setting network mode: $network_mode"
        add_network_to_override "$network_mode" "$override_file"
    fi

    claude_home_path=$(path_claude_home "$name")
    ensure_dir "$claude_home_path"
    add_claude_home_to_override "$override_file" "$claude_home_path"
    add_timezone_to_override "$override_file"

    # Pre-populate foundry skills and hooks on host before container starts (no network needed inside)
    prepopulate_foundry_global "$claude_home_path" "0"

    local runtime_enable_ssh="0"
    if [ "$SANDBOX_SYNC_SSH" = "1" ]; then
        if [ -n "$ssh_agent_sock" ]; then
            echo "Enabling SSH agent forwarding..."
            add_ssh_agent_to_override "$override_file" "$ssh_agent_sock"
            runtime_enable_ssh="1"
        else
            log_warn "SSH agent not detected; SSH forwarding disabled (agent-only mode)."
            add_ssh_agent_to_override "$override_file" ""
        fi
    else
        add_ssh_agent_to_override "$override_file" ""
    fi

    write_sandbox_metadata "$name" "$repo_url" "$branch" "$from_branch" "$working_dir" "$sparse_flag" "$pip_requirements" "$allow_pr" "${mounts[@]}" -- "${copies[@]}"

    local container_id="${container}-dev-1"

    # Export gh token if available (needed for macOS keychain)
    if export_gh_token; then
        log_info "GitHub CLI token exported for container"
    fi

    echo "Starting your container..."
    if [ "$isolate_credentials" = "true" ]; then
        echo "Credential isolation enabled - API keys will be held in proxy container"
        # Validate git remotes don't contain embedded credentials
        # This is critical for credential isolation - credentials must go through the gateway
        if ! validate_git_remotes "$worktree_dir/.git"; then
            die "Cannot enable credential isolation with embedded git credentials"
        fi
        # Export ALLOW_PR_OPERATIONS for api-proxy
        if [ "$allow_pr" = "true" ]; then
            export ALLOW_PR_OPERATIONS=true
            echo "PR operations: allowed"
        else
            export ALLOW_PR_OPERATIONS=
            echo "PR operations: blocked (default)"
        fi
    fi
    compose_up "$worktree_dir" "$claude_config_path" "$container" "$override_file" "$isolate_credentials"

    # Setup gateway session for credential isolation
    if [ "$isolate_credentials" = "true" ]; then
        # Get the gateway's host port and set GATEWAY_URL
        if ! setup_gateway_url "$container"; then
            log_error "Failed to get gateway port - gateway container may not be running"
            compose_down "$worktree_dir" "$claude_config_path" "$container" "$override_file" "true" "$isolate_credentials"
            exit 1
        fi

        # Extract repo owner/name from repo_url for session authorization
        local repo_spec
        repo_spec=$(echo "$repo_url" | sed -E 's#^(https?://)?github\.com/##; s#^git@github\.com:##; s#\.git$##')
        if ! setup_gateway_session "$container_id" "$repo_spec"; then
            log_error "Failed to create gateway session - destroying sandbox"
            compose_down "$worktree_dir" "$claude_config_path" "$container" "$override_file" "true" "$isolate_credentials"
            echo ""
            echo "Gateway session creation failed. See error messages above for remediation."
            echo "To create sandbox without credential isolation, use --no-isolate-credentials flag."
            exit 1
        fi
        # Export gateway enabled flag for container_config.sh
        export SANDBOX_GATEWAY_ENABLED=true
    fi

    copy_configs_to_container "$container_id" "0" "$runtime_enable_ssh" "$working_dir" "$isolate_credentials"

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
            # Use tar piping instead of docker cp to avoid read-only rootfs issues
            if [ -d "$src" ]; then
                copy_dir_to_container "$container_id" "$src" "$dst"
            else
                copy_file_to_container "$container_id" "$src" "$dst"
            fi
        done
    fi

    # Install foundry permissions into workspace
    install_workspace_permissions "$container_id"

    # Install Python packages from requirements.txt if specified
    if [ -n "$pip_requirements" ]; then
        install_pip_requirements "$container_id" "$pip_requirements"
    fi

    # Apply network restrictions AFTER plugin/MCP registration completes
    if [ -n "$network_mode" ]; then
        echo "Applying network mode: $network_mode"
        if [ "$network_mode" = "limited" ]; then
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-firewall.sh
        else
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-mode "$network_mode"
        fi
    fi

    echo ""
    echo -e "${CYAN}${BOLD}Your sandbox is ready!${NC}"
    echo ""
    echo "  Sandbox    $name"
    echo "  Worktree   $worktree_dir"
    echo ""
    echo "  Commands:"
    echo "    cast attach $name   - reconnect later"
    echo "    cast stop $name     - pause the sandbox"
    echo "    cast destroy $name  - remove completely"
    echo ""
    if [ -t 0 ]; then
        read -p "Press Enter to launch... "
    fi

    tmux_attach "$name" "$working_dir"
}
