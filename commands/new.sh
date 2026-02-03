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

# Choose from options (single select)
tui_choose() {
    local prompt="$1"
    shift
    local options=("$@")

    if has_gum; then
        printf '%s\n' "${options[@]}" | gum choose --cursor "  > " --cursor-prefix "" --selected-prefix "  > " --unselected-prefix "    "
    else
        # Numbered fallback
        local i=1
        for opt in "${options[@]}"; do
            echo "  $i) $opt"
            ((i++))
        done
        echo ""
        local choice
        read -p "  Select [1]: " choice
        choice="${choice:-1}"

        # Validate input
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#options[@]} ]; then
            choice=1
        fi

        echo "${options[$((choice-1))]}"
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

# Choose from a list of options
tui_choose() {
    local prompt="$1"
    local default="$2"
    shift 2
    local options=("$@")
    if has_gum; then
        if [[ -n "$default" ]]; then
            gum choose --header "$prompt" --selected "$default" "${options[@]}"
        else
            gum choose --header "$prompt" "${options[@]}"
        fi
    else
        echo ""
        echo -e "  ${BOLD}$prompt${NC}"
        local i=1
        for opt in "${options[@]}"; do
            echo "    [$i] $opt"
            i=$((i + 1))
        done
        local choice=""
        while [[ -z "$choice" ]]; do
            read -p "  > " choice
            if [[ -z "$choice" && -n "$default" ]]; then
                echo "$default"
                return
            fi
            if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
                echo "${options[$((choice - 1))]}"
                return
            fi
            choice=""
        done
    fi
}

# Step indicator
tui_step() {
    local step="$1"
    local title="$2"
    if has_gum; then
        gum style --foreground 240 "  Step $step: $title"
    else
        echo -e "  ${DIM}Step $step: $title${NC}"
    fi
}

# Section header
tui_section() {
    local title="$1"
    if has_gum; then
        gum style --border rounded --padding "0 1" --margin "1 0" \
            --foreground 86 --bold "  $title"
    else
        echo ""
        echo -e "  ${CYAN}${BOLD}$title${NC}"
    fi
}

# Divider line
tui_divider() {
    if has_gum; then
        gum style --foreground 240 "----------------------------------------"
    else
        echo "----------------------------------------"
    fi
}

# Summary line formatter
summary_line() {
    local label="$1"
    local value="$2"
    printf "%-12s %s" "$label" "$value"
}

# ============================================================================
# Guided Interactive Mode
# ============================================================================

# Resolve a repo input to URL and optional local info
resolve_repo_input() {
    local input="$1"
    WIZ_REPO_INPUT="$input"
    WIZ_REPO_ROOT=""
    WIZ_REPO_URL=""
    WIZ_REPO_DISPLAY=""
    WIZ_CURRENT_BRANCH=""

    case "$input" in
        .|/*|./*|../*|~/*)
            local repo_root
            repo_root=$(git -C "$input" rev-parse --show-toplevel 2>/dev/null || true)
            if [ -z "$repo_root" ]; then
                return 1
            fi
            WIZ_REPO_ROOT="$repo_root"
            local origin_url
            origin_url=$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)
            if [ -n "$origin_url" ]; then
                WIZ_REPO_URL="$origin_url"
                WIZ_REPO_DISPLAY="$origin_url"
            else
                WIZ_REPO_URL="$repo_root"
                WIZ_REPO_DISPLAY="$repo_root"
            fi
            WIZ_CURRENT_BRANCH=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
            ;;
        *)
            if [[ "$input" == http* || "$input" == git@* || "$input" == *"://"* ]]; then
                WIZ_REPO_URL="$input"
            else
                WIZ_REPO_URL="https://github.com/$input"
            fi
            WIZ_REPO_DISPLAY="$WIZ_REPO_URL"
            ;;
    esac
    return 0
}

relpath() {
    local base="$1"
    local target="$2"
    # Try GNU realpath first (has --relative-to option, not available on macOS BSD)
    local result
    if result=$(realpath --relative-to="$base" "$target" 2>/dev/null); then
        echo "$result"
    else
        # Fallback to Python (use python3 for macOS compatibility)
        python3 - <<'PY' "$base" "$target"
import os, sys
base = sys.argv[1]
target = sys.argv[2]
print(os.path.relpath(target, base))
PY
    fi
}

get_local_branches() {
    local repo_root="$1"
    git -C "$repo_root" for-each-ref --format='%(refname:short)' refs/heads 2>/dev/null
}

wizard_repo() {
    tui_step "1/7" "Repository"
    tui_section "Repository"

    local current_repo_root
    current_repo_root=$(git -C . rev-parse --show-toplevel 2>/dev/null || true)
    if [[ -n "$current_repo_root" ]]; then
        local current_origin
        current_origin=$(git -C "$current_repo_root" remote get-url origin 2>/dev/null || true)
        local current_display="$current_origin"
        [[ -z "$current_display" ]] && current_display="$current_repo_root"
        if tui_confirm_question "Use current repo?" "Detected: $current_display" "y"; then
            if resolve_repo_input "$current_repo_root"; then
                return 0
            else
                echo -e "  ${DIM}Not a git repository: $current_repo_root${NC}"
            fi
        fi
    fi

    while true; do
        local repo_input
        repo_input=$(tui_question \
            "What repo are you working with?" \
            "owner/repo, full URL, local path, or '.'" \
            "" "owner/repo")
        if [[ -z "$repo_input" ]]; then
            echo -e "  ${DIM}We need a repo to continue.${NC}"
            continue
        fi
        if ! resolve_repo_input "$repo_input"; then
            echo -e "  ${DIM}Not a git repository: $repo_input${NC}"
            continue
        fi
        if tui_confirm_question "Use this repo?" "We will use: $WIZ_REPO_DISPLAY" "y"; then
            return 0
        fi
    done
}

wizard_branch() {
    tui_step "2/7" "Branch"
    tui_section "Branch"

    local choice
    choice=$(tui_choose "Branch strategy" "Create new branch" "Create new branch" "Checkout existing branch")
    if [[ "$choice" == "Create new branch" ]]; then
        WIZ_CREATE_BRANCH=true
        while true; do
            WIZ_BRANCH=$(tui_question \
                "Name for new branch?" \
                "Leave blank to auto-generate" \
                "" "my-new-branch")
            if [[ -n "$WIZ_BRANCH" ]]; then
                if git check-ref-format --branch "$WIZ_BRANCH" >/dev/null 2>&1; then
                    break
                fi
                echo -e "  ${DIM}Invalid branch name. Try again.${NC}"
            else
                break
            fi
        done

        local default_base="main"
        [[ -n "$WIZ_CURRENT_BRANCH" && "$WIZ_CURRENT_BRANCH" != "HEAD" ]] && default_base="$WIZ_CURRENT_BRANCH"
        if [[ -n "$WIZ_REPO_ROOT" ]]; then
            local_branches=()
            while IFS= read -r line; do
                [[ -n "$line" ]] && local_branches+=("$line")
            done < <(get_local_branches "$WIZ_REPO_ROOT")
            if [[ ${#local_branches[@]} -gt 0 ]]; then
                local options=("${local_branches[@]}" "Type manually...")
                local base_choice
                base_choice=$(tui_choose "Base it on?" "$default_base" "${options[@]}")
                if [[ "$base_choice" == "Type manually..." ]]; then
                    WIZ_FROM_BRANCH=$(tui_question \
                        "Base it on?" \
                        "The existing branch to start from" \
                        "$default_base" "$default_base")
                else
                    WIZ_FROM_BRANCH="$base_choice"
                fi
            else
                WIZ_FROM_BRANCH=$(tui_question \
                    "Base it on?" \
                    "The existing branch to start from" \
                    "$default_base" "$default_base")
            fi
        else
            WIZ_FROM_BRANCH=$(tui_question \
                "Base it on?" \
                "The existing branch to start from" \
                "$default_base" "$default_base")
        fi
    else
        WIZ_CREATE_BRANCH=false
        if [[ -n "$WIZ_REPO_ROOT" ]]; then
            local_branches=()
            while IFS= read -r line; do
                [[ -n "$line" ]] && local_branches+=("$line")
            done < <(get_local_branches "$WIZ_REPO_ROOT")
            if [[ ${#local_branches[@]} -gt 0 ]]; then
                local options=("${local_branches[@]}" "Type manually...")
                local branch_choice
                branch_choice=$(tui_choose "Which branch to checkout?" "$WIZ_CURRENT_BRANCH" "${options[@]}")
                if [[ "$branch_choice" == "Type manually..." ]]; then
                    while true; do
                        WIZ_BRANCH=$(tui_question \
                            "Which branch to checkout?" \
                            "Enter the name of an existing branch" \
                            "" "main")
                        [[ -n "$WIZ_BRANCH" ]] && break
                        echo -e "  ${DIM}Branch name is required.${NC}"
                    done
                else
                    WIZ_BRANCH="$branch_choice"
                fi
            else
                while true; do
                    WIZ_BRANCH=$(tui_question \
                        "Which branch to checkout?" \
                        "Enter the name of an existing branch" \
                        "" "main")
                    [[ -n "$WIZ_BRANCH" ]] && break
                    echo -e "  ${DIM}Branch name is required.${NC}"
                done
            fi
        else
            while true; do
                WIZ_BRANCH=$(tui_question \
                    "Which branch to checkout?" \
                    "Enter the name of an existing branch" \
                    "" "main")
                [[ -n "$WIZ_BRANCH" ]] && break
                echo -e "  ${DIM}Branch name is required.${NC}"
            done
        fi
        WIZ_FROM_BRANCH=""
    fi
}

wizard_working_dir() {
    tui_step "3/7" "Working directory"
    tui_section "Working directory"

    WIZ_WORKING_DIR=""
    if [[ -n "$WIZ_REPO_ROOT" ]]; then
        local cwd
        cwd=$(pwd)
        local rel
        rel=$(relpath "$WIZ_REPO_ROOT" "$cwd")
        case "$rel" in
            ..|../*|/*) rel="" ;;
        esac
        if [[ -n "$rel" || "$cwd" == "$WIZ_REPO_ROOT" ]]; then
            local rel_display="$rel"
            [[ "$cwd" == "$WIZ_REPO_ROOT" || "$rel" == "." ]] && rel_display="(repo root)"
            if tui_confirm_question "Use current directory as working directory?" "Detected: $rel_display" "y"; then
                if [[ "$rel" == "." || "$rel_display" == "(repo root)" ]]; then
                    WIZ_WORKING_DIR=""
                else
                    WIZ_WORKING_DIR="$rel"
                fi
                return
            fi
        fi
    fi

    while true; do
        local working_dir
        working_dir=$(tui_question \
            "Working directory?" \
            "For monorepos - leave blank for repo root" \
            "" "packages/app")
        if [[ -z "$working_dir" ]]; then
            WIZ_WORKING_DIR=""
            return
        fi
        case "$working_dir" in
            /*) echo -e "  ${DIM}Working directory must be relative.${NC}";;
            ../*|*/../*) echo -e "  ${DIM}Working directory cannot include '..'.${NC}";;
            *)
                if [[ -n "$WIZ_REPO_ROOT" && ! -d "$WIZ_REPO_ROOT/$working_dir" ]]; then
                    echo -e "  ${DIM}Path does not exist in repo: $working_dir${NC}"
                else
                    WIZ_WORKING_DIR="$working_dir"
                    return
                fi
                ;;
        esac
    done
}

wizard_sparse() {
    tui_step "4/7" "Sparse checkout"
    tui_section "Sparse checkout"

    WIZ_SPARSE=false
    if [[ -n "$WIZ_WORKING_DIR" ]]; then
        if tui_confirm_question \
            "Enable sparse checkout?" \
            "Faster/leaner checkout, but repo-wide tools and searches may miss files outside this directory." \
            "n"; then
            WIZ_SPARSE=true
        fi
    fi
}

wizard_deps() {
    tui_step "5/7" "Dependencies"
    tui_section "Dependencies"

    WIZ_PIP_REQ=""
    local choice
    choice=$(tui_choose "Python dependencies" "None" "None" "Auto-detect" "Provide path")
    case "$choice" in
        "None")
            WIZ_PIP_REQ=""
            ;;
        "Auto-detect")
            WIZ_PIP_REQ="auto"
            ;;
        "Provide path")
            while true; do
                local pip_path
                pip_path=$(tui_question \
                    "Where's your requirements file?" \
                    "Host path to requirements.txt or similar" \
                    "requirements.txt" "requirements.txt")
                if [[ -z "$pip_path" ]]; then
                    WIZ_PIP_REQ=""
                    break
                fi
                if [[ "$pip_path" == "~/"* ]]; then
                    pip_path="$HOME/${pip_path#~/}"
                elif [[ "$pip_path" == "$HOME/~/"* ]]; then
                    pip_path="$HOME/${pip_path#"$HOME/~/"}"
                fi
                if [[ "$pip_path" == *"/~/"* ]]; then
                    pip_path="${pip_path//\/~\//\/}"
                fi
                if [[ -e "$pip_path" ]]; then
                    WIZ_PIP_REQ="$pip_path"
                    break
                fi
                echo -e "  ${DIM}File not found: $pip_path${NC}"
            done
            ;;
    esac
}

wizard_pr() {
    tui_step "6/7" "PR access"
    tui_section "PR access"

    WIZ_ALLOW_PR=false
    if tui_confirm_question \
        "Allow PR operations?" \
        "Create PRs, add comments, request reviews. This increases risk; see docs/security/sandbox-threats.md for details." \
        "n"; then
        WIZ_ALLOW_PR=true
    fi
}

wizard_summary() {
    tui_step "7/7" "Review"
    tui_section "Review"

    local action_display
    local branch_display
    if [[ "$WIZ_CREATE_BRANCH" == true ]]; then
        action_display="Create new branch"
        if [[ -n "$WIZ_BRANCH" ]]; then
            branch_display="$WIZ_BRANCH"
        else
            branch_display="(auto-generated)"
        fi
    else
        action_display="Checkout existing"
        branch_display="$WIZ_BRANCH"
    fi

    local pip_display
    if [[ -n "$WIZ_PIP_REQ" ]]; then
        pip_display="$WIZ_PIP_REQ"
    else
        pip_display="no"
    fi

    local pr_display="no"
    [[ "$WIZ_ALLOW_PR" == true ]] && pr_display="yes"

    local dir_display="(repo root)"
    [[ -n "$WIZ_WORKING_DIR" ]] && dir_display="$WIZ_WORKING_DIR"

    local sparse_display="no"
    [[ "$WIZ_SPARSE" == true ]] && sparse_display="yes"

    local lines=()
    lines+=("$(summary_line "Repository" "$WIZ_REPO_DISPLAY")")
    lines+=("$(summary_line "Action" "$action_display")")
    lines+=("$(summary_line "Branch" "$branch_display")")
    [[ "$WIZ_CREATE_BRANCH" == true ]] && lines+=("$(summary_line "Based on" "${WIZ_FROM_BRANCH:-main}")")
    lines+=("$(summary_line "Directory" "$dir_display")")
    lines+=("$(summary_line "Sparse clone" "$sparse_display")")
    lines+=("$(summary_line "Python deps" "$pip_display")")
    lines+=("$(summary_line "PR access" "$pr_display")")

    local summary
    summary=$(printf "%s\n" "${lines[@]}")
    tui_summary "Here's what we'll create:" "$summary"
}

# Guided interactive mode for sandbox creation
guided_new() {
    tui_header "Let's set up your sandbox"

    wizard_repo
    wizard_branch
    wizard_working_dir
    wizard_sparse
    wizard_deps
    wizard_pr

    while true; do
        wizard_summary
        local next
        next=$(tui_choose "Next step" "Create sandbox" "Create sandbox" "Edit answers" "Cancel")
        case "$next" in
            "Create sandbox")
                break
                ;;
            "Cancel")
                echo ""
                echo "  Cancelled. Run 'cast new' again when you're ready."
                return 1
                ;;
            "Edit answers")
                local edit
                edit=$(tui_choose "What do you want to edit?" "" \
                    "Repository" "Branch" "Working directory" "Dependencies" "PR access")
                case "$edit" in
                    "Repository")
                        wizard_repo
                        wizard_branch
                        wizard_working_dir
                        wizard_sparse
                        ;;
                    "Branch")
                        wizard_branch
                        ;;
                    "Working directory")
                        wizard_working_dir
                        wizard_sparse
                        ;;
                    "Dependencies")
                        wizard_deps
                        ;;
                    "PR access")
                        wizard_pr
                        ;;
                esac
                ;;
        esac
    done

    # Build the equivalent command line for future use
    local cmd_line="cast new $repo"
    if [[ "$create_branch" == true ]]; then
        # New branch: cast new repo [branch] [from_branch]
        [[ -n "$branch" ]] && cmd_line+=" $branch"
        [[ -n "$from_branch" ]] && cmd_line+=" $from_branch"
    else
        # Existing branch: cast new repo branch
        [[ -n "$branch" ]] && cmd_line+=" $branch"
    fi
    [[ -n "$working_dir" ]] && cmd_line+=" --wd $working_dir"
    [[ "$sparse" == true ]] && cmd_line+=" --sparse"
    [[ -n "$pip_req" ]] && cmd_line+=" --pip-requirements $pip_req"
    [[ "$allow_pr" == true ]] && cmd_line+=" --allow-pr"

    echo ""
    echo -e "  ${DIM}To repeat this setup:${NC}"
    echo -e "  ${DIM}cast new --last${NC}"
    echo -e "  ${DIM}or: $cmd_line${NC}"

    # Build arguments array
    local args=("$WIZ_REPO_INPUT")
    [[ -n "$WIZ_BRANCH" ]] && args+=("$WIZ_BRANCH")
    [[ -n "$WIZ_FROM_BRANCH" ]] && args+=("--from" "$WIZ_FROM_BRANCH")
    [[ -n "$WIZ_WORKING_DIR" ]] && args+=("--wd" "$WIZ_WORKING_DIR")
    [[ "$WIZ_SPARSE" == true ]] && args+=("--sparse")
    [[ -n "$WIZ_PIP_REQ" ]] && args+=("--pip-requirements" "$WIZ_PIP_REQ")
    [[ "$WIZ_ALLOW_PR" == true ]] && args+=("--allow-pr")

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

    # Handle --last flag: load last cast new args
    if [ "$NEW_USE_LAST" = "true" ]; then
        if ! load_last_cast_new; then
            exit 1
        fi
        echo ""
        echo "Repeating last command:"
        echo "  $LAST_COMMAND_LINE"
        echo ""
    fi

    # Handle --preset flag: load named preset
    if [ -n "$NEW_USE_PRESET" ]; then
        if ! load_cast_preset "$NEW_USE_PRESET"; then
            exit 1
        fi
        echo ""
        echo "Using preset '$NEW_USE_PRESET':"
        echo "  $LAST_COMMAND_LINE"
        echo ""
    fi

    # Store save-as name before it gets overwritten
    local save_as_preset="$NEW_SAVE_AS"
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
    local enable_opencode="$NEW_ENABLE_OPENCODE"
    local enable_zai="$NEW_ENABLE_ZAI"
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
        echo "  --from <branch>                  Base branch for new branch creation"
        echo "  --mount, -v host:container[:ro]  Mount host path into container"
        echo "  --copy, -c  host:container       Copy host path into container (once at creation)"
        echo "  --network, -n <mode>             Network isolation mode (default: limited)"
        echo "                                   Modes: limited, host-only, none"
        echo "  --with-ssh                       Enable SSH agent forwarding (opt-in, agent-only)"
        echo "  --with-opencode                  Enable OpenCode setup (requires host auth file)"
        echo "  --with-zai                       Enable ZAI Claude alias (requires ZHIPU_API_KEY)"
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
        echo "  $0 new user/repo feature --with-opencode  # enable OpenCode setup"
        echo "  $0 new user/repo feature --with-zai  # enable ZAI Claude alias"
        exit 1
    fi

    # Opt-in tool enablement (default off)
    SANDBOX_ENABLE_OPENCODE="0"
    SANDBOX_ENABLE_ZAI="0"
    if [ "$enable_opencode" = "true" ]; then
        if has_opencode_key; then
            SANDBOX_ENABLE_OPENCODE="1"
        else
            log_warn "OpenCode requested but auth file not found; skipping OpenCode setup."
            log_warn "Run 'opencode auth login' or re-run with --with-opencode after configuring ~/.local/share/opencode/auth.json."
        fi
    fi
    if [ "$enable_zai" = "true" ]; then
        if has_zai_key; then
            SANDBOX_ENABLE_ZAI="1"
        else
            log_warn "ZAI requested but ZHIPU_API_KEY not set; skipping ZAI setup."
        fi
    fi
    export SANDBOX_ENABLE_OPENCODE SANDBOX_ENABLE_ZAI
    if [ "${SANDBOX_ENABLE_ZAI}" != "1" ]; then
        export ZHIPU_API_KEY=
    fi

    # Check API keys unless skipped (keys are expected in the environment)
    if [ "$skip_key_check" != "true" ]; then
        # Claude is mandatory
        if ! check_claude_key_required; then
            die "Sandbox creation cancelled - Claude authentication required."
        fi
        # All CLI status shown in Configuration section via show_cli_status()
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

    # Check network capacity before creating resources
    if ! check_docker_network_capacity "$isolate_credentials"; then
        exit 1
    fi

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

    # Auto-generate unique name for cast repeat to allow multiple sandboxes
    if [ "$NEW_USE_LAST" = "true" ] || [ -n "$NEW_USE_PRESET" ]; then
        local original_name="$name"
        name=$(find_next_sandbox_name "$name")

        # If sandbox name got a suffix, apply the same suffix to the branch
        if [ "$name" != "$original_name" ]; then
            local suffix="${name#$original_name}"
            branch="${branch}${suffix}"
        fi
    fi

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
    log_section "Repository"

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

    log_section "Configuration"

    if [ ${#mounts[@]} -gt 0 ]; then
        log_step "Custom mounts added"
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
        log_step "Network mode: $network_mode"
        add_network_to_override "$network_mode" "$override_file"
    fi

    claude_home_path=$(path_claude_home "$name")
    ensure_dir "$claude_home_path"
    add_claude_home_to_override "$override_file" "$claude_home_path"
    add_timezone_to_override "$override_file"

    # Pre-populate foundry skills and hooks on host before container starts (no network needed inside)
    prepopulate_foundry_global "$claude_home_path" "0"

    # Show detected CLI configurations
    show_cli_status

    local runtime_enable_ssh="0"
    if [ "$SANDBOX_SYNC_SSH" = "1" ]; then
        if [ -n "$ssh_agent_sock" ]; then
            log_step "SSH agent forwarding: enabled"
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
    export_gh_token

    log_section "Container"
    log_step "Starting container..."
    if [ "$isolate_credentials" = "true" ]; then
        log_step "Credential isolation: enabled"
        if [ ! -f "$HOME/.codex/auth.json" ]; then
            log_warn "Credential isolation: ~/.codex/auth.json not found; Codex CLI will not work."
            log_warn "Run 'codex auth' to create it if you plan to use Codex."
        fi
        if [ "$enable_opencode" != "true" ] && [ ! -f "$HOME/.local/share/opencode/auth.json" ]; then
            log_warn "Credential isolation: ~/.local/share/opencode/auth.json not found; OpenCode CLI will not work."
            log_warn "Run 'opencode auth login' to create it if you plan to use OpenCode."
        fi
        if [ ! -f "$HOME/.gemini/oauth_creds.json" ] && [ -z "${GEMINI_API_KEY:-}" ]; then
            log_warn "Credential isolation: ~/.gemini/oauth_creds.json not found and GEMINI_API_KEY not set; Gemini CLI will not work."
            log_warn "Run 'gemini auth' or set GEMINI_API_KEY if you plan to use Gemini."
        fi
        # Validate git remotes don't contain embedded credentials
        # This is critical for credential isolation - credentials must go through the gateway
        if ! validate_git_remotes "$worktree_dir/.git"; then
            die "Cannot enable credential isolation with embedded git credentials"
        fi
        # Export ALLOW_PR_OPERATIONS for api-proxy
        if [ "$allow_pr" = "true" ]; then
            export ALLOW_PR_OPERATIONS=true
            log_step "PR operations: allowed"
        else
            export ALLOW_PR_OPERATIONS=
            log_step "PR operations: blocked (default)"
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
        if [ "$network_mode" = "limited" ]; then
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-firewall.sh
        else
            run_cmd docker exec "$container_id" sudo /usr/local/bin/network-mode "$network_mode"
        fi
    fi

    # Save last cast new args for --last flag
    local sparse_for_save="false"
    [ "$sparse_checkout" = "true" ] && sparse_for_save="true"
    local allow_pr_for_save="false"
    [ "$allow_pr" = "true" ] && allow_pr_for_save="true"
    local enable_opencode_for_save="false"
    [ "$enable_opencode" = "true" ] && enable_opencode_for_save="true"
    local enable_zai_for_save="false"
    [ "$enable_zai" = "true" ] && enable_zai_for_save="true"

    save_last_cast_new "$repo_url" "$branch" "$from_branch" "$working_dir" \
        "$sparse_for_save" "$pip_requirements" "$allow_pr_for_save" "$network_mode" \
        "$sync_ssh" "$enable_opencode_for_save" "$enable_zai_for_save" \
        "${mounts[@]}" -- "${copies[@]}"

    # Save as last attached for cast reattach
    save_last_attach "$name"

    # Save as named preset if --save-as was specified
    if [ -n "$save_as_preset" ]; then
        save_cast_preset "$save_as_preset" "$repo_url" "$branch" "$from_branch" "$working_dir" \
            "$sparse_for_save" "$pip_requirements" "$allow_pr_for_save" "$network_mode" \
            "$sync_ssh" "$enable_opencode_for_save" "$enable_zai_for_save" \
            "${mounts[@]}" -- "${copies[@]}"
    fi

    echo ""
    echo -e "${GREEN}✓${NC} ${BOLD}Your sandbox is ready!${NC}"
    echo ""
    echo "  Sandbox    $name"
    echo "  Worktree   $worktree_dir"
    echo ""
    echo "  Commands:"
    echo "    cast attach $name   - reconnect later"
    echo "    cast reattach       - reconnect (auto-detects sandbox in worktree)"
    echo "    cast stop $name     - pause the sandbox"
    echo "    cast destroy $name  - remove completely"
    echo "    cast repeat         - repeat this setup"
    echo ""
    echo "  This command:"
    echo "    $LAST_COMMAND_LINE"
    echo ""

    # IDE launch logic
    local with_ide="$NEW_WITH_IDE"
    local ide_only="$NEW_IDE_ONLY"
    local skip_terminal=false

    if [ -t 0 ]; then
        if [ "$with_ide" = "none" ]; then
            # --no-ide: skip IDE prompt entirely
            read -p "Press Enter to launch... "
        elif [ -n "$with_ide" ] && [ "$with_ide" != "auto" ]; then
            # Specific IDE requested via --with-ide=<name> or --ide-only=<name>
            if auto_launch_ide "$with_ide" "$worktree_dir"; then
                if [ "$ide_only" = "true" ]; then
                    skip_terminal=true
                    echo ""
                    echo "IDE launched. Run 'cast attach $name' for terminal."
                else
                    read -p "Press Enter to launch terminal... "
                fi
            else
                # IDE launch failed, fall back to terminal
                read -p "Press Enter to launch... "
            fi
        elif [ -n "$with_ide" ]; then
            # --with-ide or --ide-only without specific name: prompt for selection
            prompt_ide_selection "$worktree_dir" "$name"
            if [ "$ide_only" = "true" ] || [ "$IDE_WAS_LAUNCHED" = "true" ]; then
                skip_terminal=true
                echo ""
                echo "  Run this in your IDE's terminal to connect:"
                echo ""
                echo "    cast attach $name"
                echo ""
            else
                read -p "Press Enter to launch terminal... "
            fi
        else
            # Default: offer IDE selection if any available
            prompt_ide_selection "$worktree_dir" "$name"
            if [ "$IDE_WAS_LAUNCHED" = "true" ]; then
                echo ""
                echo "  Run this in your IDE's terminal to connect:"
                echo ""
                echo "    cast attach $name"
                echo ""
                skip_terminal=true
            else
                read -p "Press Enter to launch terminal... "
            fi
        fi
    fi

    if [ "$skip_terminal" = "false" ]; then
        tmux_attach "$name" "$working_dir"
    fi
}
