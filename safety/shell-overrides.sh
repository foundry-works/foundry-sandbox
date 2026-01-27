#!/bin/bash
# Safety overrides for dangerous commands (UX LAYER ONLY)
# Installed to /etc/profile.d/ for all bash sessions
#
# NOTE: This is NOT a security boundary. Shell functions can be bypassed via:
#   /bin/rm, command rm, \rm, env rm, etc.
#
# The real security comes from:
#   - Layer 0: Read-only root filesystem (docker-compose.yml: read_only: true)
#   - Layer 2: Strict sudoers allowlist (/etc/sudoers.d/allowlist)
#
# This layer provides friendly "BLOCKED" messages to help a non-adversarial AI
# avoid accidental destructive commands. It is not foolproof.

# =============================================================================
# Generic dangerous command checker - single source of truth for all patterns
# Used by shell wrappers (bash -c, sh -c, eval) to catch bypass attempts
# Returns 0 if dangerous (with description on stdout), 1 if safe
# =============================================================================
_check_dangerous_cmd() {
    local cmd="$1"

    # --- rm patterns ---
    # Short flags: -rf, -fr (combined), or -r...-f / -f...-r (separate)
    # Match -rf or -fr (both flags in same argument)
    if [[ "$cmd" =~ rm[[:space:]].*-[^[:space:]]*r[^[:space:]]*f ]] || \
       [[ "$cmd" =~ rm[[:space:]].*-[^[:space:]]*f[^[:space:]]*r ]]; then
        echo "dangerous rm pattern"
        return 0
    fi
    # Match -r ... -f or -f ... -r (flags in separate arguments)
    if [[ "$cmd" =~ rm[[:space:]].*-[^[:space:]]*r.*[[:space:]]+-[^[:space:]]*f ]] || \
       [[ "$cmd" =~ rm[[:space:]].*-[^[:space:]]*f.*[[:space:]]+-[^[:space:]]*r ]]; then
        echo "dangerous rm pattern"
        return 0
    fi
    # Long options: --recursive --force (any order)
    if [[ "$cmd" =~ rm[[:space:]] ]] && [[ "$cmd" =~ --recursive ]] && [[ "$cmd" =~ --force ]]; then
        echo "dangerous rm pattern (long options)"
        return 0
    fi
    # Mixed: -r --force, --recursive -f
    if [[ "$cmd" =~ rm[[:space:]] ]] && [[ "$cmd" =~ --recursive ]] && [[ "$cmd" =~ -[^-]*f ]]; then
        echo "dangerous rm pattern (mixed)"
        return 0
    fi
    if [[ "$cmd" =~ rm[[:space:]] ]] && [[ "$cmd" =~ --force ]] && [[ "$cmd" =~ -[^-]*r ]]; then
        echo "dangerous rm pattern (mixed)"
        return 0
    fi
    # Catch-all: any rm command is potentially destructive
    if [[ "$cmd" =~ (^|[[:space:]]|[\;\&\|])rm[[:space:]] ]] || [[ "$cmd" =~ (^|[[:space:]]|[\;\&\|])/bin/rm[[:space:]] ]]; then
        echo "rm (file deletion)"
        return 0
    fi

    # --- rsync delete patterns ---
    # rsync --delete removes files in destination that don't exist in source
    if [[ "$cmd" =~ rsync[[:space:]].*--delete ]]; then
        echo "rsync --delete (can remove files)"
        return 0
    fi

    # --- find delete patterns ---
    # find -delete removes matched files
    if [[ "$cmd" =~ find[[:space:]].*-delete ]]; then
        echo "find -delete"
        return 0
    fi
    # find -exec rm - indirect deletion
    if [[ "$cmd" =~ find[[:space:]].*-exec[[:space:]]+(rm|/bin/rm) ]]; then
        echo "find -exec rm"
        return 0
    fi

    # --- git patterns ---
    if [[ "$cmd" =~ git[[:space:]].*reset[[:space:]].*--hard ]]; then
        echo "git reset --hard"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*reset[[:space:]].*--merge ]]; then
        echo "git reset --merge"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*clean[[:space:]].*-[a-zA-Z]*f ]]; then
        echo "git clean -f"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*push[[:space:]].*--force ]] && [[ ! "$cmd" =~ --force-with-lease ]]; then
        echo "git push --force"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*checkout[[:space:]].*-[bB][[:space:]] ]]; then
        echo "git checkout -b (branch switch)"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*checkout[[:space:]].*--[[:space:]] ]]; then
        echo "git checkout -- (discard changes)"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*switch ]]; then
        echo "git switch"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*restore ]] && [[ ! "$cmd" =~ --staged ]]; then
        echo "git restore (discard changes)"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*branch[[:space:]].*-D ]]; then
        echo "git branch -D"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*stash[[:space:]]+(drop|clear) ]]; then
        echo "git stash drop/clear"
        return 0
    fi
    if [[ "$cmd" =~ git[[:space:]].*filter-branch ]]; then
        echo "git filter-branch"
        return 0
    fi

    # --- gh patterns ---
    if [[ "$cmd" =~ gh[[:space:]].*repo[[:space:]].*delete ]]; then
        echo "gh repo delete"
        return 0
    fi
    if [[ "$cmd" =~ gh[[:space:]].*release[[:space:]].*delete ]]; then
        echo "gh release delete"
        return 0
    fi
    if [[ "$cmd" =~ gh[[:space:]].*api[[:space:]] ]] || [[ "$cmd" =~ gh[[:space:]].*api$ ]]; then
        echo "gh api (raw API access)"
        return 0
    fi
    if [[ "$cmd" =~ gh[[:space:]].*secret[[:space:]] ]]; then
        echo "gh secret (secrets access)"
        return 0
    fi
    if [[ "$cmd" =~ gh[[:space:]].*variable[[:space:]] ]]; then
        echo "gh variable (variables access)"
        return 0
    fi

    # --- dd patterns ---
    if [[ "$cmd" =~ dd[[:space:]].*of=/dev/ ]]; then
        echo "dd write to device"
        return 0
    fi

    return 1
}

# =============================================================================
# Path protection helpers
# =============================================================================

# Protected paths that should never be deleted recursively
# Uses resolved absolute paths for comparison
_PROTECTED_PATHS=(
    "/"
    "/bin"
    "/boot"
    "/dev"
    "/etc"
    "/home"
    "/lib"
    "/lib64"
    "/opt"
    "/proc"
    "/root"
    "/run"
    "/sbin"
    "/srv"
    "/sys"
    "/tmp"
    "/usr"
    "/var"
)

# Check if a path is protected (resolves symlinks and variables)
# Returns 0 if protected (with path on stdout), 1 if not protected
_is_protected_path() {
    local path="$1"
    local resolved=""
    local original_abs=""

    # Special handling for . and .. (always dangerous to rm -rf)
    case "$path" in
        .|..)
            echo "$path (current/parent directory)"
            return 0
            ;;
    esac

    # Handle special shell paths
    case "$path" in
        /) resolved="/" ;;
        ~|"$HOME") resolved="$HOME" ;;
        /*)
            # Absolute path - get both original normalized and symlink-resolved
            original_abs=$(realpath -s -m "$path" 2>/dev/null) || original_abs="$path"
            resolved=$(realpath -m "$path" 2>/dev/null) || resolved="$original_abs"
            ;;
        *)
            # Relative path - resolve to absolute
            resolved=$(realpath -m "$path" 2>/dev/null) || resolved="$path"
            original_abs="$resolved"
            ;;
    esac

    # Check against protected paths (check both original and resolved)
    for protected in "${_PROTECTED_PATHS[@]}"; do
        # Check resolved path
        if [[ "$resolved" == "$protected" ]] || [[ "$resolved" == "$protected/" ]]; then
            echo "$resolved"
            return 0
        fi
        # Check original absolute path (for symlinks like /bin -> /usr/bin)
        if [[ "$original_abs" == "$protected" ]] || [[ "$original_abs" == "$protected/" ]]; then
            echo "$original_abs"
            return 0
        fi
    done

    # Check if it's $HOME or a parent of $HOME
    if [[ -n "$HOME" ]]; then
        if [[ "$resolved" == "$HOME" ]] || [[ "$resolved" == "$HOME/" ]]; then
            echo "$resolved"
            return 0
        fi
        # Check if HOME is inside this path (e.g., rm -rf /home deletes all users)
        if [[ "$HOME" == "$resolved"/* ]]; then
            echo "$resolved (contains \$HOME)"
            return 0
        fi
    fi

    return 1
}

# =============================================================================
# Command-specific overrides
# =============================================================================

# Block all rm operations - file deletion requires operator approval
rm() {
    echo "BLOCKED: rm (file deletion)"
    echo "  This operation requires human operator approval."
    return 1
}

# Block dangerous git operations
git() {
    case "$1" in
        reset)
            if [[ "$*" =~ --hard ]]; then
                echo "BLOCKED: git reset --hard destroys all uncommitted changes permanently"
                echo "  Use 'git stash' first."
                return 1
            fi
            if [[ "$*" =~ --merge ]]; then
                echo "BLOCKED: git reset --merge can lose uncommitted changes"
                echo "  Use 'git stash' first."
                return 1
            fi ;;
        clean)
            if [[ "$*" =~ -[a-zA-Z]*f ]]; then
                echo "BLOCKED: git clean -f requires operator approval"
                echo "  This operation requires human operator approval."
                return 1
            fi ;;
        push)
            if [[ "$*" =~ --force ]] && [[ ! "$*" =~ --force-with-lease ]]; then
                echo "BLOCKED: git push --force requires operator approval"
                echo "  Use --force-with-lease instead, or request operator approval."
                return 1
            fi ;;
        checkout)
            # Block branch creation/switching
            if [[ "$*" =~ \ -b\  ]] || [[ "$*" =~ \ -B\  ]]; then
                echo "BLOCKED: git checkout -b (branch creation/switch) is not allowed in this worktree"
                echo "  This sandbox is locked to its current branch."
                return 1
            fi
            # Block file restoration with -- (discards uncommitted changes)
            if [[ "$*" =~ \ --\  ]]; then
                echo "BLOCKED: git checkout -- discards uncommitted changes permanently"
                echo "  Use 'git stash' first, then 'git checkout -- <file>'."
                return 1
            fi
            # Block pathspec-from-file
            if [[ "$*" =~ --pathspec-from-file ]]; then
                echo "BLOCKED: git checkout --pathspec-from-file can overwrite multiple files"
                echo "  Use 'git stash' first."
                return 1
            fi
            # Block git checkout -p (interactive patch discard)
            if [[ "$*" =~ \ -p ]] || [[ "$*" =~ \ --patch ]]; then
                echo "BLOCKED: git checkout -p discards selected changes"
                echo "  Use 'git stash' first."
                return 1
            fi
            # Check remaining args for branch switching vs file restoration
            shift
            for arg in "$@"; do
                [[ "$arg" == -* ]] && continue
                if [[ ! -e "$arg" ]]; then
                    echo "BLOCKED: git checkout <branch> is not allowed in this worktree"
                    echo "  This sandbox is locked to its current branch."
                    return 1
                fi
            done ;;
        switch)
            echo "BLOCKED: git switch is not allowed in this worktree"
            echo "  This sandbox is locked to its current branch."
            return 1 ;;
        restore)
            # Block all git restore (discards changes) except --staged only
            if [[ "$*" =~ --staged ]] && [[ ! "$*" =~ --worktree ]]; then
                : # Allow --staged only (unstage, doesn't discard)
            else
                echo "BLOCKED: git restore discards uncommitted changes"
                echo "  Use 'git stash' first, or use 'git restore --staged' to only unstage."
                return 1
            fi ;;
        branch)
            if [[ "$*" =~ \ -D\  ]] || [[ "$*" =~ \ -D$ ]]; then
                echo "BLOCKED: git branch -D force-deletes without merge check"
                echo "  Use 'git branch -d' for safe delete (checks if merged)."
                return 1
            fi ;;
        stash)
            if [[ "$2" == "drop" ]] || [[ "$2" == "clear" ]]; then
                echo "BLOCKED: git stash $2 permanently deletes stashed changes"
                echo "  Use 'git stash list' to review stashes first."
                return 1
            fi ;;
        worktree)
            if [[ "$2" == "remove" ]] && [[ "$*" =~ --force ]]; then
                echo "BLOCKED: git worktree remove --force can delete uncommitted changes"
                echo "  Remove the --force flag to get a safety check."
                return 1
            fi ;;
        filter-branch)
            echo "BLOCKED: git filter-branch rewrites entire repository history"
            echo "  This operation requires human operator approval."
            return 1 ;;
    esac
    command git "$@"
}

# Block dangerous GitHub CLI operations
gh() {
    case "$1" in
        repo)
            if [[ "$2" == "delete" ]]; then
                echo "BLOCKED: gh repo delete permanently destroys repository"
                echo "  This operation requires human operator approval."
                return 1
            fi ;;
        release)
            if [[ "$2" == "delete" ]]; then
                echo "BLOCKED: gh release delete removes release artifacts"
                echo "  This operation requires human operator approval."
                return 1
            fi ;;
        api)
            echo "BLOCKED: gh api provides raw API access"
            echo "  This operation requires human operator approval."
            return 1 ;;
        secret)
            echo "BLOCKED: gh secret accesses repository secrets"
            echo "  This operation requires human operator approval."
            return 1 ;;
        variable)
            echo "BLOCKED: gh variable accesses repository variables"
            echo "  This operation requires human operator approval."
            return 1 ;;
    esac
    command gh "$@"
}

# =============================================================================
# Shell wrapper interception
# Catches bypass attempts via bash -c, sh -c, eval
# =============================================================================

# Helper to extract -c argument from shell invocation
_extract_c_arg() {
    local next_is_cmd=0
    for arg in "$@"; do
        if [[ $next_is_cmd -eq 1 ]]; then
            echo "$arg"
            return
        fi
        [[ "$arg" == "-c" ]] && next_is_cmd=1
    done
}

bash() {
    if [[ "$*" =~ -c ]]; then
        local cmd_arg
        cmd_arg=$(_extract_c_arg "$@")
        local danger
        if danger=$(_check_dangerous_cmd "$cmd_arg"); then
            echo "BLOCKED: bash -c with $danger detected"
            echo "  Command: $cmd_arg"
            return 1
        fi
    fi
    command bash "$@"
}

sh() {
    if [[ "$*" =~ -c ]]; then
        local cmd_arg
        cmd_arg=$(_extract_c_arg "$@")
        local danger
        if danger=$(_check_dangerous_cmd "$cmd_arg"); then
            echo "BLOCKED: sh -c with $danger detected"
            echo "  Command: $cmd_arg"
            return 1
        fi
    fi
    command sh "$@"
}

eval() {
    local cmd_arg="$*"
    local danger
    if danger=$(_check_dangerous_cmd "$cmd_arg"); then
        echo "BLOCKED: eval with $danger detected"
        echo "  Command: $cmd_arg"
        return 1
    fi
    builtin eval "$@"
}

# Block dangerous dd operations (kept separate for direct dd calls)
dd() {
    if [[ "$*" =~ of=/dev/ ]]; then
        echo "BLOCKED: dd write to device file"
        echo "  This operation requires human operator approval."
        return 1
    fi
    command dd "$@"
}

# =============================================================================
# Credential file warnings
# Warn when reading files that commonly contain secrets
# =============================================================================

# File patterns that commonly contain credentials
_CRED_FILE_PATTERNS=(".env" ".api_keys" ".credentials" "credentials.json" ".secrets" ".netrc" ".npmrc" ".pypirc")

# Check if filename matches credential file patterns
# Returns 0 if it's a credential file (with warning message), 1 if not
_is_credential_file() {
    local filepath="$1"
    local filename
    filename=$(basename "$filepath")

    for pattern in "${_CRED_FILE_PATTERNS[@]}"; do
        if [[ "$filename" == *"$pattern"* ]]; then
            echo "WARNING: Reading potential credential file: $filename" >&2
            echo "  Consider if this file contains sensitive API keys or tokens." >&2
            return 0
        fi
    done
    return 1
}

# Wrap cat to warn when reading credential files
cat() {
    for arg in "$@"; do
        # Skip flags
        [[ "$arg" == -* ]] && continue
        # Check if it's a credential file
        _is_credential_file "$arg" || true
    done
    command cat "$@"
}

export -f _check_dangerous_cmd _is_protected_path _extract_c_arg _is_credential_file rm git gh bash sh eval dd cat
