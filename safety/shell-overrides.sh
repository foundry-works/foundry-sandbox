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
# Generic dangerous command checker
# Used by shell wrappers (bash -c, sh -c, eval) to catch bypass attempts
# Returns 0 if dangerous (with description on stdout), 1 if safe
# =============================================================================
_check_dangerous_cmd() {
    local cmd="$1"

    # File deletion commands
    [[ "$cmd" =~ (^|[[:space:]\;\&\|])(rm|/bin/rm)[[:space:]] ]] && { echo "rm"; return 0; }
    [[ "$cmd" =~ rsync[[:space:]].*--delete ]] && { echo "rsync --delete"; return 0; }
    [[ "$cmd" =~ find[[:space:]].*(-delete|-exec[[:space:]]+(rm|/bin/rm)) ]] && { echo "find delete"; return 0; }

    # Dangerous git operations (local - can't enforce at gateway)
    [[ "$cmd" =~ git[[:space:]].*(reset[[:space:]]+--(hard|merge)|clean[[:space:]]+-[a-zA-Z]*f) ]] && { echo "git destructive"; return 0; }
    [[ "$cmd" =~ git[[:space:]].*(checkout[[:space:]]+(-[bB]|--)|switch|filter-branch) ]] && { echo "git branch/history"; return 0; }
    [[ "$cmd" =~ git[[:space:]].*restore ]] && [[ ! "$cmd" =~ --staged ]] && { echo "git restore"; return 0; }
    [[ "$cmd" =~ git[[:space:]].*(branch[[:space:]]+-D|stash[[:space:]]+(drop|clear)) ]] && { echo "git destructive"; return 0; }

    # Device writes
    [[ "$cmd" =~ dd[[:space:]].*of=/dev/ ]] && { echo "dd device write"; return 0; }

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

# Block dangerous git operations and redact credentials from config output
# NOTE: _redact_output is provided by credential-redaction.sh (also in profile.d)
git() {
    case "$1" in
        config)
            # Redact credentials from git config output (URLs may contain tokens)
            command git "$@" | _redact_output
            return ;;
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
_CRED_FILE_PATTERNS=(".env" ".api_keys" ".credentials" "credentials.json" ".secrets" ".netrc" ".npmrc" ".pypirc", "auth.json", "creds.json")

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

export -f _check_dangerous_cmd _extract_c_arg _is_credential_file rm git bash sh eval dd cat
