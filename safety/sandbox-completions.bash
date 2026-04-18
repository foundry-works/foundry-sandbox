# Bash completions for sandbox aliases
# Installed to /etc/bash_completion.d/ in the container

# Complete alias names starting with common prefixes
_sandbox_alias_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local aliases="claudedsp codexdsp reinstall-foundry"
    COMPREPLY=($(compgen -W "$aliases" -- "$cur"))
}

# Register completions for partial typing of sandbox aliases
# This helps with discovering available aliases via tab completion
complete -F _sandbox_alias_completions claudedsp
complete -F _sandbox_alias_completions codexdsp
complete -F _sandbox_alias_completions reinstall-foundry

# Make aliases complete like their underlying commands for arguments
# claudedsp -> claude completions (if available)
if type _claude_completions &>/dev/null; then
    complete -F _claude_completions claudedsp
fi

# codexdsp -> codex completions (if available)
if type _codex_completions &>/dev/null; then
    complete -F _codex_completions codexdsp
fi
