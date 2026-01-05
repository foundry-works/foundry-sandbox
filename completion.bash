# Bash completion for sb (foundry-sandbox)
# Source this file or add to ~/.bashrc.d/

_sb_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    local sandbox_home="${SANDBOX_HOME:-$HOME/.sandboxes}"

    # First argument: commands
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "new list attach start stop destroy build help" -- "$cur"))
        return
    fi

    # Second argument: sandbox names for relevant commands
    case "$prev" in
        attach|start|stop|destroy)
            local sandboxes=""
            if [ -d "$sandbox_home/worktrees" ]; then
                sandboxes=$(ls -1 "$sandbox_home/worktrees" 2>/dev/null)
            fi
            COMPREPLY=($(compgen -W "$sandboxes" -- "$cur"))
            ;;
    esac
}
complete -F _sb_completions sb
