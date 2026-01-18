# Bash completion for cast (foundry-sandbox)
# Source this file or add to ~/.bashrc.d/

_cast_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    local sandbox_home="${SANDBOX_HOME:-$HOME/.sandboxes}"
    local cmd="${COMP_WORDS[1]}"

    # First argument: commands
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "new list attach start stop destroy build help status config prune info" -- "$cur"))
        return
    fi

    # Path completion for mount/copy args
    case "$prev" in
        --mount|-v|--copy|-c)
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
    esac

    # Flag completion by command
    case "$cmd" in
        new)
            COMPREPLY=($(compgen -W "--mount -v --copy -c" -- "$cur"))
            ;;
        destroy)
            COMPREPLY=($(compgen -W "--keep-worktree --force -f --yes -y" -- "$cur"))
            ;;
        list|status|config|info)
            COMPREPLY=($(compgen -W "--json" -- "$cur"))
            ;;
        prune)
            COMPREPLY=($(compgen -W "--json --force -f" -- "$cur"))
            ;;
        build)
            COMPREPLY=($(compgen -W "--no-cache" -- "$cur"))
            ;;
    esac

    # Second argument: sandbox names for relevant commands
    case "$prev" in
        attach|start|stop|destroy|status)
            local sandboxes=""
            if [ -d "$sandbox_home/worktrees" ]; then
                sandboxes=$(ls -1 "$sandbox_home/worktrees" 2>/dev/null)
            fi
            COMPREPLY=($(compgen -W "$sandboxes" -- "$cur"))
            ;;
    esac
}
complete -F _cast_completions cast
