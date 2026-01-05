#!/bin/bash

# Source API keys if available
if [ -f "$HOME/.api_keys" ]; then
    source "$HOME/.api_keys"
fi

# CLI tools are pre-installed in the image
# To update manually: npm update -g @anthropic-ai/claude-code @google/gemini-cli @openai/codex opencode-ai

# Plugins are copied from host by sandbox.sh, no installation needed

# Ensure Claude onboarding is marked complete
CLAUDE_JSON="$HOME/.claude/.claude.json"
if [ -f "$CLAUDE_JSON" ]; then
    if ! grep -q '"hasCompletedOnboarding": true' "$CLAUDE_JSON"; then
        echo "Setting hasCompletedOnboarding in Claude config..."
        tmp=$(mktemp)
        jq '. + {"hasCompletedOnboarding": true}' "$CLAUDE_JSON" > "$tmp" && mv "$tmp" "$CLAUDE_JSON"
    fi
else
    # Create minimal config if it doesn't exist
    mkdir -p "$HOME/.claude"
    echo '{"hasCompletedOnboarding": true}' > "$CLAUDE_JSON"
fi

# Fix git worktree paths for container environment
# Worktrees have a .git file (not directory) pointing to the bare repo
if [ -f /workspace/.git ] && [ -n "$HOST_USER" ]; then
    # Fix the worktree's .git reference (host path -> container path)
    if grep -q "/home/$HOST_USER" /workspace/.git 2>/dev/null; then
        sed -i "s|/home/$HOST_USER|/home/ubuntu|g" /workspace/.git

        # Extract worktree name and fix the bare repo's gitdir reference
        GITDIR_PATH=$(grep "gitdir:" /workspace/.git | sed 's/gitdir: //')
        if [ -d "$GITDIR_PATH" ]; then
            GITDIR_FILE="$GITDIR_PATH/gitdir"
            if [ -f "$GITDIR_FILE" ]; then
                echo "/workspace/.git" > "$GITDIR_FILE"
            fi
        fi
    fi
fi

# Execute the command passed to the container
exec "$@"
