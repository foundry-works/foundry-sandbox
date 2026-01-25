#!/bin/bash

# Create home directories (needed because /home/ubuntu is tmpfs with read-only root)
# These would normally be created by Dockerfile but tmpfs is empty on each start
mkdir -p "$HOME/.claude" \
         "$HOME/.config/gh" \
         "$HOME/.gemini" \
         "$HOME/.config/opencode" \
         "$HOME/.cursor" \
         "$HOME/.codex" \
         "$HOME/.ssh" \
         "$HOME/.local/bin" \
         "$HOME/.cache" \
         "$HOME/.npm"

# Ensure Claude Code temp dir exists (defaulted via docker-compose)
if [ -n "${CLAUDE_CODE_TMPDIR:-}" ]; then
    mkdir -p "$CLAUDE_CODE_TMPDIR" 2>/dev/null || true
fi

# Set up npm prefix for user-local installs
npm config set prefix "$HOME/.local" 2>/dev/null || true

# Add foundry-upgrade alias for easy MCP plugin updates
echo "alias foundry-upgrade='pip install --pre --upgrade foundry-mcp'" >> ~/.bashrc

# API keys are expected to be passed via environment variables (docker-compose)

# CLI tools are pre-installed in the image
# To update manually: npm update -g @anthropic-ai/claude-code @google/gemini-cli @openai/codex opencode-ai

# Ensure Claude onboarding is marked complete (required for auth to work)
CLAUDE_JSON="$HOME/.claude.json"
if [ -f "$CLAUDE_JSON" ]; then
    if ! grep -q '"hasCompletedOnboarding": true' "$CLAUDE_JSON"; then
        echo "Setting hasCompletedOnboarding in Claude config..."
        tmp=$(mktemp)
        jq '. + {"hasCompletedOnboarding": true}' "$CLAUDE_JSON" > "$tmp" && mv "$tmp" "$CLAUDE_JSON"
    fi
else
    # Create minimal config if it doesn't exist
    echo '{"hasCompletedOnboarding": true}' > "$CLAUDE_JSON"
fi

# Note: Git worktree path fixes are handled by the host script (lib/container_config.sh)
# after copying the repos directory, ensuring the bare repo exists before fixing paths.

# Network mode is applied AFTER plugin registration by the host setup script.
# This allows plugin/MCP registration to access GitHub if needed.
# To apply network mode manually: sudo network-mode <limited|host-only|none>
# The host script will call this after copy_configs_to_container completes.

# Execute the command passed to the container
exec "$@"
