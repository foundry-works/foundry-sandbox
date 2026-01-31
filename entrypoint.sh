#!/bin/bash

# Create home directories (needed because /home/ubuntu is tmpfs with read-only root)
# These would normally be created by Dockerfile but tmpfs is empty on each start
mkdir -p "$HOME/.claude" \
         "$HOME/.config/gh" \
         "$HOME/.gemini" \
         "$HOME/.config/opencode" \
         "$HOME/.local/share/opencode" \
         "$HOME/.cursor" \
         "$HOME/.codex" \
         "$HOME/.ssh" \
         "$HOME/.local/bin" \
         "$HOME/.cache" \
         "$HOME/.npm" \
         "$HOME/.foundry-mcp/cache" \
         "$HOME/.foundry-mcp/errors" \
         "$HOME/.foundry-mcp/metrics"

# Fix ownership of directories that Docker may have created as root
# (happens when credential-isolation mounts files before entrypoint runs)
# Include parent directories (.local, .local/share) that Docker creates for nested mounts
for dir in "$HOME/.codex" "$HOME/.local" "$HOME/.local/share" "$HOME/.local/share/opencode" "$HOME/.gemini"; do
    if [ -d "$dir" ] && [ "$(stat -c '%U' "$dir" 2>/dev/null)" = "root" ]; then
        sudo chown "$(id -u):$(id -g)" "$dir" 2>/dev/null || true
    fi
done

# Copy stub auth files from staging location to writable home directories
# (credential isolation mode mounts read-only stubs to /stub-auth/)
# This allows CLI tools to "write" to auth.json without errors, but writes are
# discarded when container stops since home is tmpfs
if [ -f "/stub-auth/codex-auth.json" ]; then
    cp /stub-auth/codex-auth.json "$HOME/.codex/auth.json"
fi
if [ -f "/stub-auth/opencode-auth.json" ]; then
    cp /stub-auth/opencode-auth.json "$HOME/.local/share/opencode/auth.json"
fi
if [ -f "/stub-auth/gemini-oauth_creds.json" ]; then
    cp /stub-auth/gemini-oauth_creds.json "$HOME/.gemini/oauth_creds.json"
fi

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

# Trust mitmproxy CA when mounted (explicit proxy mode)
if [ -f "/certs/mitmproxy-ca.pem" ]; then
    echo "Configuring CA trust for proxy..."
    export NODE_EXTRA_CA_CERTS="/certs/mitmproxy-ca.pem"
    export REQUESTS_CA_BUNDLE="/certs/mitmproxy-ca.pem"
    export SSL_CERT_FILE="/certs/mitmproxy-ca.pem"
    export CURL_CA_BUNDLE="/certs/mitmproxy-ca.pem"
    if command -v update-ca-certificates >/dev/null 2>&1; then
        if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            sudo cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
            sudo update-ca-certificates >/dev/null 2>&1 || true
        elif [ -w "/usr/local/share/ca-certificates" ]; then
            cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
            update-ca-certificates >/dev/null 2>&1 || true
        fi
    fi
fi

# Execute the command passed to the container
exec "$@"
