FROM ubuntu:24.04

ARG UID=1000
ARG GID=1000
ARG USERNAME=ubuntu
ARG INCLUDE_OPENCODE=1

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Basics + iptables for network mode switching
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    ca-certificates \
    gnupg \
    sudo \
    gosu \
    ripgrep \
    fd-find \
    fzf \
    vim \
    jq \
    lsof \
    python3 \
    python3-pip \
    iptables \
    ipset \
    iproute2 \
    dnsutils \
    bash-completion \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/bin/python3 /usr/bin/python

# Node.js 22.x (for claude, gemini)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs

# Go 1.23 (for opencode) - auto-detect architecture for Apple Silicon support
# Only install if INCLUDE_OPENCODE=1 (Go is only needed for OpenCode)
RUN if [ "$INCLUDE_OPENCODE" = "1" ]; then \
        ARCH=$(dpkg --print-architecture) && \
        curl -fsSL "https://go.dev/dl/go1.23.4.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz; \
    fi

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Create user (ubuntu exists by default, create custom user if different)
# Symlink their home to /home/ubuntu for docker-compose tmpfs mount compatibility
RUN if [ "$USERNAME" != "ubuntu" ]; then \
        userdel -r ubuntu 2>/dev/null || true; \
        groupadd -g $GID $USERNAME; \
        useradd -m -u $UID -g $GID -s /bin/bash -d /home/ubuntu $USERNAME; \
        ln -sf /home/ubuntu /home/$USERNAME; \
    fi

# Install safety guardrails

# Credential redaction (automatically redacts API keys in env output)
COPY safety/credential-redaction.sh /etc/profile.d/credential-redaction.sh
RUN chmod 644 /etc/profile.d/credential-redaction.sh

# Layer 2: Strict sudoers allowlist (no NOPASSWD:ALL fallback)
COPY safety/sudoers-allowlist /etc/sudoers.d/allowlist
RUN sed -i "s/^ubuntu/$USERNAME/g" /etc/sudoers.d/allowlist && \
    chmod 440 /etc/sudoers.d/allowlist && visudo -c

# Layer 3: Operator approval wrapper (NOT in AI's PATH)
RUN mkdir -p /opt/operator/bin
COPY safety/operator-approve /opt/operator/bin/operator-approve
RUN chmod 755 /opt/operator/bin/operator-approve

# Layer 4: Network isolation scripts (must be in /usr/local/bin, not /home which is tmpfs)
COPY safety/network-firewall.sh /usr/local/bin/network-firewall.sh
COPY safety/network-mode /usr/local/bin/network-mode
RUN chmod +x /usr/local/bin/network-firewall.sh /usr/local/bin/network-mode

# Remove PEP 668 protection (run as root before switching users)
# Safe in Docker containers where isolation already exists
RUN rm -f /usr/lib/python*/EXTERNALLY-MANAGED

# Install AI tools globally as root (to /usr/local, survives tmpfs on /home)
# global-agent is needed for claude-zai to route DNS through the HTTP proxy
# Pin global-agent@3.0.0 - v4+ has packaging issues (missing dist/ in npm package)
RUN npm install -g @anthropic-ai/claude-code \
    && npm install -g @google/gemini-cli \
    && npm install -g @openai/codex \
    && npm install -g global-agent@3.0.0
# Install OpenCode conditionally (only if INCLUDE_OPENCODE=1)
RUN if [ "$INCLUDE_OPENCODE" = "1" ]; then \
        npm install -g opencode-ai @opencode-ai/sdk; \
    fi

# Install Python packages globally (to /usr/local/lib/python3)
RUN pip3 install foundry-mcp pypdf pytest-asyncio hypothesis cc-context-stats pyright

# Install tavily-mcp globally (npm package for web search MCP server)
# Baked into image because npm is blocked in credential isolation mode
RUN npm install -g tavily-mcp

# Fix ESM module resolution for OpenCode SDK wrapper (only if INCLUDE_OPENCODE=1)
# ESM imports don't respect NODE_PATH, so we create a symlink from foundry-mcp's
# providers directory to the globally installed SDK
RUN if [ "$INCLUDE_OPENCODE" = "1" ]; then \
        PROVIDERS_DIR=$(python3 -c "import foundry_mcp.core.providers as p; print(p.__path__[0])") && \
        mkdir -p "$PROVIDERS_DIR/node_modules" && \
        ln -sf /usr/local/lib/node_modules/@opencode-ai "$PROVIDERS_DIR/node_modules/@opencode-ai"; \
    fi

# Add useful aliases to system bashrc (before switching to non-root user)
# Home directory is tmpfs at runtime, so user .bashrc won't persist
# API keys are passed via environment variables (docker-compose), not sourced from files
RUN echo "alias claudedsp='claude --dangerously-skip-permissions'" >> /etc/bash.bashrc && \
    echo "alias codexdsp='codex --dangerously-bypass-approvals-and-sandbox'" >> /etc/bash.bashrc && \
    echo "alias reinstall-foundry='claude plugin marketplace add foundry-works/claude-foundry && claude plugin install foundry@claude-foundry && claude plugin enable foundry@claude-foundry'" >> /etc/bash.bashrc

# Install bash completions for sandbox aliases
COPY safety/sandbox-completions.bash /etc/bash_completion.d/sandbox-completions
RUN chmod 644 /etc/bash_completion.d/sandbox-completions

# Pre-populate GitHub SSH host keys (prevents "authenticity of host" prompts)
RUN mkdir -p /etc/skel/.ssh && \
    ssh-keyscan -t ed25519,rsa github.com >> /etc/skel/.ssh/known_hosts 2>/dev/null && \
    chmod 700 /etc/skel/.ssh && \
    chmod 644 /etc/skel/.ssh/known_hosts

# Git URL rewriting for credential isolation gateway (conditional)
# The gitconfig is created at runtime by entrypoint.sh when SANDBOX_GATEWAY_ENABLED=true
# This ensures credentials never reach the sandbox - the gateway injects them
# When gateway is disabled, direct GitHub access is used
# Create the gateway gitconfig template (will be applied conditionally at runtime)
COPY safety/gateway-gitconfig /etc/gitconfig.gateway
RUN chmod 644 /etc/gitconfig.gateway

# Gateway credential helper - reads token from /run/secrets/gateway_token
# Outputs via git credential protocol; never logs/echoes the token
COPY safety/gateway-credential-helper /usr/local/bin/gateway-credential-helper
RUN chmod 755 /usr/local/bin/gateway-credential-helper

# Copy entrypoints to system path (not /home which is tmpfs)
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY entrypoint-root.sh /usr/local/bin/entrypoint-root.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint-root.sh

# Clean up root home directory and restrict access (security best practice)
# Removes build artifacts and shell configs that could be information leaks
RUN rm -rf /root/.bash_history /root/.bashrc /root/.profile \
           /root/.ssh /root/.cache /root/.local /root/.gnupg /root/.npm 2>/dev/null || true && \
    chmod 700 /root

USER $USERNAME
WORKDIR /workspace

# Set up paths for user (use /home/ubuntu for compatibility - symlinked if different user)
ENV PATH="/usr/local/go/bin:/home/ubuntu/go/bin:/home/ubuntu/.local/bin:$PATH"
ENV GOPATH="/home/ubuntu/go"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
