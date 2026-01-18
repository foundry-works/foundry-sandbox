FROM ubuntu:24.04

ARG UID=1000
ARG GID=1000

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
    ripgrep \
    fd-find \
    fzf \
    vim \
    jq \
    lsof \
    python3 \
    python3-pip \
    iptables \
    dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/bin/python3 /usr/bin/python

# Node.js 22.x (for claude, gemini)
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs

# Go 1.23 (for opencode) - auto-detect architecture for Apple Silicon support
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://go.dev/dl/go1.23.4.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Ubuntu 24.04 already has ubuntu user with UID/GID 1000
# Install safety guardrails (before switching to ubuntu user)

# Layer 1: Shell function overrides (loaded by all bash sessions)
COPY safety/shell-overrides.sh /etc/profile.d/shell-overrides.sh
RUN chmod 644 /etc/profile.d/shell-overrides.sh

# Layer 1b: Credential redaction (automatically redacts API keys in env output)
COPY safety/credential-redaction.sh /etc/profile.d/credential-redaction.sh
RUN chmod 644 /etc/profile.d/credential-redaction.sh

# Layer 2: Strict sudoers allowlist (no NOPASSWD:ALL fallback)
COPY safety/sudoers-allowlist /etc/sudoers.d/allowlist
RUN chmod 440 /etc/sudoers.d/allowlist && visudo -c

# Layer 3: Operator approval wrapper (NOT in AI's PATH)
RUN mkdir -p /opt/operator/bin
COPY safety/operator-approve /opt/operator/bin/operator-approve
RUN chmod 755 /opt/operator/bin/operator-approve

# Layer 4: Network isolation scripts
COPY safety/network-firewall.sh /home/ubuntu/network-firewall.sh
COPY safety/network-mode /usr/local/bin/network-mode
RUN chmod +x /home/ubuntu/network-firewall.sh /usr/local/bin/network-mode

# Remove PEP 668 protection (run as root before switching users)
# Safe in Docker containers where isolation already exists
RUN rm -f /usr/lib/python*/EXTERNALLY-MANAGED

# Install AI tools globally as root (to /usr/local, survives tmpfs on /home)
RUN npm install -g @anthropic-ai/claude-code \
    && npm install -g @google/gemini-cli \
    && npm install -g @openai/codex \
    && npm install -g opencode-ai @opencode-ai/sdk

# Install Python packages globally (to /usr/local/lib/python3)
RUN pip3 install foundry-mcp pytest-asyncio hypothesis

# Fix ESM module resolution for OpenCode SDK wrapper
# ESM imports don't respect NODE_PATH, so we create a symlink from foundry-mcp's
# providers directory to the globally installed SDK
RUN PROVIDERS_DIR=$(python3 -c "import foundry_mcp.core.providers as p; print(p.__path__[0])") && \
    mkdir -p "$PROVIDERS_DIR/node_modules" && \
    ln -sf /usr/local/lib/node_modules/@opencode-ai "$PROVIDERS_DIR/node_modules/@opencode-ai"

# Install Cursor CLI system-wide
RUN curl https://cursor.com/install -fsS | CURSOR_INSTALL_DIR=/usr/local/bin bash

# Add useful aliases to system bashrc (before switching to non-root user)
# Home directory is tmpfs at runtime, so user .bashrc won't persist
RUN echo "alias cdsp='claude --dangerously-skip-permissions'" >> /etc/bash.bashrc && \
    echo "alias cdspr='claude --dangerously-skip-permissions --resume'" >> /etc/bash.bashrc && \
    echo '[ -f "$HOME/.api_keys" ] && source "$HOME/.api_keys"' >> /etc/bash.bashrc

# Copy entrypoint to system path (not /home which is tmpfs)
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER ubuntu
WORKDIR /workspace

# Set up paths for user
ENV PATH="/usr/local/go/bin:/home/ubuntu/go/bin:/home/ubuntu/.local/bin:$PATH"
ENV GOPATH="/home/ubuntu/go"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
