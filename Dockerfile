FROM ubuntu:24.04

ARG UID=1000
ARG GID=1000
ARG USERNAME=ubuntu

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
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://go.dev/dl/go1.23.4.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz

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

# Layer 1: Shell function overrides (loaded by all bash sessions)
COPY safety/shell-overrides.sh /etc/profile.d/shell-overrides.sh
RUN chmod 644 /etc/profile.d/shell-overrides.sh

# Layer 1b: Credential redaction (automatically redacts API keys in env output)
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

# Layer 5: Credential proxy init (for credential isolation mode)
COPY safety/credential-proxy-init.sh /usr/local/bin/credential-proxy-init.sh
RUN chmod +x /usr/local/bin/credential-proxy-init.sh

# Remove PEP 668 protection (run as root before switching users)
# Safe in Docker containers where isolation already exists
RUN rm -f /usr/lib/python*/EXTERNALLY-MANAGED

# Install AI tools globally as root (to /usr/local, survives tmpfs on /home)
RUN npm install -g @anthropic-ai/claude-code \
    && npm install -g @google/gemini-cli \
    && npm install -g @openai/codex \
    && npm install -g opencode-ai @opencode-ai/sdk

# Install Python packages globally (to /usr/local/lib/python3)
RUN pip3 install foundry-mcp pytest-asyncio hypothesis cc-context-stats pyright

# Fix ESM module resolution for OpenCode SDK wrapper
# ESM imports don't respect NODE_PATH, so we create a symlink from foundry-mcp's
# providers directory to the globally installed SDK
RUN PROVIDERS_DIR=$(python3 -c "import foundry_mcp.core.providers as p; print(p.__path__[0])") && \
    mkdir -p "$PROVIDERS_DIR/node_modules" && \
    ln -sf /usr/local/lib/node_modules/@opencode-ai "$PROVIDERS_DIR/node_modules/@opencode-ai"

# Install Cursor Agent to /opt (survives tmpfs on /home)
RUN mkdir -p /opt/cursor && \
    curl https://cursor.com/install -fsS | HOME=/opt/cursor bash && \
    ln -sf /opt/cursor/.local/bin/agent /usr/local/bin/agent && \
    ln -sf /opt/cursor/.local/bin/cursor-agent /usr/local/bin/cursor-agent

# Add useful aliases to system bashrc (before switching to non-root user)
# Home directory is tmpfs at runtime, so user .bashrc won't persist
# API keys are passed via environment variables (docker-compose), not sourced from files
RUN echo "alias claudedsp='claude --dangerously-skip-permissions'" >> /etc/bash.bashrc && \
    echo "alias codexdsp='codex --dangerously-bypass-approvals-and-sandbox'" >> /etc/bash.bashrc && \
    echo "alias reinstall-foundry='sudo network-mode full && claude plugin marketplace add foundry-works/claude-foundry && claude plugin install foundry@claude-foundry && claude plugin enable foundry@claude-foundry && sudo network-mode limited'" >> /etc/bash.bashrc

# Install bash completions for sandbox aliases
COPY safety/sandbox-completions.bash /etc/bash_completion.d/sandbox-completions
RUN chmod 644 /etc/bash_completion.d/sandbox-completions

# Pre-populate GitHub SSH host keys (prevents "authenticity of host" prompts)
RUN mkdir -p /etc/skel/.ssh && \
    ssh-keyscan -t ed25519,rsa github.com >> /etc/skel/.ssh/known_hosts 2>/dev/null && \
    chmod 700 /etc/skel/.ssh && \
    chmod 644 /etc/skel/.ssh/known_hosts

# Copy entrypoint to system path (not /home which is tmpfs)
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER $USERNAME
WORKDIR /workspace

# Set up paths for user (use /home/ubuntu for compatibility - symlinked if different user)
ENV PATH="/usr/local/go/bin:/home/ubuntu/go/bin:/home/ubuntu/.local/bin:$PATH"
ENV GOPATH="/home/ubuntu/go"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
