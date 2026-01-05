FROM ubuntu:24.04

ARG UID=1000
ARG GID=1000

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Basics
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
# Just add sudo access
RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER ubuntu
WORKDIR /home/ubuntu

# Set up paths for user
ENV PATH="/usr/local/go/bin:/home/ubuntu/go/bin:/home/ubuntu/.local/bin:$PATH"
ENV GOPATH="/home/ubuntu/go"

# Install AI tools as user
RUN npm config set prefix '/home/ubuntu/.local' \
    && npm install -g @anthropic-ai/claude-code \
    && npm install -g @google/gemini-cli \
    && npm install -g @openai/codex

# Install opencode CLI and SDK
RUN npm install -g opencode-ai @opencode-ai/sdk

# Remove PEP 668 protection - safe in Docker containers where isolation already exists
RUN sudo rm -f /usr/lib/python*/EXTERNALLY-MANAGED

# Install foundry-mcp for MCP server support
RUN pip3 install foundry-mcp pytest-asyncio hypothesis

# Fix ESM module resolution for OpenCode SDK wrapper
# ESM imports don't respect NODE_PATH, so we create a symlink from foundry-mcp's
# providers directory to the globally installed SDK
RUN PROVIDERS_DIR=$(python3 -c "import foundry_mcp.core.providers as p; print(p.__path__[0])") && \
    mkdir -p "$PROVIDERS_DIR/node_modules" && \
    ln -sf /home/ubuntu/.local/lib/node_modules/@opencode-ai "$PROVIDERS_DIR/node_modules/@opencode-ai"

# Install Cursor CLI (cursor-agent)
RUN curl https://cursor.com/install -fsS | bash

# Create directories for mounted configs
RUN mkdir -p /home/ubuntu/.claude \
    /home/ubuntu/.config/gh \
    /home/ubuntu/.gemini \
    /home/ubuntu/.config/opencode \
    /home/ubuntu/.cursor \
    /home/ubuntu/.codex \
    /home/ubuntu/.ssh

# Add useful aliases to bashrc
RUN echo "alias cdsp='claude --dangerously-skip-permissions'" >> /home/ubuntu/.bashrc && \
    echo "alias cdspr='claude --dangerously-skip-permissions --resume'" >> /home/ubuntu/.bashrc && \
    echo '[ -f "$HOME/.api_keys" ] && source "$HOME/.api_keys"' >> /home/ubuntu/.bashrc

WORKDIR /workspace

# Copy and set entrypoint script
COPY --chown=ubuntu:ubuntu entrypoint.sh /home/ubuntu/entrypoint.sh
RUN chmod +x /home/ubuntu/entrypoint.sh

ENTRYPOINT ["/home/ubuntu/entrypoint.sh"]
CMD ["/bin/bash"]
