# API Proxy Container
# mitmproxy-based credential injection proxy for API requests
#
# This container holds API credentials and injects them into outbound requests,
# keeping credentials isolated from the sandbox environment.

FROM mitmproxy/mitmproxy:11.1.0

# Labels for container identification
LABEL org.opencontainers.image.title="API Credential Proxy"
LABEL org.opencontainers.image.description="mitmproxy-based API credential injection"
LABEL org.opencontainers.image.source="https://github.com/your-org/foundry-sandbox"

# Install additional Python dependencies for the addon
USER root
RUN pip install --no-cache-dir pyyaml httpx

# Create directories for configuration and certificates
# Owned by mitmproxy user so the container can write to mounted volumes
RUN mkdir -p /etc/proxy/credentials /etc/proxy/certs \
    && chown -R mitmproxy:mitmproxy /etc/proxy

# Copy the credential injection addon and OAuth token managers
COPY inject-credentials.py /opt/proxy/inject-credentials.py
COPY codex-token-manager.py /opt/proxy/codex_token_manager.py
COPY opencode-token-manager.py /opt/proxy/opencode_token_manager.py
COPY gemini-token-manager.py /opt/proxy/gemini_token_manager.py
# Copy the GitHub API security filter and its configuration
COPY github-api-filter.py /opt/proxy/github-api-filter.py
COPY github_config.py /opt/proxy/github_config.py

# Copy the entrypoint script
COPY entrypoint.sh /opt/proxy/entrypoint.sh
RUN chmod +x /opt/proxy/entrypoint.sh

# Switch back to mitmproxy user for runtime
USER mitmproxy

# Expose mitmproxy ports
# 8080: HTTP/HTTPS proxy port
# 8081: mitmproxy web interface (optional, for debugging)
EXPOSE 8080 8081

# Health check - verify proxy port is listening
HEALTHCHECK --interval=5s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 8080)); s.close()" || exit 1

# Volume mount points for runtime configuration
# /etc/proxy/credentials - credential files mounted at runtime
# /etc/proxy/certs - CA certificates for HTTPS interception
VOLUME ["/etc/proxy/credentials", "/etc/proxy/certs"]

# Default environment variables
ENV PROXY_MODE=regular
ENV PROXY_LOG_LEVEL=info

ENTRYPOINT ["/opt/proxy/entrypoint.sh"]
