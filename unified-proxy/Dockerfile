# Unified Proxy Container
# mitmproxy-based credential injection and traffic filtering proxy
#
# This container holds API credentials and injects them into outbound requests,
# keeping credentials isolated from the sandbox environment. It also provides:
# - DNS filtering (allowlist-based egress control)
# - Git protocol filtering (blocks dangerous operations)
# - Policy enforcement (rate limiting, circuit breaking)
# - Container identity tracking

FROM mitmproxy/mitmproxy:11.1.0

# Labels for container identification
LABEL org.opencontainers.image.title="Unified Proxy"
LABEL org.opencontainers.image.description="mitmproxy-based credential injection and traffic filtering"
LABEL org.opencontainers.image.source="https://github.com/anthropics/foundry-sandbox"

# Install additional Python dependencies
USER root
COPY requirements.txt /opt/proxy/requirements.txt
RUN pip install --no-cache-dir -r /opt/proxy/requirements.txt

# Create directories for configuration, certificates, and runtime
# Owned by mitmproxy user so the container can write to mounted volumes
RUN mkdir -p /etc/proxy/credentials /etc/proxy/certs /var/run/proxy \
    && chown -R mitmproxy:mitmproxy /etc/proxy /var/run/proxy

# Copy core modules
COPY __init__.py /opt/proxy/__init__.py
COPY registry.py /opt/proxy/registry.py
COPY config.py /opt/proxy/config.py
COPY logging_config.py /opt/proxy/logging_config.py
COPY internal_api.py /opt/proxy/internal_api.py
COPY pktline.py /opt/proxy/pktline.py

# Copy legacy credential injection scripts (still used by entrypoint)
COPY inject-credentials.py /opt/proxy/inject-credentials.py
COPY codex-token-manager.py /opt/proxy/codex_token_manager.py
COPY opencode-token-manager.py /opt/proxy/opencode_token_manager.py
COPY gemini-token-manager.py /opt/proxy/gemini_token_manager.py

# Copy the GitHub API security filter and its configuration
COPY github-api-filter.py /opt/proxy/github-api-filter.py
COPY github_config.py /opt/proxy/github_config.py

# Copy addon modules (mitmproxy addons)
COPY addons/ /opt/proxy/addons/

# Copy the entrypoint script
COPY entrypoint.sh /opt/proxy/entrypoint.sh
RUN chmod +x /opt/proxy/entrypoint.sh

# Set PYTHONPATH so addons can import core modules
ENV PYTHONPATH=/opt/proxy

# Switch back to mitmproxy user for runtime
USER mitmproxy

# Expose mitmproxy ports
# 8080: HTTP/HTTPS proxy port
# 8081: mitmproxy web interface (optional, for debugging)
# 8082: Internal API for container registration
EXPOSE 8080 8081 8082

# Health check - verify proxy port is listening
HEALTHCHECK --interval=5s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 8080)); s.close()" || exit 1

# Volume mount points for runtime configuration
# /etc/proxy/credentials - credential files mounted at runtime
# /etc/proxy/certs - CA certificates for HTTPS interception
# /var/run/proxy - runtime socket and state files
VOLUME ["/etc/proxy/credentials", "/etc/proxy/certs", "/var/run/proxy"]

# Default environment variables
ENV PROXY_MODE=regular
ENV PROXY_LOG_LEVEL=info

ENTRYPOINT ["/opt/proxy/entrypoint.sh"]
