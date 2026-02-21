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

# Ensure curl, gosu, git, and squid are available
# curl: host-driven registration via docker exec
# gosu: privilege dropping at runtime
# git: credential helper configuration
# squid: forward proxy for SNI-based domain filtering (no TLS decryption)
RUN if command -v apt-get >/dev/null 2>&1; then \
        apt-get update && apt-get install -y curl gosu git squid && rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache curl gosu git squid; \
    else \
        echo "ERROR: No supported package manager (apt-get or apk) found" >&2 && exit 1; \
    fi

# Create directories for configuration, certificates, runtime, and Squid
# Owned by mitmproxy user so the container can write to mounted volumes
RUN mkdir -p /etc/proxy/credentials /etc/proxy/certs /var/run/proxy /var/lib/unified-proxy \
        /etc/squid /var/log/squid /var/spool/squid /var/run/squid \
    && chown -R mitmproxy:mitmproxy /etc/proxy /var/run/proxy /var/lib/unified-proxy \
        /etc/squid /var/log/squid /var/spool/squid /var/run/squid

# Copy core modules
COPY __init__.py /opt/proxy/__init__.py
COPY registry.py /opt/proxy/registry.py
COPY config.py /opt/proxy/config.py
COPY logging_config.py /opt/proxy/logging_config.py
COPY internal_api.py /opt/proxy/internal_api.py
COPY pktline.py /opt/proxy/pktline.py

# Copy token manager modules (used by credential_injector addon)
COPY codex-token-manager.py /opt/proxy/codex_token_manager.py
COPY opencode-token-manager.py /opt/proxy/opencode_token_manager.py
COPY gemini-token-manager.py /opt/proxy/gemini_token_manager.py

# Copy the GitHub API security filter and its configuration
COPY github-api-filter.py /opt/proxy/github-api-filter.py
COPY github_config.py /opt/proxy/github_config.py

# Copy the API gateways, shared base modules, and middleware
COPY gateway_errors.py /opt/proxy/gateway_errors.py
COPY gateway_base.py /opt/proxy/gateway_base.py
COPY security_policies.py /opt/proxy/security_policies.py
COPY gateway_middleware.py /opt/proxy/gateway_middleware.py
COPY gateway.py /opt/proxy/gateway.py
COPY openai_gateway.py /opt/proxy/openai_gateway.py
COPY chatgpt_gateway.py /opt/proxy/chatgpt_gateway.py
COPY gemini_gateway.py /opt/proxy/gemini_gateway.py
COPY github_gateway.py /opt/proxy/github_gateway.py

# Copy the git API server and git policy modules (used when git shadow mode is enabled)
COPY git_api.py /opt/proxy/git_api.py
COPY git_operations.py /opt/proxy/git_operations.py
COPY git_policies.py /opt/proxy/git_policies.py
COPY branch_types.py /opt/proxy/branch_types.py
COPY branch_isolation.py /opt/proxy/branch_isolation.py
COPY branch_output_filter.py /opt/proxy/branch_output_filter.py
COPY git_command_validation.py /opt/proxy/git_command_validation.py
COPY git_subprocess.py /opt/proxy/git_subprocess.py

# Copy addon modules (mitmproxy addons)
COPY addons/ /opt/proxy/addons/

# Copy Squid configuration and domain list generator
COPY squid.conf /etc/squid/squid.conf
COPY generate_squid_config.py /opt/proxy/generate_squid_config.py

# Copy the entrypoint script
COPY entrypoint.sh /opt/proxy/entrypoint.sh
RUN chmod +x /opt/proxy/entrypoint.sh

# Set PYTHONPATH so addons can import core modules
ENV PYTHONPATH=/opt/proxy

# Expose proxy and gateway ports
# 443:  ChatGPT gateway TLS (transparent interception for chatgpt.com)
# 8080: Squid forward proxy (SNI-based domain filtering)
# 8081: mitmproxy (MITM-only, receives CONNECT from Squid cache_peer)
# 8082: Internal API for container registration
# 8083: Git API server
# 9848: Anthropic API gateway
# 9849: OpenAI API gateway
# 9850: GitHub API gateway
# 9851: Gemini API gateway
# 9852: ChatGPT/Codex API gateway (HTTP)
EXPOSE 443 8080 8081 8082 8083 9848 9849 9850 9851 9852

# Health check - verify internal API is responsive
HEALTHCHECK --interval=5s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8082/internal/health || exit 1

# Volume mount points for runtime configuration
# /etc/proxy/credentials - credential files mounted at runtime
# /etc/proxy/certs - CA certificates for HTTPS interception
# /var/run/proxy - runtime socket and state files
VOLUME ["/etc/proxy/credentials", "/etc/proxy/certs", "/var/run/proxy"]

# Default environment variables
ENV PROXY_MODE=regular
ENV PROXY_LOG_LEVEL=info
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/opt/proxy/entrypoint.sh"]
