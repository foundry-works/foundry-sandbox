# Dockerfile for credential isolation gateway
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including dnsmasq
RUN apt-get update && apt-get install -y \
    curl \
    git \
    dnsmasq \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy gateway application and configuration files
COPY gateway.py .
COPY allowlist.conf .
COPY build-configs.sh .
COPY entrypoint.sh .

# Generate configuration files at build time
RUN chmod +x build-configs.sh && ./build-configs.sh

# Copy generated dnsmasq config to system location
# dnsmasq reads from /etc/dnsmasq.conf by default
RUN cp /app/dnsmasq.conf /etc/dnsmasq.conf

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Create socket directory (will be used by entrypoint)
RUN mkdir -p /var/run/gateway && chmod 755 /var/run/gateway

# Create non-root user for security
# Note: User needs write access to socket directory
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app && \
    chown -R appuser:appuser /var/run/gateway

# Expose ports (8080 for HTTP, 53 for DNS if enabled)
EXPOSE 8080
EXPOSE 53/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application via entrypoint script
# Entrypoint starts dnsmasq as root (if configured), then drops to appuser for Gunicorn
# Note: Container must run as root initially to bind dnsmasq to port 53
ENTRYPOINT ["/app/entrypoint.sh"]
