# Gateway service for credential-isolated sandboxes
# Provides HTTP proxy for git operations with real credentials
FROM python:3.12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsmasq \
    tinyproxy \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r gateway && useradd -r -g gateway -d /app -s /sbin/nologin gateway

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY gateway.py .
COPY allowlist.conf .
COPY build-configs.sh .
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY tinyproxy-filter /etc/tinyproxy/filter

# Generate configs at build time
RUN chmod +x build-configs.sh && ./build-configs.sh /etc/gateway

# Create directories with correct permissions
RUN mkdir -p /var/run/dnsmasq /var/log/tinyproxy \
    && chown -R gateway:gateway /app /var/run/dnsmasq /var/log/tinyproxy

# Expose ports
# 5000 = gateway API (Flask/gunicorn)
# 8888 = egress proxy (tinyproxy)
EXPOSE 5000 8888

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run as non-root (dnsmasq and tinyproxy started by entrypoint)
USER gateway

# Start with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", \
     "--timeout", "120", "--access-logfile", "-", "gateway:app"]
