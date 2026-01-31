# Dockerfile for credential isolation gateway
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including dnsmasq
RUN apt-get update && apt-get install -y \
    curl \
    git \
    dnsmasq \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy gateway application and configuration files
COPY gateway.py .
COPY allowlist.conf .
COPY build-configs.sh .

# Generate configuration files at build time
RUN chmod +x build-configs.sh && ./build-configs.sh

# Create non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--worker-class", "sync", "--timeout", "60", "gateway:app"]
