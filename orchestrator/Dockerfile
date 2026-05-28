# -----------------------------
# Runtime Image (No Obfuscation)
# -----------------------------
# Temporarily disabled PyArmor obfuscation as it breaks class inheritance
FROM python:3.11-slim

WORKDIR /app

# 1. Install system dependencies
# Note: if DNS resolution fails, use one of the following methods:
# Method 1: use host network mode (recommended at build time)
#   docker build --network=host -t 192.168.1.121:30500/argus/orchestrator:1.0.0 .
# Method 2: configure DNS for the Docker daemon (requires root)
#   Edit /etc/docker/daemon.json: {"dns": ["8.8.8.8", "8.8.4.4"]}
#   Then restart: sudo systemctl restart docker
# Method 3: use buildx (if available)
#   DOCKER_BUILDKIT=1 docker buildx build --network=host -t 192.168.1.121:30500/argus/orchestrator:1.0.0 .
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    supervisor \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# 2. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2.1 Install Playwright browsers (separate layer for cache reuse)
RUN playwright install --with-deps chromium

# 3. Install Node dependencies
COPY package.json package-lock.json* ./
RUN npm install

# 4. Copy other required config files (add as needed)
# .env is no longer baked into the image -- injected at runtime via k8s Secret/ConfigMap (for local dev use docker run --env-file .env)
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 5. Copy source code (no PyArmor obfuscation)
COPY orchestrator/ orchestrator/

# 5.1 Clear all Python cache files
RUN find /app -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
RUN find /app -type f -name '*.pyc' -delete 2>/dev/null || true

# 6. Copy server entrypoint and connection manager
COPY server.py .
COPY connection_manager.py .

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose ports (8080: ADK Web, 8081: Orchestrator Server)
EXPOSE 8081
# EXPOSE 8080 8081

# Run supervisord to manage multiple processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
