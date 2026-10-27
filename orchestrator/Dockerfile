FROM python:3.11-slim

WORKDIR /app

# 1. Install system dependencies
# If DNS resolution fails during the build, build with host networking:
#   docker build --network=host -t <registry>/argus/orchestrator:<tag> .
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copy config files
# .env is not baked into the image; it is injected at runtime via k8s Secret/ConfigMap (locally: docker run --env-file .env)
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# 4. Copy source code
COPY orchestrator/ orchestrator/

# 4.1 Clear all Python cache files
RUN find /app -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
RUN find /app -type f -name '*.pyc' -delete 2>/dev/null || true

# 5. Copy server entrypoint and connection manager
COPY server.py .
COPY connection_manager.py .

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Informational only: server.py listens on $PORT (default 8080; the Helm chart sets it).
EXPOSE 8081

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
