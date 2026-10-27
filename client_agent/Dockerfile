# -----------------------------
# Argus Client Agent Dockerfile
# docker build --network=host -t <your-gh-user>/client_agent:latest .
# -----------------------------
# Use official Playwright image — includes Chromium + all system deps for browser automation.
FROM mcr.microsoft.com/playwright/python:v1.51.0-noble

WORKDIR /app

# 1. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 2. Install Playwright browser binaries (Chromium only to keep image lean).
#    The playwright package is already in requirements.txt; this installs the binary.
RUN playwright install chromium --with-deps

# 3. Copy application code and the entrypoint script
COPY . .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 4. Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# 5. Run the service
# docker run \
#   --network=host \
#   -e ORCHESTRATOR_URL=ws://<orchestrator-host>:8080 \
#   -e AGENT_NAME=my-agent \
#   <your-gh-user>/client_agent:latest
#
# ORCHESTRATOR_URL is required. Set API_SERVICE_URL plus credentials only to register first.
ENTRYPOINT ["/entrypoint.sh"]
