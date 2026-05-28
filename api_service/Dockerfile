# -----------------------------
# Argus API Service Dockerfile
# docker build --network=host -t 192.168.1.121:30500/argus/api_service:1.0.0 .
# -----------------------------
FROM python:3.11-slim

WORKDIR /app

# 1. Install system dependencies
# gcc: needed to compile some Python packages (e.g. psycopg2)
# postgresql-client: optional, for database debugging tools
# RUN apt-get clean && \
#     rm -rf /var/lib/apt/lists/* && \
#     apt-get update && \
#     apt-get install -y --no-install-recommends \
#         gcc \
#         postgresql-client \
#     && rm -rf /var/lib/apt/lists/*

# 2. Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 3. Copy application code
COPY . .

# 4. Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# 5. Expose port
EXPOSE 8881

# 6. Run the service
# Note: database connection is configured via the DATABASE_URL environment variable
# or injected via a Secret in K8s
CMD ["python", "server.py"]
