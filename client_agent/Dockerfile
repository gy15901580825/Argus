# Build from the repository root with -f client_agent/Dockerfile.
FROM mcr.microsoft.com/playwright/python:v1.51.0-noble
WORKDIR /app
COPY client_agent/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY client_agent/ /app/client_agent/
COPY argus_transport/ /app/argus_transport/
COPY client_agent/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/entrypoint.sh"]
