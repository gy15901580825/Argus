FROM python:3.11-slim

WORKDIR /app

# Orchestrator server image: the /redteam API and the /agent/connect hub.
# Build from the repo root. If DNS resolution fails during the build, add --network=host:
#   docker build -t <registry>/argus/orchestrator:<tag> .
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# .env is not baked into the image; inject it at runtime (locally: docker run --env-file .env).
COPY pyproject.toml LICENSE NOTICE ./
COPY docs/cli.md docs/cli.md
COPY argus/ argus/
RUN pip install --no-cache-dir . && rm -rf /app/argus

ENV PYTHONUNBUFFERED=1

# argus.server listens on $PORT, default 8080.
EXPOSE 8080

CMD ["python", "-m", "argus.server"]
