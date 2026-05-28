FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install --with-deps chromium

# Copy source code
COPY server.py .
COPY tools_impl.py .
COPY ai_crawler.py .

# Expose port
EXPOSE 8001

# Environment variables
ENV PORT=8001
ENV HOST=0.0.0.0

CMD ["mcp", "run", "server.py", "--transport", "sse"]
