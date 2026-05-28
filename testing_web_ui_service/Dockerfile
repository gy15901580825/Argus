FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple --default-timeout=100

# Install Chromium + system deps so browser_use's LocalBrowserWatchdog finds a
# pre-installed browser (PLAYWRIGHT_BROWSERS_PATH glob in _find_installed_browser_path).
# Without this, the watchdog falls back to `uvx playwright install chrome` at runtime
# which requires uv (not in the base image) and would download Chrome on every cold start.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN playwright install --with-deps chromium

# Copy application files
COPY . .

# Expose the port
EXPOSE 8002

# Environment variables
ENV HOST=0.0.0.0
ENV PORT=8002

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8002"]
