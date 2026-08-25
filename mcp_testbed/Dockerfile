# One image, two roles. The testbed and the demo agent share a codebase and are
# only ever useful together, so the deployment picks the entrypoint:
#
#   testbed:    uvicorn testbed.app:app
#   demo agent: uvicorn demo_agent.app:app
#
# The demo agent is deliberately insecure. Never point it at a real MCP tool
# server -- see README.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY testbed/ ./testbed/
COPY demo_agent/ ./demo_agent/

ENV PORT=8080
# Only used by the demo_agent role: the origin of the testbed instance it is
# paired with. Empty means the demo agent refuses every outbound request
# (fail closed) rather than being an unrestricted fetch pivot -- see README.
ENV TESTBED_ORIGIN=""
EXPOSE 8080

# Overridden per deployment; the testbed is the safe default.
CMD ["sh", "-c", "uvicorn testbed.app:app --host 0.0.0.0 --port ${PORT}"]
