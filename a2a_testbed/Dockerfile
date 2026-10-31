FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY testbed/ ./testbed/
COPY demo_agent/ ./demo_agent/
ENV PORT=8080
ENV TESTBED_CONTROL_PORT=8081
ENV TESTBED_CONTROL_TOKEN=""
ENV TESTBED_CONTROL_HOST="127.0.0.1"
ENV TESTBED_ORIGIN=""
ENV A2A_AGENT_CREDENTIALS=""
ENV A2A_DRIVER_CREDENTIAL=""
ENV DEMO_WEAKNESSES="safe"
EXPOSE 8080
CMD ["python", "-m", "testbed.serve"]
