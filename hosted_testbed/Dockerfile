FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home appuser
COPY testbed/ ./testbed/
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "testbed.app", "--host", "0.0.0.0", "--port", "8080"]
