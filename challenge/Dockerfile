FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd --gid 10001 challenge \
    && useradd --uid 10001 --gid challenge --no-create-home challenge \
    && mkdir /data \
    && chown challenge:challenge /data

COPY *.py ./
COPY static/ ./static/

ENV CHALLENGE_DB_PATH=/data/challenge.sqlite3 \
    CHALLENGE_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-proxy-headers"]
