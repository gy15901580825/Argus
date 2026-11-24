#!/usr/bin/env bash
set -euo pipefail
unset ANTHROPIC_API_KEY OPENAI_API_KEY AZURE_OPENAI_API_KEY AZURE_API_KEY

image="${1:?Usage: smoke_image.sh IMAGE}"
container=$(docker run --detach --network none \
  --env CHALLENGE_MODEL_BASE=http://127.0.0.1:9 \
  --env CHALLENGE_MODEL=challenge-deployment "$image")
cleanup() {
  docker rm --force "$container" >/dev/null
}
trap cleanup EXIT

if ! docker exec "$container" python -c '
import os
import time
from urllib.error import URLError
from urllib.request import urlopen

assert os.getuid() == 10001
assert os.environ["CHALLENGE_ENV"] == "production"
assert os.environ["CHALLENGE_DB_PATH"] == "/data/challenge.sqlite3"
for attempt in range(60):
    try:
        with urlopen("http://127.0.0.1:8080/healthz", timeout=1) as response:
            assert response.status == 200
        break
    except URLError:
        time.sleep(0.5)
else:
    raise SystemExit("Container health check did not become ready")
with urlopen("http://127.0.0.1:8080/", timeout=2) as response:
    assert response.status == 200
    assert "<title>Argus Challenge: break the agent</title>" in response.read().decode()
assert os.path.isfile("/data/challenge.sqlite3")
print("Image smoke passed: non-root production service, /healthz 200, / 200, page title, database file")
'; then
  docker logs "$container"
  exit 1
fi
