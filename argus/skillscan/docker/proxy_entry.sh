#!/bin/bash
# Runs as root: make a neutral CA, take the upstream key and decoy markers from a FIFO fed over `docker exec -i`,
# then start mitmdump as the mitmproxy user. The key never touches the container config or disk.
set -euo pipefail

CONF=/home/mitmproxy/.mitmproxy
python3 - "$CONF" <<'PY'
import sys
from pathlib import Path
from mitmproxy.certs import CertStore
CertStore.create_store(Path(sys.argv[1]), "mitmproxy", 2048, organization="Internal IT", cn="Internal Root CA")
PY
touch /var/log/proxy/requests.jsonl
chown -R mitmproxy:mitmproxy "$CONF" /var/log/proxy

mkfifo -m 600 /run/upstream-key
ARGUS_REAL_KEY=""
ARGUS_MARKERS=""
# Line 1 is the key, line 2 the space-separated decoy markers to look for in refused traffic.
{ IFS= read -r ARGUS_REAL_KEY || true; IFS= read -r ARGUS_MARKERS || true; } < /run/upstream-key
rm -f /run/upstream-key
export ARGUS_REAL_KEY ARGUS_MARKERS

exec env HOME=/home/mitmproxy gosu mitmproxy mitmdump --quiet --listen-port 8080 \
  --set connection_strategy=lazy --set upstream_cert=false --set rawtcp=false \
  --set http2=false --set http3=false --set onboarding=false \
  --set flow_detail=0 -s /opt/proxy/proxy_addon.py
