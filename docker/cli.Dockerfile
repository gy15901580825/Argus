# Build with a context containing only this Dockerfile and the release wheel.
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

ARG VERSION
LABEL org.opencontainers.image.source="https://github.com/gy15901580825/Argus" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY *.whl /tmp/wheel/
RUN python -m pip install --no-cache-dir /tmp/wheel/*.whl \
    && rm -rf /tmp/wheel \
    && useradd --create-home --uid 10001 argus

USER 10001:10001
WORKDIR /home/argus
ENTRYPOINT ["argus-probe"]
