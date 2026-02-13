# docker/Dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# System deps (certs, tini optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tini && \
    rm -rf /var/lib/apt/lists/*

# Python deps: openstacksdk, kubernetes, pyyaml for YAML access rules
RUN pip install --no-cache-dir \
      openstacksdk \
      kubernetes \
      pyyaml

WORKDIR /app
COPY cron_appcred_to_secret.py /app/cron_appcred_to_secret.py

# Nonroot (optional)
RUN useradd -r -u 10001 appuser
USER appuser

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "/app/cron_appcred_to_secret.py"]
