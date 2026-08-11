# INTECTED — Dockerfile for the FastAPI dashboard
# Build:  docker build -t intected-dashboard .
FROM python:3.12-slim

LABEL org.opencontainers.image.title="INTECTED Dashboard"
LABEL org.opencontainers.image.description="RedAegis pentest co-pilot dashboard + LLM bridge"

# ------------------------------------------------------------------ system deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------ app user
RUN useradd --create-home --shell /bin/bash intected
WORKDIR /home/intected/app

# ------------------------------------------------------------------ Python deps
# Install uv for fast package resolution
RUN pip install --no-cache-dir uv

COPY pyproject.toml ./
# Install the project in editable mode (copies the package metadata)
RUN uv pip install --system -e ".[test]"

# ------------------------------------------------------------------ application
COPY intected/ ./intected/
COPY tests/    ./tests/
COPY scripts/  ./scripts/

# Make entrypoint executable
RUN chmod +x ./scripts/docker-entrypoint.sh

# ------------------------------------------------------------------ runtime
EXPOSE 8765

ENV INTECTED_STATE=/home/intected/.intected
ENV REDAEGIS_BRIDGE_URL=http://bridge:4000/v1

USER intected
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD curl -fs http://localhost:8765/api/missions?token=healthcheck || exit 1

ENTRYPOINT ["./scripts/docker-entrypoint.sh"]
