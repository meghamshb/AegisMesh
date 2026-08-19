# Real Hermes agent runtime for Phase 4 (LAP template pattern, policy-gateway scope).
# Installs NousResearch/hermes-agent; terminal + web toolsets egress via HTTP_PROXY.
FROM python:3.12-slim-bookworm

ARG HERMES_AGENT_REF=v2026.8.18
ARG HERMES_AGENT_SHA=e624e9fde561e1add9388384012b295fde669ade

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HERMES_HOME=/data/hermes-home \
    HERMES_WORKDIR=/tmp/hermes-workspace \
    HERMES_TOOLSETS=terminal,web \
    TERMINAL_ENV=local \
    PATH="/opt/hermes-venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        iptables \
        iproute2 \
        nodejs \
        npm \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hermes-agent
RUN git init . \
    && git remote add origin https://github.com/NousResearch/hermes-agent.git \
    && git fetch --depth 1 origin "${HERMES_AGENT_SHA}" \
    && git checkout FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${HERMES_AGENT_SHA}" \
    || (echo "HERMES_AGENT_SHA mismatch: expected ${HERMES_AGENT_SHA}, got $(git rev-parse HEAD)" >&2; exit 1)

# Hermes blocks wheel builds; editable install is the supported dev/container path.
RUN python -m venv /opt/hermes-venv \
    && /opt/hermes-venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/hermes-venv/bin/pip install -e .

WORKDIR /app
COPY scripts/ ./scripts/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/scripts/*.py /app/scripts/*.sh \
    && mkdir -p /data/hermes-home /tmp/hermes-workspace

ENV PYTHONPATH=/opt/hermes-agent

ENTRYPOINT ["/entrypoint.sh"]
