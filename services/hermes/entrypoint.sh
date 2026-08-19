#!/bin/sh
set -eu

GATEWAY_URL="${GATEWAY_HEALTH_URL:-http://policy-gateway:8080/health}"
MAX_ATTEMPTS="${GATEWAY_WAIT_ATTEMPTS:-30}"
SLEEP_SECONDS="${GATEWAY_WAIT_INTERVAL_SECONDS:-2}"

attempt=1
while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  if curl -fsS "$GATEWAY_URL" >/dev/null; then
    echo "policy-gateway is healthy"
    break
  fi

  echo "waiting for policy-gateway ($attempt/$MAX_ATTEMPTS)..."
  attempt=$((attempt + 1))
  sleep "$SLEEP_SECONDS"
done

if [ "$attempt" -gt "$MAX_ATTEMPTS" ]; then
  echo "policy-gateway did not become healthy in time" >&2
  exit 1
fi

if ! command -v hermes >/dev/null 2>&1; then
  echo "hermes CLI missing after install" >&2
  exit 1
fi

if ! python -c "from tools.terminal_tool import terminal_tool" >/dev/null 2>&1; then
  echo "hermes terminal tool import failed" >&2
  exit 1
fi

if [ -z "${HTTP_PROXY:-}" ] || [ -z "${HTTPS_PROXY:-}" ]; then
  echo "HTTP_PROXY and HTTPS_PROXY must be set for policy-gated egress" >&2
  exit 1
fi

echo "Hermes agent ready (Phase 4)"
echo "HTTP_PROXY=${HTTP_PROXY:-unset}"
echo "HTTPS_PROXY=${HTTPS_PROXY:-unset}"
echo "HERMES_TOOLSETS=${HERMES_TOOLSETS:-unset}"

exec sleep infinity
