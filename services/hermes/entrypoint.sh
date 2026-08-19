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

echo "Hermes stub ready"
echo "HTTP_PROXY=${HTTP_PROXY:-unset}"
echo "HTTPS_PROXY=${HTTPS_PROXY:-unset}"
echo "Phase 0: agent runtime will replace this container in phase 4"

exec sleep infinity
