#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Checking gateway health..."
curl -fsS http://localhost:8080/health | grep -q '"status":"ok"'

echo "Checking hermes cannot reach postgres (network isolation)..."
if docker compose exec -T hermes sh -c 'curl -fsS --max-time 3 postgres:5432 >/dev/null 2>&1'; then
  echo "FAIL: hermes can reach postgres directly" >&2
  exit 1
fi
echo "PASS: hermes cannot reach postgres"

echo "Checking hermes cannot reach public internet directly..."
if docker compose exec -T hermes sh -c 'curl -fsS --max-time 5 https://example.com >/dev/null 2>&1'; then
  echo "FAIL: hermes reached the public internet without the gateway" >&2
  exit 1
fi
echo "PASS: hermes has no direct internet egress"

echo "Checking proxied HTTPS request is blocked and persisted..."
before_count="$(curl -fsS "http://localhost:8080/api/v1/requests?status=pending" | grep -o '"host"' | wc -l | tr -d ' ')"
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 5 https://example.com >/dev/null' || true
after_count="$(curl -fsS "http://localhost:8080/api/v1/requests?status=pending" | grep -o '"host":"example.com"' | wc -l | tr -d ' ')"
if [ "$after_count" -lt 1 ]; then
  echo "FAIL: proxied request did not create a pending row for example.com" >&2
  exit 1
fi
echo "PASS: proxied request created pending egress row"

echo "Phase 1 smoke checks passed"
