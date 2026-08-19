#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Checking gateway health..."
curl -fsS http://localhost:8080/health | grep -q '"status":"ok"'

echo "Checking approval UI is served..."
curl -fsS http://localhost:8080/ui | grep -q 'Hermes Policy Gateway'

echo "Resetting request and audit history for a clean smoke run..."
docker compose exec -T postgres psql -U hermes -d hermes_policy -c \
  "TRUNCATE TABLE audit_events, egress_requests RESTART IDENTITY;"

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
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 5 https://example.com >/dev/null' || true
if ! curl -fsS "http://localhost:8080/api/v1/requests?status=pending" | grep -q '"host":"example.com"'; then
  echo "FAIL: proxied request did not create a pending row for example.com" >&2
  exit 1
fi
echo "PASS: proxied request created pending egress row"

echo "Checking approve-once allows retry for GitHub API..."
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 10 https://api.github.com/zen >/dev/null' >/tmp/phase2-github-blocked.log 2>&1 || true
if ! grep -q '403' /tmp/phase2-github-blocked.log; then
  echo "FAIL: expected initial GitHub API call to be blocked with 403" >&2
  cat /tmp/phase2-github-blocked.log >&2
  exit 1
fi
if ! curl -fsS "http://localhost:8080/api/v1/requests?status=pending" | grep -q '"host":"api.github.com"'; then
  echo "FAIL: GitHub API block did not create a pending row" >&2
  exit 1
fi

request_id="$(curl -fsS "http://localhost:8080/api/v1/requests?status=pending" | python3 -c 'import json,sys; items=[i for i in json.load(sys.stdin)["items"] if i["host"]=="api.github.com"]; print(items[-1]["id"] if items else "")')"
if [ -z "$request_id" ]; then
  echo "FAIL: could not find pending request for api.github.com" >&2
  exit 1
fi

curl -fsS -X POST "http://localhost:8080/api/v1/requests/${request_id}/approve" \
  -H 'Content-Type: application/json' \
  -d '{}' | grep -q '"status":"approved"'

github_body="$(docker compose exec -T hermes sh -c 'curl -fsS -x http://policy-gateway:8080 --max-time 15 https://api.github.com/zen')"
if [ -z "$github_body" ]; then
  echo "FAIL: GitHub API retry failed after approve-once" >&2
  exit 1
fi
echo "PASS: approve-once unblocked GitHub API retry"

echo "Checking deny keeps destination blocked..."
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 10 https://httpbin.org/get >/dev/null' >/tmp/phase2-deny-blocked.log 2>&1 || true
if ! grep -q '403' /tmp/phase2-deny-blocked.log; then
  echo "FAIL: expected httpbin request to be blocked with 403" >&2
  cat /tmp/phase2-deny-blocked.log >&2
  exit 1
fi
deny_request_id="$(curl -fsS "http://localhost:8080/api/v1/requests?status=pending" | python3 -c 'import json,sys; items=[i for i in json.load(sys.stdin)["items"] if i["host"]=="httpbin.org"]; print(items[-1]["id"] if items else "")')"
if [ -z "$deny_request_id" ]; then
  echo "FAIL: could not find pending request for httpbin.org" >&2
  exit 1
fi
curl -fsS -X POST "http://localhost:8080/api/v1/requests/${deny_request_id}/deny" \
  -H 'Content-Type: application/json' \
  -d '{"feedback":"blocked in smoke test"}' | grep -q '"status":"denied"'
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 10 https://httpbin.org/get >/dev/null' >/tmp/phase2-deny-retry.log 2>&1 || true
if ! grep -q '403' /tmp/phase2-deny-retry.log; then
  echo "FAIL: denied destination should remain blocked on retry" >&2
  cat /tmp/phase2-deny-retry.log >&2
  exit 1
fi
echo "PASS: denied destination remains blocked on retry"

echo "Phase 2 smoke checks passed"
