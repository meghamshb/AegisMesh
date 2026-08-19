#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ADMIN_TOKEN="${GATEWAY_ADMIN_TOKEN:-dev-local-admin-token}"

api_curl() {
  curl -fsS -H "X-Admin-Token: ${ADMIN_TOKEN}" "$@"
}

echo "Checking gateway health..."
health_body="$(curl -fsS http://localhost:8080/health)"
echo "$health_body" | grep -Fq '"status":"ok"'

echo "Checking approval UI is served..."
ui_body="$(curl -fsS http://localhost:8080/ui)"
echo "$ui_body" | grep -Fq 'Hermes Policy Gateway'

echo "Resetting request, rule, and audit history for a clean smoke run..."
docker compose exec -T postgres psql -U hermes -d hermes_policy -c \
  "TRUNCATE TABLE audit_events, egress_requests, policy_rules RESTART IDENTITY CASCADE;"
docker compose exec -T postgres psql -U hermes -d hermes_policy -c \
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_rules_dedup ON policy_rules (org_id, scope, scope_ref_id, effect, host, port, method, path_prefix);"

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
if ! api_curl "http://localhost:8080/api/v1/requests?status=pending" | grep -q '"host":"example.com"'; then
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
if ! api_curl "http://localhost:8080/api/v1/requests?status=pending" | grep -q '"host":"api.github.com"'; then
  echo "FAIL: GitHub API block did not create a pending row" >&2
  exit 1
fi

request_id="$(api_curl "http://localhost:8080/api/v1/requests?status=pending" | python3 -c 'import json,sys; items=[i for i in json.load(sys.stdin)["items"] if i["host"]=="api.github.com"]; print(items[-1]["id"] if items else "")')"
if [ -z "$request_id" ]; then
  echo "FAIL: could not find pending request for api.github.com" >&2
  exit 1
fi

api_curl -X POST "http://localhost:8080/api/v1/requests/${request_id}/approve" \
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
deny_request_id="$(api_curl "http://localhost:8080/api/v1/requests?status=pending" | python3 -c 'import json,sys; items=[i for i in json.load(sys.stdin)["items"] if i["host"]=="httpbin.org"]; print(items[-1]["id"] if items else "")')"
if [ -z "$deny_request_id" ]; then
  echo "FAIL: could not find pending request for httpbin.org" >&2
  exit 1
fi
api_curl -X POST "http://localhost:8080/api/v1/requests/${deny_request_id}/deny" \
  -H 'Content-Type: application/json' \
  -d '{"feedback":"blocked in smoke test"}' | grep -q '"status":"denied"'
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 10 https://httpbin.org/get >/dev/null' >/tmp/phase2-deny-retry.log 2>&1 || true
if ! grep -q '403' /tmp/phase2-deny-retry.log; then
  echo "FAIL: denied destination should remain blocked on retry" >&2
  cat /tmp/phase2-deny-retry.log >&2
  exit 1
fi
echo "PASS: denied destination remains blocked on retry"

echo "Checking approve-and-remember creates org rule and auto-approves retry..."
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 10 http://jsonplaceholder.typicode.com/todos/1 >/dev/null' >/tmp/phase3-org-blocked.log 2>&1 || true
org_request_id="$(api_curl "http://localhost:8080/api/v1/requests?status=pending" | python3 -c 'import json,sys; items=[i for i in json.load(sys.stdin)["items"] if i["host"]=="jsonplaceholder.typicode.com"]; print(items[-1]["id"] if items else "")')"
if [ -z "$org_request_id" ]; then
  echo "FAIL: jsonplaceholder request did not create a pending row" >&2
  cat /tmp/phase3-org-blocked.log >&2
  exit 1
fi

api_curl -X POST "http://localhost:8080/api/v1/requests/${org_request_id}/approve" \
  -H 'Content-Type: application/json' \
  -d '{"remember":true,"scope":"org"}' | grep -q '"status":"approved"'

if ! api_curl "http://localhost:8080/api/v1/rules" | grep -q '"host":"jsonplaceholder.typicode.com"'; then
  echo "FAIL: org allow rule was not created" >&2
  exit 1
fi

json_body="$(docker compose exec -T hermes sh -c 'curl -fsS -x http://policy-gateway:8080 --max-time 15 http://jsonplaceholder.typicode.com/todos/1')"
if [ -z "$json_body" ]; then
  echo "FAIL: jsonplaceholder retry failed after org rule approval" >&2
  exit 1
fi

if ! api_curl "http://localhost:8080/api/v1/requests?status=auto_approved" | grep -q '"host":"jsonplaceholder.typicode.com"'; then
  echo "FAIL: retry did not create auto_approved row with org rule" >&2
  exit 1
fi
if ! api_curl "http://localhost:8080/api/v1/requests?status=auto_approved" | grep -q '"rule_id"'; then
  echo "FAIL: auto_approved row missing rule_id" >&2
  exit 1
fi
echo "PASS: org rule auto-approved matching retry with rule_id"

echo "Checking CONNECT remember is rejected..."
docker compose exec -T hermes sh -c 'curl -sS -x http://policy-gateway:8080 --max-time 10 https://example.org/ >/dev/null' >/tmp/phase3-connect-blocked.log 2>&1 || true
connect_request_id="$(api_curl "http://localhost:8080/api/v1/requests?status=pending" | python3 -c 'import json,sys; items=[i for i in json.load(sys.stdin)["items"] if i["host"]=="example.org" and i["method"]=="CONNECT"]; print(items[-1]["id"] if items else "")')"
if [ -z "$connect_request_id" ]; then
  echo "FAIL: could not find pending CONNECT request for example.org" >&2
  exit 1
fi
connect_code="$(curl -sS -o /tmp/phase3-connect-remember.body -w '%{http_code}' -X POST "http://localhost:8080/api/v1/requests/${connect_request_id}/approve" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"remember":true,"scope":"org"}')"
if [ "$connect_code" != "400" ]; then
  echo "FAIL: CONNECT remember should return 400, got ${connect_code}" >&2
  cat /tmp/phase3-connect-remember.body >&2
  exit 1
fi
if ! grep -q 'not allowed for CONNECT' /tmp/phase3-connect-remember.body; then
  echo "FAIL: expected CONNECT remember rejection message" >&2
  cat /tmp/phase3-connect-remember.body >&2
  exit 1
fi
echo "PASS: CONNECT remember rejected"

echo "Checking POST /api/v1/rules manual bootstrap..."
manual_code="$(curl -sS -o /tmp/phase35-manual-rule.body -w '%{http_code}' -X POST "http://localhost:8080/api/v1/rules" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"org","effect":"allow","host":"httpstat.us","port":80,"method":"GET","path_prefix":"/200"}')"
if [ "$manual_code" != "201" ]; then
  echo "FAIL: POST /api/v1/rules should return 201, got ${manual_code}" >&2
  cat /tmp/phase35-manual-rule.body >&2
  exit 1
fi
echo "PASS: manual policy rule created"

echo "Checking second agent auto-approves via org rule..."
docker compose exec -T postgres psql -U hermes -d hermes_policy -v ON_ERROR_STOP=1 -c \
  "INSERT INTO actors (id, type, org_id, display_name) VALUES ('11111111-1111-1111-1111-111111111003', 'user', '11111111-1111-1111-1111-111111111010', 'Second User') ON CONFLICT (id) DO NOTHING; INSERT INTO agents (id, actor_id, name, container_id) VALUES ('11111111-1111-1111-1111-111111111021', '11111111-1111-1111-1111-111111111003', 'hermes-agent-2', 'hermes') ON CONFLICT (id) DO NOTHING;"
AGENT2_ID="11111111-1111-1111-1111-111111111021"
agent2_body="$(docker compose exec -T hermes sh -c "curl -fsS -x http://policy-gateway:8080 -H 'X-Gateway-Agent-Id: ${AGENT2_ID}' --max-time 15 http://jsonplaceholder.typicode.com/todos/1")"
if [ -z "$agent2_body" ]; then
  echo "FAIL: second agent request failed after org rule exists" >&2
  exit 1
fi
if ! api_curl "http://localhost:8080/api/v1/requests?status=auto_approved&agent_id=${AGENT2_ID}" | grep -q '"host":"jsonplaceholder.typicode.com"'; then
  echo "FAIL: second agent did not get auto_approved via org rule" >&2
  exit 1
fi
echo "PASS: cross-agent org rule auto-approval"

echo "Checking real Hermes install (Phase 4)..."
if ! docker compose exec -T hermes sh -c 'command -v hermes >/dev/null && python -c "from tools.terminal_tool import terminal_tool"'; then
  echo "FAIL: Hermes agent runtime is not installed in the hermes container" >&2
  exit 1
fi
echo "PASS: Hermes CLI and terminal tool available"

echo "Checking Hermes terminal tool triggers pending egress..."
set +e
docker compose exec -T hermes python /app/scripts/hermes-terminal-fetch.py https://icanhazip.com >/tmp/phase4-terminal-blocked.log 2>&1
phase4_blocked_rc=$?
set -e
if [ "$phase4_blocked_rc" -eq 0 ]; then
  echo "FAIL: Hermes terminal tool fetch should exit non-zero before approval" >&2
  cat /tmp/phase4-terminal-blocked.log >&2
  exit 1
fi
if grep -q 'http_code=200' /tmp/phase4-terminal-blocked.log; then
  echo "FAIL: Hermes terminal tool fetch should be blocked before approval" >&2
  cat /tmp/phase4-terminal-blocked.log >&2
  exit 1
fi
if ! api_curl "http://localhost:8080/api/v1/requests?status=pending" | grep -q '"host":"icanhazip.com"'; then
  echo "FAIL: Hermes terminal tool fetch did not create pending row for icanhazip.com" >&2
  cat /tmp/phase4-terminal-blocked.log >&2
  exit 1
fi
phase4_request_id="$(api_curl "http://localhost:8080/api/v1/requests?status=pending" | python3 -c 'import json,sys; items=[i for i in json.load(sys.stdin)["items"] if i["host"]=="icanhazip.com"]; print(items[-1]["id"] if items else "")')"
if [ -z "$phase4_request_id" ]; then
  echo "FAIL: could not find pending request for icanhazip.com" >&2
  exit 1
fi
api_curl -X POST "http://localhost:8080/api/v1/requests/${phase4_request_id}/approve" \
  -H 'Content-Type: application/json' \
  -d '{}' | grep -q '"status":"approved"'
phase4_body="$(docker compose exec -T hermes python /app/scripts/hermes-terminal-fetch.py https://icanhazip.com 2>/tmp/phase4-terminal-retry.log)"
if [ -z "$phase4_body" ]; then
  echo "FAIL: Hermes terminal tool retry failed after approve-once" >&2
  cat /tmp/phase4-terminal-retry.log >&2
  exit 1
fi
if ! echo "$phase4_body" | grep -q 'http_code=200'; then
  echo "FAIL: expected http_code=200 after approval, got: $phase4_body" >&2
  cat /tmp/phase4-terminal-retry.log >&2
  exit 1
fi
echo "PASS: Hermes terminal tool egress approved end-to-end"

echo "Checking proxied postgres access is hard-denied (SSRF guard)..."
postgres_ip="$(docker compose exec -T policy-gateway getent hosts postgres | awk '{print $1; exit}')"
if [ -z "$postgres_ip" ]; then
  echo "FAIL: could not resolve postgres IP on policy-gateway" >&2
  exit 1
fi
ssrf_code="$(curl -sS -o /tmp/phase4-ssrf-postgres.body -w '%{http_code}' -x http://localhost:8080 --max-time 5 "http://${postgres_ip}:5432/" 2>/dev/null || true)"
if [ "$ssrf_code" != "403" ]; then
  echo "FAIL: proxied postgres IP access should return 403, got ${ssrf_code}" >&2
  cat /tmp/phase4-ssrf-postgres.body >&2
  exit 1
fi
if ! grep -q 'internal destination blocked' /tmp/phase4-ssrf-postgres.body; then
  echo "FAIL: expected internal destination blocked message for postgres SSRF" >&2
  cat /tmp/phase4-ssrf-postgres.body >&2
  exit 1
fi
if api_curl "http://localhost:8080/api/v1/requests?status=pending" | grep -q "\"host\":\"${postgres_ip}\""; then
  echo "FAIL: internal postgres target should not create pending approval row" >&2
  exit 1
fi
echo "PASS: proxied postgres access blocked without approval queue"

echo "Phase 2, Phase 3, Phase 3.5, and Phase 4 smoke checks passed"
