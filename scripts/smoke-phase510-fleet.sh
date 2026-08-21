#!/usr/bin/env bash
# Phase 5.10 — multi-gateway fleet smoke.
#
# Proves the acceptance criterion: one policy change made once against the
# control plane controls two physically separate gateway containers, without
# restarting either of them.
#
# The gateways decide policy from their cached snapshot, not from SQL, so the
# only path a new rule can take to them is the versioned snapshot fetch. That
# is what makes this demo mean something: the wait between "rule created" and
# "both gateways auto-approve" is real propagation, not a shared database read.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Pin the project name so network names are deterministic regardless of the
# checkout directory.
PROJECT="clearance-fleet"
COMPOSE="docker compose -p ${PROJECT} -f docker-compose.fleet.yml"
CONTROL_NET="${PROJECT}_control-net"
CURL_IMAGE="curlimages/curl:8.10.1"

# Everything talks to the control plane over the compose network rather than a
# published host port: port publishing is unreliable on some Docker hosts, and
# the fleet's whole point is that these components reach each other by service
# name anyway.
CONTROL="http://control-plane:8080"
ADMIN_TOKEN="${GATEWAY_ADMIN_TOKEN:-dev-local-admin-token}"
ORG_ID="11111111-1111-1111-1111-111111111010"
TARGET_HOST="example.com"
TARGET_PATH="/fleet-test"

# Refresh interval is 3s in docker-compose.fleet.yml; allow generous margin so
# the test is not flaky on a loaded machine.
REFRESH_WAIT="${FLEET_REFRESH_WAIT:-12}"

api() {
  docker run --rm --network "$CONTROL_NET" "$CURL_IMAGE" \
    -fsS -H "X-Admin-Token: ${ADMIN_TOKEN}" "$@"
}

control_health() {
  docker run --rm --network "$CONTROL_NET" "$CURL_IMAGE" \
    -fsS --max-time 5 "${CONTROL}/health" 2>/dev/null
}

fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "── $*"; }

cleanup() {
  if [ "${FLEET_KEEP_UP:-0}" != "1" ]; then
    echo
    echo "Tearing down fleet stack (set FLEET_KEEP_UP=1 to keep it)..."
    $COMPOSE down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
step "Step 1: start a clean fleet control plane"
# ---------------------------------------------------------------------------
$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d --build postgres control-plane >/dev/null

for _ in $(seq 1 40); do
  if control_health >/dev/null 2>&1; then break; fi
  sleep 2
done
control_health | grep -Fq '"status":"ok"' || fail "control plane did not become healthy"
echo "PASS: control plane healthy"

# ---------------------------------------------------------------------------
step "Step 2: seed Alice, Bob, Agent A, Agent B, Gateway A, Gateway B"
# ---------------------------------------------------------------------------
create_user() {
  api -X POST "${CONTROL}/api/v1/users" -H 'Content-Type: application/json' \
    -d "{\"display_name\":\"$1\",\"role\":\"member\"}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
}
alice_id="$(create_user Alice)"
bob_id="$(create_user Bob)"
[ -n "$alice_id" ] && [ -n "$bob_id" ] || fail "could not create users"
echo "  Alice=${alice_id}  Bob=${bob_id}"

register_agent() {
  api -X POST "${CONTROL}/api/v1/agents" -H 'Content-Type: application/json' \
    -d "{\"owner_user_id\":\"$1\",\"name\":\"$2\"}" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["agent"]["id"] + " " + d["credential"]["token"])'
}
read -r agent_a_id agent_a_token <<<"$(register_agent "$alice_id" agent-a)"
read -r agent_b_id agent_b_token <<<"$(register_agent "$bob_id" agent-b)"
[ -n "$agent_a_token" ] && [ -n "$agent_b_token" ] || fail "could not register agents"
echo "  AgentA=${agent_a_id}  AgentB=${agent_b_id}"

register_gateway() {
  api -X POST "${CONTROL}/api/v1/gateways" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$1\"}" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["gateway"]["id"] + " " + d["credential"]["token"])'
}
read -r gw_a_id gw_a_token <<<"$(register_gateway gateway-a)"
read -r gw_b_id gw_b_token <<<"$(register_gateway gateway-b)"
[ -n "$gw_a_token" ] && [ -n "$gw_b_token" ] || fail "could not register gateways"
echo "  GatewayA=${gw_a_id}  GatewayB=${gw_b_id}"

# Gateways can only start once they have a credential, so they come up here
# rather than in step 1.
export GATEWAY_A_TOKEN="$gw_a_token"
export GATEWAY_B_TOKEN="$gw_b_token"
$COMPOSE up -d --build gateway-a gateway-b >/dev/null
sleep 8

for gw in gateway-a gateway-b; do
  $COMPOSE logs "$gw" 2>&1 | grep -Fq "policy snapshot loaded" ||
    fail "$gw did not load an initial policy snapshot"
done
echo "PASS: both gateways registered and loaded an initial snapshot"

# ---------------------------------------------------------------------------
# Helper: issue a request as an agent, from that agent's own network, through
# its own gateway. Echoes the HTTP status the proxy returned.
# ---------------------------------------------------------------------------
agent_request() {
  local net="$1" gw="$2" token="$3"
  docker run --rm --network "${PROJECT}_${net}" "$CURL_IMAGE" \
    -s -o /dev/null -w '%{http_code}' --max-time 15 \
    -x "http://${gw}:8081" -H "Proxy-Authorization: Bearer ${token}" \
    "http://${TARGET_HOST}${TARGET_PATH}" 2>/dev/null || echo "000"
}

latest_status_for() {
  local agent_id="$1"
  api "${CONTROL}/api/v1/requests?agent_id=${agent_id}&limit=200" |
    python3 -c '
import json,sys
items=json.load(sys.stdin)["items"]
print(items[0]["status"] if items else "none")'
}

# ---------------------------------------------------------------------------
step "Step 3-4: both agents request ${TARGET_HOST}${TARGET_PATH} with no rule in force"
# ---------------------------------------------------------------------------
code_a="$(agent_request gateway-a-net gateway-a "$agent_a_token")"
code_b="$(agent_request gateway-b-net gateway-b "$agent_b_token")"
echo "  gateway-a returned HTTP ${code_a}, gateway-b returned HTTP ${code_b}"

[ "$(latest_status_for "$agent_a_id")" = "pending" ] || fail "agent A's request should be pending"
[ "$(latest_status_for "$agent_b_id")" = "pending" ] || fail "agent B's request should be pending"
echo "PASS: both gateways independently queued a pending request"

# ---------------------------------------------------------------------------
step "Step 5: admin creates ONE org-scoped allow rule in the control plane"
# ---------------------------------------------------------------------------
rule_id="$(api -X POST "${CONTROL}/api/v1/rules" -H 'Content-Type: application/json' \
  -d "{\"scope\":\"org\",\"scope_ref_id\":\"${ORG_ID}\",\"effect\":\"allow\",\"host\":\"${TARGET_HOST}\",\"port\":80,\"method\":\"*\",\"path_prefix\":\"/\"}" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
[ -n "$rule_id" ] || fail "could not create the org allow rule"
echo "  rule ${rule_id} created once, centrally"

# ---------------------------------------------------------------------------
step "Step 6: wait ${REFRESH_WAIT}s for both gateways to refresh their snapshot"
# ---------------------------------------------------------------------------
sleep "$REFRESH_WAIT"

# %-formatting rather than an f-string: Python < 3.12 rejects backslashes
# inside f-string expressions, and these keys are quoted.
policy_versions="$(api "${CONTROL}/api/v1/gateways" |
  python3 -c '
import json, sys
for g in json.load(sys.stdin)["items"]:
    print("  %s: policy_version=%s agents_seen=%s" % (g["name"], g["policy_version"], g["active_agents"]))')"
echo "$policy_versions"

# ---------------------------------------------------------------------------
step "Step 7-8: both agents retry — no container was restarted"
# ---------------------------------------------------------------------------
code_a="$(agent_request gateway-a-net gateway-a "$agent_a_token")"
code_b="$(agent_request gateway-b-net gateway-b "$agent_b_token")"
echo "  gateway-a returned HTTP ${code_a}, gateway-b returned HTTP ${code_b}"

status_a="$(latest_status_for "$agent_a_id")"
status_b="$(latest_status_for "$agent_b_id")"
[ "$status_a" = "auto_approved" ] || fail "agent A expected auto_approved, got ${status_a}"
[ "$status_b" = "auto_approved" ] || fail "agent B expected auto_approved, got ${status_b}"
echo "PASS: one central rule auto-approved traffic on BOTH separate gateways"

# ---------------------------------------------------------------------------
step "Step 9-10: revoke the rule centrally and wait for refresh"
# ---------------------------------------------------------------------------
api -X DELETE "${CONTROL}/api/v1/rules/${rule_id}" -o /dev/null
echo "  rule revoked; waiting ${REFRESH_WAIT}s"
sleep "$REFRESH_WAIT"

# ---------------------------------------------------------------------------
step "Step 11: both agents retry — auto-approval must be gone"
# ---------------------------------------------------------------------------
code_a="$(agent_request gateway-a-net gateway-a "$agent_a_token")"
code_b="$(agent_request gateway-b-net gateway-b "$agent_b_token")"
echo "  gateway-a returned HTTP ${code_a}, gateway-b returned HTTP ${code_b}"

status_a="$(latest_status_for "$agent_a_id")"
status_b="$(latest_status_for "$agent_b_id")"
[ "$status_a" != "auto_approved" ] || fail "agent A still auto-approved after central revoke"
[ "$status_b" != "auto_approved" ] || fail "agent B still auto-approved after central revoke"
echo "PASS: central revoke removed auto-approval from both gateways (A=${status_a}, B=${status_b})"

# ---------------------------------------------------------------------------
step "Step 12: verify every decision landed in the central audit trail"
# ---------------------------------------------------------------------------
audit_summary="$(api "${CONTROL}/api/v1/audit?limit=200" |
  python3 -c '
import json,sys
events=json.load(sys.stdin)["items"]
counts={}
for e in events:
    counts[e["event_type"]]=counts.get(e["event_type"],0)+1
for k in sorted(counts):
    print(f"  {k}: {counts[k]}")')"
echo "$audit_summary"

decisions="$(api "${CONTROL}/api/v1/requests?limit=200" |
  python3 -c '
import json,sys
items=json.load(sys.stdin)["items"]
fleet=[i for i in items if i["host"]=="'"${TARGET_HOST}"'" and i["path"]=="'"${TARGET_PATH}"'"]
print(len(fleet))')"
[ "$decisions" -ge 6 ] || fail "expected at least 6 fleet egress decisions centrally, found ${decisions}"
echo "PASS: ${decisions} fleet decisions recorded centrally from two separate gateways"

# ---------------------------------------------------------------------------
step "Bypass prevention still holds"
# ---------------------------------------------------------------------------
if docker run --rm --network "${PROJECT}_gateway-a-net" "$CURL_IMAGE" \
    -fsS --max-time 5 "http://${TARGET_HOST}${TARGET_PATH}" >/dev/null 2>&1; then
  fail "an agent-side network reached the internet without its gateway"
fi
echo "PASS: agent networks have no direct egress"

if docker run --rm --network "${PROJECT}_gateway-a-net" "$CURL_IMAGE" \
    -fsS --max-time 5 "http://postgres:5432" >/dev/null 2>&1; then
  fail "an agent-side network reached postgres"
fi
echo "PASS: agent networks cannot reach postgres"

echo
echo "Phase 5.10 fleet smoke passed: one policy change, two independent gateways, no restarts."
