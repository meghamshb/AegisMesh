#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
ADMIN_TOKEN="${GATEWAY_ADMIN_TOKEN:-dev-local-admin-token}"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <owner_user_id> <agent_name> [container_id]" >&2
  echo "Example: $0 11111111-1111-1111-1111-111111111001 alice-macbook-hermes" >&2
  exit 1
fi

OWNER_USER_ID="$1"
AGENT_NAME="$2"
CONTAINER_ID="${3:-}"

BODY="$(python3 -c '
import json, sys
owner_user_id, name, container_id = sys.argv[1], sys.argv[2], sys.argv[3]
payload = {"owner_user_id": owner_user_id, "name": name}
if container_id:
    payload["container_id"] = container_id
print(json.dumps(payload))
' "$OWNER_USER_ID" "$AGENT_NAME" "$CONTAINER_ID")"

RESPONSE="$(curl -fsS -X POST \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$BODY" \
  "${GATEWAY_URL}/api/v1/agents")"

echo "Agent registered."
echo
echo "$RESPONSE" | python3 -c '
import json, sys
data = json.load(sys.stdin)
agent = data["agent"]
cred = data["credential"]
name = agent["name"]
agent_id = agent["id"]
owner = agent["owner_display_name"]
token = cred["token"]
print("  Name:  " + name)
print("  ID:    " + agent_id)
print("  Owner: " + owner)
print()
print("  Credential: " + token)
print()
print("This credential is shown once. Copy it now.")
print("Configure Hermes with: CLEARANCE_AGENT_TOKEN=" + token)
'
