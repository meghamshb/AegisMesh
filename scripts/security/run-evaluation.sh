#!/usr/bin/env bash
# Phase 5.12 — reproducible egress security evaluation.
#
# Runs every bypass attempt in docs/security/egress-bypass-evaluation.md against
# a real stack and regenerates that document from the measured results. The
# numbers in the document come from this script; nothing there is hand-written.
#
# It evaluates the FLEET configuration (docker-compose.fleet.yml) rather than
# the default single-node one, because that is the production-like posture:
# agent identity comes from a credential (GATEWAY_AGENT_AUTH_MODE=token) and
# the control plane is a separate process. The default docker-compose.yml
# enables GATEWAY_ALLOW_IDENTITY_OVERRIDE for local convenience, which the
# identity cases below would correctly fail against - see the "Configuration
# under test" section of the generated document.
#
#   ./scripts/security/run-evaluation.sh          run and regenerate the doc
#   KEEP_UP=1 ./scripts/security/run-evaluation.sh   leave the stack running
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=scripts/security/lib.sh
source "${ROOT}/scripts/security/lib.sh"

PROJECT="clearance-sec"
COMPOSE="docker compose -p ${PROJECT} -f docker-compose.fleet.yml"
CONTROL_NET="${PROJECT}_control-net"
AGENT_NET="${PROJECT}_gateway-a-net"
CURL_IMAGE="curlimages/curl:8.10.1"
ALPINE_IMAGE="alpine:3.20"
CONTROL="http://control-plane:8080"
GATEWAY="http://gateway-a:8081"
ADMIN_TOKEN="${GATEWAY_ADMIN_TOKEN:-dev-local-admin-token}"
ORG_ID="11111111-1111-1111-1111-111111111010"
DOC="docs/security/egress-bypass-evaluation.md"

# A public host used as the "ordinary unapproved destination".
PUBLIC_HOST="example.com"

api() {
  docker run --rm --network "$CONTROL_NET" "$CURL_IMAGE" \
    -fsS -H "X-Admin-Token: ${ADMIN_TOKEN}" "$@"
}

cleanup() {
  if [ "${KEEP_UP:-0}" != "1" ]; then
    echo
    echo "Tearing down evaluation stack (KEEP_UP=1 to keep it)..."
    $COMPOSE down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Probe helpers.
#
# in_agent runs inside the real Hermes container - the actual agent runtime,
# with its real toolchain and its real network position.
# ---------------------------------------------------------------------------
in_agent() { $COMPOSE exec -T hermes-a sh -c "$1" 2>&1; }

# agent_proxy_probe <shell-snippet-producing-"CODE|BODY">
agent_proxy_probe() {
  local cmd="$1"
  local out code body
  out="$(in_agent "$cmd")"
  code="${out%%|*}"
  body="${out#*|}"
  classify_proxy_response "$code" "$body"
}

# run_probe_in_agent <interpreter> <file> <script>
#
# Ships a script into the agent container base64-encoded. Passing a multi-line
# program through `docker exec sh -c "..."` requires several layers of nested
# quoting, which silently corrupts it - the python and node probes reported
# "error" for exactly that reason, not because the gateway misbehaved.
run_probe_in_agent() {
  local interpreter="$1" file="$2" script="$3"
  local b64
  b64="$(printf '%s' "$script" | base64 | tr -d '\n')"
  local out
  out="$(in_agent "echo ${b64} | base64 -d > ${file} && ${interpreter} ${file}")"
  # The probe prints CODE|BODY on its last line.
  printf '%s' "$out" | tail -1
}

# curl_through_proxy <url> [extra curl args]
# --noproxy '' clears the image's NO_PROXY (which lists localhost and
# 127.0.0.1). Without it curl silently bypasses the proxy for exactly the hosts
# the SSRF cases need to reach the gateway, and the guard is never exercised.
#
# curl exit 56 with an empty body is a refused CONNECT: the proxy answered
# non-200 to the tunnel request, so there is no HTTP response body to read.
# That is a mediated tunnel, not an unreachable host.
curl_through_proxy() {
  local url="$1"; shift
  local out code body rc
  out="$(in_agent "curl -s --noproxy '' -o /tmp/b -w '%{http_code}' --max-time 12 -x ${GATEWAY} -H 'Proxy-Authorization: Bearer ${AGENT_A_TOKEN}' $* '${url}' 2>/tmp/e; echo \"|\$?|\$(cat /tmp/b 2>/dev/null)\$(cat /tmp/e 2>/dev/null)\"")"
  code="$(printf '%s' "$out" | cut -d'|' -f1)"
  rc="$(printf '%s' "$out" | cut -d'|' -f2)"
  body="$(printf '%s' "$out" | cut -d'|' -f3-)"
  if [ "$code" = "000" ] && [ "$rc" = "56" ]; then
    # CONNECT refused by the proxy. Distinguish a hard SSRF denial from a
    # policy block using the tunnel status curl reports.
    if printf '%s' "$body" | grep -Fq "$SSRF_MARKER"; then echo "blocked"; return; fi
    echo "mediated"
    return
  fi
  classify_proxy_response "$code" "$body"
}

echo "══════════════════════════════════════════════"
echo " Clearance egress security evaluation"
echo "══════════════════════════════════════════════"

results_init

# ---------------------------------------------------------------------------
echo
echo "▸ Bringing up the evaluation stack"
# ---------------------------------------------------------------------------
$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d --build postgres control-plane >/dev/null 2>&1

for _ in $(seq 1 40); do
  docker run --rm --network "$CONTROL_NET" "$CURL_IMAGE" \
    -fsS --max-time 5 "${CONTROL}/health" >/dev/null 2>&1 && break
  sleep 2
done

alice="$(api -X POST "${CONTROL}/api/v1/users" -H 'Content-Type: application/json' \
  -d '{"display_name":"Alice","role":"member"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

read -r AGENT_A_ID AGENT_A_TOKEN <<<"$(api -X POST "${CONTROL}/api/v1/agents" \
  -H 'Content-Type: application/json' -d "{\"owner_user_id\":\"${alice}\",\"name\":\"agent-a\"}" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["agent"]["id"], d["credential"]["token"])')"

read -r REVOKED_AGENT_ID REVOKED_TOKEN <<<"$(api -X POST "${CONTROL}/api/v1/agents" \
  -H 'Content-Type: application/json' -d "{\"owner_user_id\":\"${alice}\",\"name\":\"agent-revoked\"}" |
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["agent"]["id"], d["credential"]["token"])')"
api -X POST "${CONTROL}/api/v1/agents/${REVOKED_AGENT_ID}/revoke" -o /dev/null

read -r GW_A_ID GW_A_TOKEN <<<"$(api -X POST "${CONTROL}/api/v1/gateways" \
  -H 'Content-Type: application/json' -d '{"name":"gateway-a"}' |
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["gateway"]["id"], d["credential"]["token"])')"
read -r GW_B_ID GW_B_TOKEN <<<"$(api -X POST "${CONTROL}/api/v1/gateways" \
  -H 'Content-Type: application/json' -d '{"name":"gateway-b"}' |
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["gateway"]["id"], d["credential"]["token"])')"

# A second organization, with its own agent, for the cross-org cases.
docker run --rm --network "$CONTROL_NET" -i postgres:16-alpine \
  psql "postgres://hermes:hermes@postgres:5432/hermes_policy?sslmode=disable" -q <<'SQL' >/dev/null 2>&1
INSERT INTO organizations (id, slug, name) VALUES
  ('22222222-2222-2222-2222-222222222010','evil','Other Org') ON CONFLICT DO NOTHING;
INSERT INTO actors (id, type, org_id, display_name, role, status) VALUES
  ('22222222-2222-2222-2222-222222222001','user','22222222-2222-2222-2222-222222222010','Mallory','member','active') ON CONFLICT DO NOTHING;
INSERT INTO agents (id, org_id, actor_id, name, status) VALUES
  ('22222222-2222-2222-2222-222222222020','22222222-2222-2222-2222-222222222010','22222222-2222-2222-2222-222222222001','other-org-agent','active') ON CONFLICT DO NOTHING;
SQL

# Mint a credential for the other org's agent, hashed the same way the service
# would, so the cross-org case uses a genuinely valid token.
OTHER_ORG_TOKEN="clr_agent_evaluation-other-org-token"
OTHER_ORG_HASH="$(printf '%s' "$OTHER_ORG_TOKEN" | shasum -a 256 | cut -d' ' -f1)"
docker run --rm --network "$CONTROL_NET" -i postgres:16-alpine \
  psql "postgres://hermes:hermes@postgres:5432/hermes_policy?sslmode=disable" -q <<SQL >/dev/null 2>&1
INSERT INTO agent_credentials (agent_id, token_prefix, token_hash, status)
VALUES ('22222222-2222-2222-2222-222222222020','clr_agent_eval','${OTHER_ORG_HASH}','active')
ON CONFLICT DO NOTHING;
SQL

export GATEWAY_A_TOKEN="$GW_A_TOKEN" GATEWAY_B_TOKEN="$GW_B_TOKEN"
$COMPOSE up -d --build gateway-a gateway-b hermes-a >/dev/null 2>&1

# Same reasoning as the fleet smoke: wait for readiness rather than guessing.
for _ in $(seq 1 40); do
  if $COMPOSE logs gateway-a 2>&1 | grep -Fq "policy snapshot loaded" &&
     $COMPOSE exec -T hermes-a true >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "  stack ready (agent=${AGENT_A_ID}, gateway=${GW_A_ID})"

# ---------------------------------------------------------------------------
echo
echo "▸ A. Tool diversity — every client library must be mediated, not bypassed"
# ---------------------------------------------------------------------------
record_case "EGR-01" "curl HTTP via proxy" "mediated" \
  "$(curl_through_proxy "http://${PUBLIC_HOST}/")" "real agent container"

record_case "EGR-02" "curl HTTPS (CONNECT) via proxy" "mediated" \
  "$(curl_through_proxy "https://${PUBLIC_HOST}/")" "CONNECT tunnel gated on host"

py_requests_probe="$(run_probe_in_agent python3 /tmp/p_req.py "
import requests
proxies = {'http': '${GATEWAY}', 'https': '${GATEWAY}'}
headers = {'Proxy-Authorization': 'Bearer ${AGENT_A_TOKEN}'}
try:
    r = requests.get('http://${PUBLIC_HOST}/', proxies=proxies, headers=headers, timeout=12)
    print(str(r.status_code) + '|' + r.text[:200].replace(chr(10), ' '))
except Exception as exc:
    print('000|' + str(exc))
")"
record_case "EGR-03" "Python requests via proxy" "mediated" \
  "$(classify_proxy_response "${py_requests_probe%%|*}" "${py_requests_probe#*|}")" \
  "third-party HTTP client"

py_urllib_probe="$(run_probe_in_agent python3 /tmp/p_url.py "
import urllib.request as u
opener = u.build_opener(u.ProxyHandler({'http': '${GATEWAY}'}))
opener.addheaders = [('Proxy-Authorization', 'Bearer ${AGENT_A_TOKEN}')]
try:
    r = opener.open('http://${PUBLIC_HOST}/', timeout=12)
    print(str(r.status) + '|' + r.read(200).decode('utf8', 'replace').replace(chr(10), ' '))
except Exception as exc:
    body = b''
    if hasattr(exc, 'read'):
        body = exc.read()
    code = getattr(exc, 'code', 0) or 0
    print(str(code).zfill(3) + '|' + body.decode('utf8', 'replace').replace(chr(10), ' '))
")"
record_case "EGR-04" "Python urllib via proxy" "mediated" \
  "$(classify_proxy_response "${py_urllib_probe%%|*}" "${py_urllib_probe#*|}")" \
  "stdlib HTTP client"

node_probe="$(run_probe_in_agent node /tmp/p_node.js "
const http = require('http');
const req = http.request({
  host: 'gateway-a', port: 8081, method: 'GET',
  path: 'http://${PUBLIC_HOST}/',
  headers: {
    'Proxy-Authorization': 'Bearer ${AGENT_A_TOKEN}',
    'Host': '${PUBLIC_HOST}'
  }
}, res => {
  let b = '';
  res.on('data', d => b += d);
  res.on('end', () => console.log(res.statusCode + '|' + b.slice(0, 200).replace(/\n/g, ' ')));
});
req.on('error', e => console.log('000|' + e.message));
req.end();
")"
record_case "EGR-05" "Node http via proxy" "mediated" \
  "$(classify_proxy_response "${node_probe%%|*}" "${node_probe#*|}")" \
  "node stdlib client"

wget_out="$(docker run --rm --network "$AGENT_NET" -e "http_proxy=${GATEWAY}" "$ALPINE_IMAGE" \
  wget -q -O- --timeout=12 --header="Proxy-Authorization: Bearer ${AGENT_A_TOKEN}" \
  "http://${PUBLIC_HOST}/" 2>&1; echo "rc=$?")"
if printf '%s' "$wget_out" | grep -Fq "$PENDING_MARKER"; then
  wget_actual="mediated"
elif printf '%s' "$wget_out" | grep -Fq "$SSRF_MARKER"; then
  wget_actual="blocked"
elif printf '%s' "$wget_out" | grep -q "rc=0"; then
  wget_actual="allowed"
else
  wget_actual="mediated"
fi
record_case "EGR-06" "wget via proxy" "mediated" "$wget_actual" \
  "busybox wget; not present in the Hermes image"

# ---------------------------------------------------------------------------
echo
echo "▸ B. Proxy evasion — the network must catch what the proxy cannot see"
# ---------------------------------------------------------------------------
direct_probe() {
  local target="$1"
  local out
  out="$(in_agent "env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    curl -s -o /dev/null -w '%{http_code}' --max-time 8 '${target}'; echo \"|rc=\$?\"")"
  case "$out" in
    2*|3*) echo "allowed" ;;
    *)     echo "unreachable" ;;
  esac
}

record_case "EGR-07" "Raw socket to public host, no proxy" "unreachable" \
  "$(in_agent "python3 -c \"
import socket
try:
    s=socket.create_connection(('${PUBLIC_HOST}',80),timeout=8); s.close(); print('allowed')
except Exception: print('unreachable')
\"")" "Docker network lockdown, not the proxy"

record_case "EGR-08" "Direct HTTP with proxy env unset" "unreachable" \
  "$(direct_probe "http://${PUBLIC_HOST}/")" "agent net is internal:true"

record_case "EGR-09" "Lowercase proxy env variant" "mediated" \
  "$(agent_proxy_probe "env -u HTTP_PROXY http_proxy=${GATEWAY} \
     curl -s -o /tmp/b2 -w '%{http_code}' --max-time 12 \
     -H 'Proxy-Authorization: Bearer ${AGENT_A_TOKEN}' 'http://${PUBLIC_HOST}/'; \
     echo \"|\$(cat /tmp/b2 2>/dev/null)\"")" "casing does not change enforcement"

record_case "EGR-10" "NO_PROXY=* to escape the proxy" "unreachable" \
  "$(in_agent "NO_PROXY='*' no_proxy='*' curl -s -o /dev/null -w '%{http_code}' \
     --max-time 8 'http://${PUBLIC_HOST}/' >/dev/null 2>&1 && echo allowed || echo unreachable")" \
  "NO_PROXY only removes the proxy; egress is still blocked"

# ---------------------------------------------------------------------------
echo
echo "▸ C. SSRF — internal targets must be hard-denied, never queued"
# ---------------------------------------------------------------------------
ssrf_case() {
  local id="$1" label="$2" url="$3" notes="${4:-}"
  record_case "$id" "$label" "blocked" "$(curl_through_proxy "$url")" "$notes"
}

ssrf_case "SSRF-01" "Proxy to localhost"            "http://localhost/"          ""
ssrf_case "SSRF-02" "Proxy to 127.0.0.1"            "http://127.0.0.1/"          ""
ssrf_case "SSRF-03" "Proxy to RFC1918 10.0.0.0/8"   "http://10.0.0.1/"           ""
ssrf_case "SSRF-04" "Proxy to RFC1918 172.16/12"    "http://172.16.0.1/"         ""
ssrf_case "SSRF-05" "Proxy to RFC1918 192.168/16"   "http://192.168.0.1/"        ""
ssrf_case "SSRF-06" "Proxy to link-local metadata"  "http://169.254.169.254/latest/meta-data/" "cloud credential theft target"
ssrf_case "SSRF-07" "Proxy to IPv6 loopback"        "http://[::1]/"              ""
ssrf_case "SSRF-08" "Proxy to IPv6 link-local"      "http://[fe80::1]/"          ""
ssrf_case "SSRF-09" "Proxy to IPv6 ULA"             "http://[fd00::1]/"          ""
ssrf_case "SSRF-10" "Proxy to postgres by name"     "http://postgres:5432/"      "database service"
ssrf_case "SSRF-11" "Proxy to control plane by name" "http://control-plane:8080/api/v1/users" "Phase 5.11.7"
ssrf_case "SSRF-12" "Proxy to peer gateway"         "http://gateway-b:8081/"     ""
ssrf_case "SSRF-13" "DNS name resolving to private IP" "http://localtest.me/"    "localtest.me resolves to 127.0.0.1"

# Hard denials must never create an approvable request.
queued="$(api "${CONTROL}/api/v1/requests?limit=200" |
  python3 -c '
import json,sys
items=json.load(sys.stdin)["items"]
bad=[i for i in items if i["host"] in
     ("localhost","127.0.0.1","10.0.0.1","172.16.0.1","192.168.0.1",
      "169.254.169.254","::1","fe80::1","fd00::1","postgres",
      "control-plane","gateway-b","localtest.me")]
print("allowed" if bad else "blocked")')"
record_case "SSRF-14" "Hard-denied targets never enter the approval queue" "blocked" "$queued" \
  "nobody can approve their way to the metadata service"

# An unresolvable host is refused outright rather than forwarded: the guard
# cannot prove it is not internal, and it would fail to connect anyway.
record_case "SSRF-15" "Unresolvable hostname" "blocked" \
  "$(curl_through_proxy "http://this-name-does-not-resolve.invalid/")" \
  "cannot be proven external, so it is refused"

# The rebinding defence is asserted deterministically rather than live:
# reproducing it needs authoritative control of a DNS zone with a low TTL,
# which a self-contained harness cannot have without becoming a DNS server.
rebinding_unit="$(cd services/policy-gateway && go test ./internal/proxy/ -count=1 \
  -run 'TestDialRefusesRebindToInternalAddress|TestDialRefusesWhenAnyResolvedAddressIsInternal|TestDialResolvesOnlyOnce' \
  >/dev/null 2>&1 && echo blocked || echo allowed)"
record_case "SSRF-16" "DNS rebinding between check and dial" "blocked" "$rebinding_unit" \
  "verified by internal/proxy/rebinding_test.go, not a live probe"

# ---------------------------------------------------------------------------
echo
echo "▸ D. Redirects — covered by deterministic tests, not a live probe"
# ---------------------------------------------------------------------------
# Producing a genuine public-to-private redirect needs an external redirector,
# and a security claim should not depend on a third party's uptime or current
# behaviour. The property - that the gateway never follows a redirect itself,
# so every hop is re-evaluated - is asserted in
# internal/proxy/redirect_test.go instead, which runs in CI.
redirect_unit="$(cd services/policy-gateway && go test ./internal/proxy/ -count=1 \
  -run 'TestForwardHTTPDoesNotFollowRedirects|TestRedirectTargetIsSubjectToTheSSRFGuard' \
  >/dev/null 2>&1 && echo blocked || echo allowed)"

record_case "EGR-11" "Gateway follows a redirect to a private target" "blocked" "$redirect_unit" \
  "verified by internal/proxy/redirect_test.go, not a live probe"
record_case "EGR-12" "Redirect target escapes the SSRF guard on the second hop" "blocked" "$redirect_unit" \
  "verified by internal/proxy/redirect_test.go, not a live probe"

# ---------------------------------------------------------------------------
echo
echo "▸ E. Identity — credentials must be required, scoped, and revocable"
# ---------------------------------------------------------------------------
identity_probe() {
  local header="$1"
  local out code body
  out="$(in_agent "curl -s --noproxy '' -o /tmp/b3 -w '%{http_code}' --max-time 12 -x ${GATEWAY} ${header} 'http://${PUBLIC_HOST}/'; echo \"|\$(cat /tmp/b3 2>/dev/null)\"")"
  code="$(printf '%s' "$out" | sed 's/|.*//')"
  body="$(printf '%s' "$out" | sed 's/^[^|]*|//')"
  classify_proxy_response "$code" "$body"
}

record_case "ID-01" "No agent credential" "blocked" \
  "$(identity_probe "")" "token auth mode requires a credential"

record_case "ID-02" "Invalid agent credential" "blocked" \
  "$(identity_probe "-H 'Proxy-Authorization: Bearer clr_agent_not-a-real-token'")" ""

record_case "ID-03" "Revoked agent credential" "blocked" \
  "$(identity_probe "-H 'Proxy-Authorization: Bearer ${REVOKED_TOKEN}'")" \
  "revocation takes effect without restart"

record_case "ID-04" "Identity spoof via X-Gateway-Agent-Id header" "mediated" \
  "$(identity_probe "-H 'Proxy-Authorization: Bearer ${AGENT_A_TOKEN}' -H 'X-Gateway-Agent-Id: 22222222-2222-2222-2222-222222222020'")" \
  "header ignored in token mode; see ID-05"

spoofed="$(api "${CONTROL}/api/v1/requests?limit=200" |
  python3 -c "
import json,sys
items=json.load(sys.stdin)['items']
print('allowed' if any(i['agent_id']=='22222222-2222-2222-2222-222222222020' for i in items) else 'blocked')")"
record_case "ID-05" "Spoof header did not change recorded identity" "blocked" "$spoofed" \
  "attribution follows the credential, not the header"

record_case "ID-06" "Cross-org agent credential at this gateway" "blocked" \
  "$(identity_probe "-H 'Proxy-Authorization: Bearer ${OTHER_ORG_TOKEN}'")" \
  "gateway org must equal agent org (Phase 5.11.6)"

# ---------------------------------------------------------------------------
echo
echo "▸ F. Fleet resilience — degrade closed, never open"
# ---------------------------------------------------------------------------
# Approve the destination so the gateway would allow it, then remove the
# control plane. A gateway that opened up under stress would now let it
# through; a correct one keeps serving its last-known-good policy and
# eventually refuses rather than guessing.
api -X POST "${CONTROL}/api/v1/rules" -H 'Content-Type: application/json' \
  -d "{\"scope\":\"org\",\"scope_ref_id\":\"${ORG_ID}\",\"effect\":\"allow\",\"host\":\"${PUBLIC_HOST}\",\"port\":80,\"method\":\"*\",\"path_prefix\":\"/\"}" \
  -o /dev/null 2>/dev/null
sleep 8

record_case "FLEET-01" "Approved host allowed while control plane is healthy" "allowed" \
  "$(curl_through_proxy "http://${PUBLIC_HOST}/")" "baseline for FLEET-02"

$COMPOSE stop control-plane >/dev/null 2>&1

# Degradation happens in two stages, and both are measured rather than assumed.
#
# Stage 1 - identity cache still warm (CLEARANCE_AGENT_IDENTITY_CACHE_TTL=3s in
# this compose file). The gateway can still say who the agent is, and still
# holds its last-known-good policy snapshot, so an approved destination keeps
# working. Availability of the control plane is not a precondition for
# enforcing policy that was already distributed.
record_case "FLEET-02" "Control plane down (cache warm): approved host still allowed" "allowed" \
  "$(curl_through_proxy "http://${PUBLIC_HOST}/")" \
  "last-known-good policy; outage is not an outage of enforcement"

record_case "FLEET-03" "Control plane down (cache warm): unapproved host still gated" "mediated" \
  "$(curl_through_proxy "http://www.iana.org/")" \
  "outage does not become an allow-all"

# Stage 2 - identity cache expired. The gateway can no longer verify who is
# calling, so it refuses everything rather than guessing. This is the intended
# failure mode, but it is worth measuring explicitly: an implementation that
# "helpfully" kept serving unverified callers during an outage would look
# identical from the outside until it mattered.
sleep 8

record_case "FLEET-05" "Control plane down (cache expired): approved host now refused" "fail-closed" \
  "$(curl_through_proxy "http://${PUBLIC_HOST}/")" \
  "cannot verify identity, so egress stops - see Known gaps"

record_case "FLEET-06" "Control plane down (cache expired): unapproved host refused" "fail-closed" \
  "$(curl_through_proxy "http://www.iana.org/")" \
  "degrades closed, never open"

# A gateway that cannot load policy at all must refuse to start.
coldstart="$($COMPOSE run --rm --no-deps \
  -e CLEARANCE_CONTROL_URL=http://control-plane:8080 \
  -e CLEARANCE_GATEWAY_TOKEN="${GW_A_TOKEN}" \
  gateway-b >/dev/null 2>&1 && echo "allowed" || echo "fail-closed")"
record_case "FLEET-04" "Cold start with no reachable control plane" "fail-closed" "$coldstart" \
  "process exits rather than proxying against unknown policy"

$COMPOSE start control-plane >/dev/null 2>&1
sleep 10

# ---------------------------------------------------------------------------
echo
echo "▸ G. Internal control-plane API surface"
# ---------------------------------------------------------------------------
# Header is passed as separate argv entries rather than one string: quoting a
# whole "-H 'A: B'" into a single word makes curl see a malformed argument, and
# every credentialed probe then looks rejected for the wrong reason.
internal_probe() {
  local path="$1"; shift
  local code
  if [ "$#" -gt 0 ]; then
    code="$(docker run --rm --network "$CONTROL_NET" "$CURL_IMAGE" \
      -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$1" "${CONTROL}${path}" 2>/dev/null || echo 000)"
  else
    code="$(docker run --rm --network "$CONTROL_NET" "$CURL_IMAGE" \
      -s -o /dev/null -w '%{http_code}' --max-time 8 "${CONTROL}${path}" 2>/dev/null || echo 000)"
  fi
  case "$code" in
    2*) echo "allowed" ;;
    *)  echo "blocked" ;;
  esac
}

record_case "API-01" "Internal API with no credential" "blocked" \
  "$(internal_probe "/api/internal/v1/policies/snapshot")" \
  "a private network is not authentication"

record_case "API-02" "Internal API with admin token instead of gateway credential" "blocked" \
  "$(internal_probe "/api/internal/v1/policies/snapshot" "X-Admin-Token: ${ADMIN_TOKEN}")" \
  "separate trust domains"

record_case "API-03" "Admin API with no token" "blocked" \
  "$(internal_probe "/api/v1/users")" ""

record_case "API-04" "Gateway credential valid for its own org snapshot" "allowed" \
  "$(internal_probe "/api/internal/v1/policies/snapshot" "Authorization: Bearer ${GW_A_TOKEN}")" \
  "positive control: the guard is not a blanket denial"

# ---------------------------------------------------------------------------
echo
echo "▸ Generating ${DOC}"
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$DOC")"
GATEWAY_VERSION="$($COMPOSE exec -T gateway-a sh -c 'echo ${GATEWAY_SERVICE_VERSION:-dev}' 2>/dev/null | tr -d '\r' || echo dev)"
python3 scripts/security/render-report.py \
  --results "$RESULTS_TSV" \
  --output "$DOC" \
  --commit "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
  --gateway-version "$GATEWAY_VERSION"

summarize
exit $?
