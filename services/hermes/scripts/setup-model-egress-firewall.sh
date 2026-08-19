#!/bin/sh
# Restrict outbound traffic when MODEL_EGRESS_ENABLED=true (Phase 4.1 pilot profile).
# Allows: loopback, Docker DNS, policy-gateway proxy, and HTTPS to MODEL_EGRESS_ALLOW_HOSTS only.
set -eu

if [ "${MODEL_EGRESS_ENABLED:-false}" != "true" ]; then
  exit 0
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables required for model egress firewall" >&2
  exit 1
fi

HOSTS="${MODEL_EGRESS_ALLOW_HOSTS:-api.openai.com,api.anthropic.com,openrouter.ai}"
GATEWAY_HOST="${MODEL_EGRESS_GATEWAY_HOST:-policy-gateway}"

iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d 127.0.0.11 -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -d 127.0.0.11 -p tcp --dport 53 -j ACCEPT

GW_IP="$(getent hosts "$GATEWAY_HOST" | awk '{print $1; exit}')"
if [ -n "$GW_IP" ]; then
  iptables -A OUTPUT -d "$GW_IP" -p tcp --dport 8080 -j ACCEPT
fi

for host in $(echo "$HOSTS" | tr ',' ' '); do
  host=$(echo "$host" | tr -d ' ')
  [ -n "$host" ] || continue
  for ip in $(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u); do
    [ -n "$ip" ] || continue
    iptables -A OUTPUT -d "$ip" -p tcp --dport 443 -j ACCEPT
  done
done

echo "model egress firewall applied (gateway=${GW_IP:-unknown}, hosts=${HOSTS})"
