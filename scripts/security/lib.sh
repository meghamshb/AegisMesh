#!/usr/bin/env bash
# Shared helpers for the Phase 5.12 egress security evaluation.
#
# Outcome vocabulary. Every case resolves to exactly one of these, and the
# distinction between the first two is the point of the whole suite:
#
#   blocked      Hard-denied. No approval could ever permit it. This is what an
#                SSRF target must produce - it must not even reach the queue,
#                because nobody should be able to click "approve" and grant an
#                agent access to the metadata service or the database.
#   mediated     Reached policy evaluation and was gated. A pending egress row
#                exists and a human could approve it. This is the correct
#                outcome for ordinary unapproved public traffic.
#   allowed      Traffic reached the destination. Only correct where policy
#                explicitly permits it.
#   unreachable  The network itself refused, before any Clearance code ran.
#                This is the Docker lockdown, not the proxy.
#   fail-closed  A component refused to serve rather than serve unsafely.
#   error        The probe itself failed to run. Never counted as a pass.

set -uo pipefail

RESULTS_TSV="${RESULTS_TSV:-/tmp/clearance-security-results.tsv}"

# Distinguishes a hard SSRF denial from a policy-mediated block. Both are HTTP
# 403; only the body says which, so the suite reads the body rather than
# treating every 403 as equivalent.
SSRF_MARKER='egress to internal destination blocked'
PENDING_MARKER='egress blocked pending approval'

results_init() {
  : >"$RESULTS_TSV"
}

# record_case <id> <attempt> <expected> <actual> [notes]
record_case() {
  local id="$1" attempt="$2" expected="$3" actual="$4" notes="${5:-}"
  local result="FAIL"
  if [ "$expected" = "$actual" ]; then
    result="PASS"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$attempt" "$expected" "$actual" "$result" "$notes" >>"$RESULTS_TSV"

  if [ "$result" = "PASS" ]; then
    printf '  \033[32mPASS\033[0m  %-8s %s\n' "$id" "$attempt"
  else
    printf '  \033[31mFAIL\033[0m  %-8s %s (expected %s, got %s)\n' \
      "$id" "$attempt" "$expected" "$actual"
  fi
}

# classify_proxy_response <http_code> <body>
#
# Maps a proxied request's outcome onto the vocabulary above.
classify_proxy_response() {
  local code="$1" body="$2"

  case "$code" in
    000) echo "unreachable"; return ;;
  esac

  # The gateway always writes one of its own JSON bodies when it refuses, so
  # the marker - not the status code - is what identifies a Clearance decision.
  if printf '%s' "$body" | grep -Fq "$SSRF_MARKER"; then
    echo "blocked"
    return
  fi
  if printf '%s' "$body" | grep -Fq "$PENDING_MARKER"; then
    echo "mediated"
    return
  fi
  # Credential failures: 407 with a Proxy-Authenticate challenge, or 403 for a
  # revoked agent / disabled owner / suspended org.
  if printf '%s' "$body" | grep -qE "agent credential required|agent revoked|organization suspended|agent owner disabled"; then
    echo "blocked"
    return
  fi
  # The gateway refusing because it cannot verify identity at all - e.g. a
  # distributed gateway that has lost the control plane. Traffic does not flow,
  # so this is fail-closed, NOT allowed. Classifying it as allowed would score
  # a correct refusal as a bypass, or worse, hide a real one behind a 5xx.
  if printf '%s' "$body" | grep -Fq "cannot verify agent identity"; then
    echo "fail-closed"
    return
  fi
  # Any other gateway-shaped error envelope is a refusal too. Being explicit
  # here matters: the fallback below assumes a response came from the
  # destination, and that assumption must not silently absorb a gateway error.
  if [ "$code" -ge 500 ] 2>/dev/null && printf '%s' "$body" | grep -q '"error"'; then
    echo "fail-closed"
    return
  fi

  case "$code" in
    407) echo "blocked" ;;
    # Anything else came back from the destination. A 404 here means the
    # request was forwarded and the upstream had no such path - which is an
    # *allowed* egress, not a block. Reading bare 4xx as "mediated" would
    # silently score a working bypass as a pass.
    *)   echo "allowed" ;;
  esac
}

# summarize prints the tally and exits non-zero if anything failed.
summarize() {
  local total passed failed
  total=$(wc -l <"$RESULTS_TSV" | tr -d ' ')
  passed=$(awk -F'\t' '$5=="PASS"' "$RESULTS_TSV" | wc -l | tr -d ' ')
  failed=$(awk -F'\t' '$5=="FAIL"' "$RESULTS_TSV" | wc -l | tr -d ' ')

  echo
  echo "──────────────────────────────────────────────"
  echo "  Evaluated: ${total}    Passed: ${passed}    Failed: ${failed}"
  echo "──────────────────────────────────────────────"

  if [ "$failed" -ne 0 ]; then
    echo
    echo "Failing cases (these are reported, not hidden):"
    awk -F'\t' '$5=="FAIL" {printf "  %s  %s — expected %s, got %s\n", $1, $2, $3, $4}' "$RESULTS_TSV"
    return 1
  fi
  return 0
}
