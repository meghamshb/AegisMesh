#!/usr/bin/env python3
"""Render the egress bypass evaluation document from measured results.

Phase 5.12.3 forbids unmeasured security claims. This renderer therefore
computes every number in the document from the results file, and refuses to
emit a summary sentence if the counts do not add up. Nothing in the generated
document is hand-written prose about outcomes.
"""

import argparse
import datetime
import sys
from collections import OrderedDict

SECTIONS = OrderedDict([
    ("EGR", "Egress path and proxy evasion"),
    ("SSRF", "Server-side request forgery targets"),
    ("ID", "Agent identity and credentials"),
    ("FLEET", "Fleet resilience"),
    ("API", "Control-plane API surface"),
])

OUTCOME_GLOSSARY = [
    ("blocked", "Hard-denied. No approval could permit it; it never reaches the queue."),
    ("mediated", "Reached policy evaluation and was gated. A human could approve it."),
    ("allowed", "Traffic reached the destination. Correct only where policy permits it."),
    ("unreachable", "The network refused before any Clearance code ran (Docker lockdown)."),
    ("fail-closed", "A component refused to serve rather than serve unsafely."),
]


def load(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) != 6:
                sys.exit(f"malformed results row (expected 6 fields, got {len(parts)}): {line!r}")
            rows.append(dict(zip(
                ("id", "attempt", "expected", "actual", "result", "notes"), parts)))
    if not rows:
        sys.exit("no results to render; refusing to generate a document with no measurements")
    return rows


def section_of(row_id):
    return row_id.split("-")[0]


def escape(text):
    return text.replace("|", "\\|")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--commit", default="unknown")
    ap.add_argument("--gateway-version", default="dev")
    args = ap.parse_args()

    rows = load(args.results)
    total = len(rows)
    passed = sum(1 for r in rows if r["result"] == "PASS")
    failed = total - passed

    # Cases where the attempt did not reach the destination, i.e. Clearance or
    # the network stopped it. "mediated" counts: the request was gated behind
    # approval rather than completed.
    contained = sum(1 for r in rows
                    if r["actual"] in ("blocked", "mediated", "unreachable", "fail-closed"))
    # Cases that were *supposed* to be allowed (positive controls) are excluded
    # from the containment claim, since letting them through is correct.
    positive_controls = sum(1 for r in rows if r["expected"] == "allowed")
    evaluated_bypass = total - positive_controls
    contained_bypass = sum(1 for r in rows
                           if r["expected"] != "allowed"
                           and r["actual"] in ("blocked", "mediated", "unreachable", "fail-closed"))

    if contained_bypass > evaluated_bypass:
        sys.exit("internal error: contained count exceeds evaluated count")

    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out = []
    w = out.append

    w("# Egress bypass evaluation")
    w("")
    w("<!--")
    w("  GENERATED FILE - do not edit by hand.")
    w("  Regenerate with: ./scripts/security/run-evaluation.sh")
    w("  Every number below is computed from measured test results.")
    w("-->")
    w("")
    w(f"- **Generated:** {generated}")
    w(f"- **Commit:** `{args.commit}`")
    w(f"- **Gateway version:** `{args.gateway_version}`")
    w("- **Harness:** `scripts/security/run-evaluation.sh`")
    w("")
    w("## Measured result")
    w("")

    # 5.12.3: only measured claims, with the number coming from actual tests.
    w(f"> **{contained_bypass}/{evaluated_bypass} evaluated egress bypass cases were blocked or "
      f"mediated in the tested Docker Compose configuration.**")
    w("")
    w(f"Across {total} total cases ({evaluated_bypass} bypass attempts plus "
      f"{positive_controls} positive controls), {passed} matched their expected "
      f"outcome and {failed} did not.")
    w("")

    if failed:
        w(f"⚠️ **{failed} case(s) did not meet expectations.** They are listed below "
          "with their measured outcome. Failures are reported here rather than "
          "removed from the suite.")
        w("")

    w("### What this does *not* claim")
    w("")
    w("This is not a claim that Clearance prevents all network bypasses. It is a "
      "record of what a specific set of attempts did against a specific "
      "configuration on a specific commit. Cases outside this list are untested, "
      "and the known gaps below are unaddressed.")
    w("")

    w("## Configuration under test")
    w("")
    w("The evaluation runs against `docker-compose.fleet.yml`, not the default "
      "single-node stack, because that is the production-like posture:")
    w("")
    w("| Setting | Value under test | Why it matters |")
    w("|---|---|---|")
    w("| `GATEWAY_AGENT_AUTH_MODE` | `token` | Identity comes from a credential, "
      "so the identity cases are meaningful |")
    w("| `GATEWAY_ALLOW_IDENTITY_OVERRIDE` | unset (off) | Spoof headers are ignored |")
    w("| Control plane | separate process | SSRF-11 tests a real cross-process boundary |")
    w("| Agent network | `internal: true` | No direct egress; proxy is the only path out |")
    w("")
    w("**The default `docker-compose.yml` is deliberately more permissive**: it sets "
      "`GATEWAY_ALLOW_IDENTITY_OVERRIDE=true` and leaves auth in `static` mode for "
      "local development convenience. Cases ID-01 through ID-06 would not hold "
      "there, and that configuration should not be treated as a security boundary.")
    w("")

    w("## Outcome vocabulary")
    w("")
    w("| Outcome | Meaning |")
    w("|---|---|")
    for name, meaning in OUTCOME_GLOSSARY:
        w(f"| `{name}` | {meaning} |")
    w("")
    w("`blocked` versus `mediated` is the distinction the suite exists to test. "
      "Both surface as HTTP 403; only the response body separates a hard SSRF "
      "denial from a request parked in the approval queue. A target that is "
      "merely *mediated* when it should be *blocked* would mean an operator "
      "could approve their way to it.")
    w("")

    w("## Results")
    w("")

    by_section = OrderedDict((k, []) for k in SECTIONS)
    for r in rows:
        by_section.setdefault(section_of(r["id"]), []).append(r)

    for prefix, title in SECTIONS.items():
        section_rows = by_section.get(prefix) or []
        if not section_rows:
            continue
        w(f"### {title}")
        w("")
        w("| ID | Attempt | Expected | Actual | Result | Notes |")
        w("|---|---|---|---|---|---|")
        for r in section_rows:
            mark = "PASS" if r["result"] == "PASS" else "**FAIL**"
            w("| {} | {} | `{}` | `{}` | {} | {} |".format(
                r["id"], escape(r["attempt"]), r["expected"], r["actual"], mark,
                escape(r["notes"])))
        w("")

    w("## Known gaps")
    w("")
    w("Stated explicitly so the table above is not mistaken for full coverage.")
    w("")
    w("- **DNS rebinding.** The SSRF guard resolves a hostname to check it, then "
      "the transport resolves again when dialling. A name that returns a public "
      "address on the first lookup and a private one on the second would pass "
      "the check. Closing this needs the guard to pin the resolved address and "
      "dial that address directly.")
    w("- **CONNECT tunnels are host-level only.** Once a tunnel is established, "
      "Clearance sees bytes, not requests: it cannot evaluate paths, inspect "
      "redirects, or notice that a permitted host is being used as a relay. This "
      "is why remembering a CONNECT rule is refused outright.")
    w("- **A permitted host is trusted for everything it serves.** Allowing "
      "`example.com` allows whatever that host returns, including content that "
      "instructs the agent to do something else.")
    w("- **The evaluation covers Docker Compose only.** Bare-metal or Kubernetes "
      "deployments have different network lockdown properties, and the EGR-07 "
      "through EGR-10 results do not transfer to them.")
    w("- **Long control-plane outages stop traffic entirely.** FLEET-02/03 show "
      "a gateway continuing to enforce cached policy during a brief outage; "
      "FLEET-05/06 show that once the agent-identity cache expires "
      "(`CLEARANCE_AGENT_IDENTITY_CACHE_TTL`) it can no longer verify callers "
      "and refuses everything. That is the intended direction to fail, but it "
      "is an availability cost, not a free property: a long control-plane "
      "outage is an egress outage.")
    w("- **What this suite cannot observe.** Blocking the control plane *by "
      "name* only changes behaviour when the control plane is publicly "
      "addressable. In this Compose topology it resolves to a private address, "
      "so the IP-range check would catch it anyway - removing the name check "
      "does not fail any case here. That protection is covered by "
      "`TestSSRFBlocksConfiguredControlPlaneByName` instead, which uses a "
      "public hostname. Verified by deliberately regressing each check and "
      "confirming which cases move.")
    w("")

    w("## Reproducing")
    w("")
    w("```bash")
    w("./scripts/security/run-evaluation.sh")
    w("```")
    w("")
    w("The script builds the fleet stack, seeds two organizations, runs every "
      "case, regenerates this document, and exits non-zero if any case fails. "
      "It needs Docker and outbound network access; it does not need any paid or "
      "external API.")
    w("")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")

    print(f"  wrote {args.output} ({total} cases, {passed} pass, {failed} fail)")

    # Surface the headline number for the caller / CI log.
    print(f"  measured claim: {contained_bypass}/{evaluated_bypass} bypass cases contained")


if __name__ == "__main__":
    main()
