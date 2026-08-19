#!/usr/bin/env python3
"""Run a Hermes terminal-tool curl fetch (egress uses HTTP_PROXY / HTTPS_PROXY)."""

from __future__ import annotations

import json
import shlex
import sys

from tools.terminal_tool import terminal_tool


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/"
    command = (
        "curl -sS --max-time 20 "
        f"-o /dev/null -w '%{{http_code}}' {shlex.quote(url)}"
    )
    raw = terminal_tool(command=command, timeout=30)
    print(raw)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print("terminal tool returned non-JSON output", file=sys.stderr)
        return 1

    exit_code = payload.get("exit_code", -1)
    if exit_code != 0:
        print(
            f"terminal tool failed: exit_code={exit_code} error={payload.get('error')}",
            file=sys.stderr,
        )
        return 1

    http_code = (payload.get("output") or "").strip()
    print(f"http_code={http_code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
