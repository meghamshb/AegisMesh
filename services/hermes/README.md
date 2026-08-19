# Hermes runtime (stub)

Phase 0 placeholder container that:

- waits for `policy-gateway` health
- exports `HTTP_PROXY` / `HTTPS_PROXY` toward the gateway
- mounts `./workspace` read-only at `/work`

Phase 4 replaces this image with a Hermes install based on the LAP template.
