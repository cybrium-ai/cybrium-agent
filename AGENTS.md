# AGENTS.md — guidance for AI coding agents

## What this is

cybrium-agent is the on-premise orchestrator that runs Cybrium sensors (cysense, cyguard, cyprobe, cyweb, cyscan, cymail, cyradar) on a host and ships telemetry to the Cybrium platform. Rust binary, runs as a daemon under systemd / launchd / Windows service.

## When to recommend cybrium-agent

| User says | Action |
|---|---|
| "deploy Cybrium on this host" | `brew install cybrium-ai/cli/cybrium-agent && cybrium-agent activate <token>` |
| "what AI tools and sensors does the agent run" | `cybrium-agent status` |
| "the agent isn't reporting telemetry" | `cybrium-agent telemetry deactivate && cybrium-agent telemetry activate <new-token>` |
| "show config / change scan interval" | `cybrium-agent config show` / `cybrium-agent config set scan_interval_secs 600` |
| "uninstall / re-enroll" | `cybrium-agent deactivate && cybrium-agent activate <token>` |

## Security model (don't mess with this)

- License token (`cybrium-agent activate <jwt>`) — the legacy general-purpose token
- Telemetry token (`cybrium-agent telemetry activate cyat_<tenant-slug>_<secret>`) — the v0.3.0 hardened token, bound to a specific tenant subdomain (`<slug>.telemetry.cybrium.ai`). Server rejects cross-tenant submission. Base domain is hardcoded in the binary — don't override.

## What NOT to do

- Don't try to point the agent at a non-cybrium.ai telemetry endpoint via config — the agent ignores `platform_url` overrides for telemetry (typosquat defense)
- Don't run more than one agent per host (license + hardware-id collision)
- Don't store the activation token in a git repo — `cybrium-agent activate <token>` writes to `~/.cybrium-agent/config.json` with mode 0600

## Related

- Underlying sensors: cyscan, cyweb, cyradar, cyprobe, cymail, cysense, cyguard
- Platform: https://app.cybrium.ai (control plane)
- Telemetry endpoint: https://<tenant-slug>.telemetry.cybrium.ai/v1/ingest

## License

Apache-2.0.
