# Flames.Blue Honeypot (Flask)

Mid-level corporate-style web portal honeypot. Simulates common web vulns for telemetry while never executing attacker input. Designed for isolated lab use.

## Safety Summary

- Simulation only: no code execution, no shelling out, no outbound fetches (except optional syslog).
- Uploaded files are quarantined to `/opt/honeypot/quarantine` and never executed.
- JSON event logging to `/var/log/honeypot/web_honeypot.log` (one JSON per line).
- Optional syslog forward of each JSON line via `SYSLOG_TARGET` (UDP `host:port`).
- Runs as non-root in Docker. Recommend an isolated VM/VLAN and blocked egress.

## Quick Start (Isolated Lab)

1. Prereqs: Docker and docker-compose.
2. Clone and enter the directory, then build and start:

```bash
docker compose up --build -d
```

3. Access portal: http://localhost:8080/

To avoid exposing externally, remove or comment out the `ports` mapping in `docker-compose.yml` and use an internal test client/net.

## Endpoints

- `/` Home page
- `/login` GET/POST — captures credentials (POST) and redirects to `/admin` (fake success)
- `/admin` Fake dashboard
- `/search?q=` — sqli-like detection (UNION/SELECT/--/;)
- `/reflect?q=` — raw reflection to simulate reflected XSS
- `/store` GET/POST + `/stored` — store and render payloads raw (stored XSS simulation)
- `/upload` GET/POST — quarantine uploads and log metadata
- `/api/user/<uid>` GET/POST — fake API; logs and flags suspicious payloads
- `/ping?host=` — detects command injection chars; returns simulated output
- `/fetch?url=` — SSRF simulation; only local whitelist allowed; otherwise blocked
- `/go?to=` — open redirect (recommend isolation)
- `/deserialize` POST — insecure deserialization simulation; never evaluate
- `/download?file=` — directory traversal simulation; serves only safe placeholders
- `/_local_logs?n=` — returns last N JSON log lines (for demo). Bind to localhost or remove before any exposure.

## Logging Format

Each request generates a JSON object with fields:

- `ts` ISO-8601 UTC time
- `event` — action (e.g., page_view, login_attempt, search)
- `src_ip`, `user_agent`, `method`, `path`
- `query` (map), `headers` (map with secrets redacted)
- `body_preview` (optional, truncated to 4KB) and `body_sha256` if truncated
- `meta` — per-endpoint flags like `sqli_like`, `xss_like`, `injection_like`, `saved_path`, etc.

Write path: `/var/log/honeypot/web_honeypot.log`. Each line is also sent via UDP syslog when `SYSLOG_TARGET=host:port` is set.

## Syslog / SIEM Ingest

- Wazuh: configure a UDP listener and a decoder for JSON keys. Example facility/format is plain message body as JSON. Use fields like `event`, `src_ip`, `meta.sqli_like` etc.
- QRadar: create a DSM mapping for custom JSON properties; key on `event` field to define categories.

See `log_schema.md` for examples and recommended field mappings.

## Environment Variables

- `PORT` — container port (default 8080)
- `SYSLOG_TARGET` — optional `host:port` for UDP syslog forwarding

## Network & Egress Containment

- Run in an isolated VM or VLAN. Use a bridge Docker network (default in compose) and avoid publishing ports to the host unless necessary.
- Block outbound traffic from container (iptables or Docker network policies) except to your syslog sink if used.
- Example (host firewall): allow UDP to `SYSLOG_TARGET`, drop all other egress from container subnet.

## File Handling

- Uploads are saved to `/opt/honeypot/quarantine` with filenames prefixed by SHA256. Do not open or execute.
- Stored payloads for the `/store` feature are appended to `/opt/honeypot/quarantine/stored_payloads.json`.

## Legal & Ethical

- For research and defensive training in controlled, private labs only. You are responsible for compliance with local laws and organizational policy.
- Do not expose to the public internet. The `/go` endpoint performs open redirects and `/_local_logs` reveals telemetry.

## Hardening Checklist (Before Any Exposure)

- [ ] Run on an isolated VLAN / VM with no access to production networks
- [ ] Remove or restrict `/_local_logs` (bind to localhost or delete)
- [ ] Remove `ports` mapping from compose, or restrict with firewall
- [ ] Block egress except UDP to syslog
- [ ] Set log rotation on `/var/log/honeypot/web_honeypot.log`
- [ ] Monitor disk usage of `/opt/honeypot/quarantine`
- [ ] Review `SYSLOG_TARGET` and SIEM parsing rules

## Build From Source

```bash
docker build -t flamesblue/honeypot:latest .
docker run --rm -p 8080:8080 \
  -e SYSLOG_TARGET="192.0.2.10:514" \
  -v $(pwd)/logs:/var/log/honeypot:rw \
  -v quarantine:/opt/honeypot/quarantine:rw \
  --read-only --tmpfs /tmp \
  --name flamesblue-honeypot \
  flamesblue/honeypot:latest
```

## Templates

Simple HTML provides a professional, minimal corporate look. There is no client-side execution of uploaded content.
