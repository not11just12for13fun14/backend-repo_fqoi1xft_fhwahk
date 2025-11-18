# Security Checklist and Isolation Guidance

This honeypot is intended for isolated lab environments. Before running, consider the following:

1. Isolation
   - Deploy in a dedicated VM or container host on an isolated VLAN.
   - Use Docker bridge networks; avoid publishing ports publicly. Prefer no `ports` mapping in compose.
   - Restrict inbound access to a controlled burner IP range used by scanners or test rigs.

2. Egress Control
   - Block all outbound traffic from the container except optional UDP to your syslog sink.
   - Validate `SYSLOG_TARGET` and confirm it is reachable.

3. Privileges and Filesystem
   - Run as non-root (image does). Enable `read_only: true` and `tmpfs: /tmp` (compose includes).
   - Mount `/var/log/honeypot` and `/opt/honeypot/quarantine` with restricted permissions.
   - Implement log rotation on `/var/log/honeypot/web_honeypot.log`.

4. Dangerous Endpoints
   - `/_local_logs` is for demo; remove or bind to localhost before exposure.
   - `/go` performs open redirects; keep in isolated networks.

5. Data Handling
   - Do not open or execute quarantined files. Hash and store only.
   - Treat all inputs and stored payloads as hostile. Use dedicated analysis hosts if needed.

6. Legal & Policy
   - Ensure you have authorization to operate deception systems on your network.
   - Document retention, privacy, and data handling for collected IPs and payloads.

7. Monitoring
   - Forward logs to SIEM using `SYSLOG_TARGET`. Build detections for `sqli_like`, `xss_like`, `injection_like`, etc.
   - Watch disk usage; prune quarantine and rotate logs.
