# Log Schema and SIEM Mapping

Each interaction writes one JSON object per line to `/var/log/honeypot/web_honeypot.log` and optionally forwards it via UDP to `SYSLOG_TARGET`.

## Common Fields

- ts: ISO-8601 UTC timestamp (string)
- event: Event type (string)
- src_ip: Source IP address (string)
- user_agent: HTTP user agent (string)
- method: HTTP method (string)
- path: Request path (string)
- query: Map of query parameters (object)
- headers: Map of selected headers (object), cookies and auth redacted
- body_preview: Optional body preview, up to 4096 bytes (string)
- body_sha256: Present if original body exceeded 4096 bytes (string)
- meta: Object with endpoint-specific details (object)

## Event Types and Meta Examples

- page_view: meta may be empty
- login_attempt: { username, password }
- search: { query, sqli_like }
- reflect: { q, xss_like }
- store_payload: { length }
- show_stored: { count }
- file_upload: { orig_name, saved_path, size, sha256 }
- api_user: { uid, suspicious }
- ping_attempt: { host, injection_like }
- ssrf_attempt: { url, whitelisted?, blocked? }
- open_redirect: { to }
- deserialize_attempt: { suspicious }
- download_attempt: { file, traversal_like, allowed }
- local_logs_view: { count }

## Example JSON Lines

```json
{"ts":"2024-01-01T12:00:00Z","event":"login_attempt","src_ip":"198.51.100.23","user_agent":"curl/8.1.0","method":"POST","path":"/login","query":{},"headers":{"User-Agent":"curl/8.1.0"},"body_preview":"username=admin&password=Passw0rd!","meta":{"username":"admin","password":"Passw0rd!"}}
```

```json
{"ts":"2024-01-01T12:00:05Z","event":"search","src_ip":"198.51.100.23","user_agent":"curl/8.1.0","method":"GET","path":"/search","query":{"q":"1 UNION SELECT password FROM users;--"},"headers":{"User-Agent":"curl/8.1.0"},"meta":{"query":"1 UNION SELECT password FROM users;--","sqli_like":true}}
```

```json
{"ts":"2024-01-01T12:00:10Z","event":"ping_attempt","src_ip":"198.51.100.23","user_agent":"curl/8.1.0","method":"GET","path":"/ping","query":{"host":"127.0.0.1; ls -la"},"headers":{"User-Agent":"curl/8.1.0"},"meta":{"host":"127.0.0.1; ls -la","injection_like":true}}
```

## Wazuh Decoder / Rules (recommendations)

- Decoder: map top-level keys `event`, `src_ip`, `method`, `path`, and nested `meta.*`
- Create rules to flag when:
  - `event == "search" and meta.sqli_like == true`
  - `event == "reflect" and meta.xss_like == true`
  - `event == "ping_attempt" and meta.injection_like == true`
  - `event == "ssrf_attempt" and meta.blocked == true`

## QRadar DSM Mapping (recommendations)

- Log Source Type: Universal DSM (JSON)
- Custom properties:
  - event (String)
  - src_ip (IP)
  - path (String)
  - meta.sqli_like (Boolean)
  - meta.xss_like (Boolean)
  - meta.injection_like (Boolean)
  - meta.blocked (Boolean)
  - meta.sha256 (String)
- Use `event` as the primary category and build offense rules accordingly.
