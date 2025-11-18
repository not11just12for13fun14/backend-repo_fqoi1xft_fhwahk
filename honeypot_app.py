#!/usr/bin/env python3
"""
flames.blue honeypot — Mid-level Flask honeypot web portal

IMPORTANT SAFETY NOTES
- This application SIMULATES vulnerable behaviors. It never executes attacker-supplied code,
  spawns shell commands, performs real deserialization of untrusted data, or makes
  arbitrary outbound requests.
- All potentially dangerous actions are EMULATED for telemetry and engagement only.
- Uploaded files are quarantined and never executed or opened by the app.

Logging
- One JSON object per line is written to /var/log/honeypot/web_honeypot.log
- Each JSON line is optionally forwarded to a syslog target specified by the
  environment variable SYSLOG_TARGET in the format "host:port" (UDP).

Deployment
- Containerized with Docker + docker-compose. Run as non-root. Write-only access is
  limited to quarantine and log directories.

"""
from __future__ import annotations
import hashlib
import json
import os
import re
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

# ----------------------
# Configuration
# ----------------------
LOG_DIR = Path("/var/log/honeypot")
LOG_FILE = LOG_DIR / "web_honeypot.log"
QUARANTINE_DIR = Path("/opt/honeypot/quarantine")
STORED_PAYLOADS = QUARANTINE_DIR / "stored_payloads.json"

# Ensure directories exist with restricted permissions
LOG_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
for p in (LOG_DIR, QUARANTINE_DIR):
    try:
        os.chmod(p, 0o750)
    except Exception:
        pass

# Optional syslog forwarding target (UDP)
SYSLOG_TARGET = os.getenv("SYSLOG_TARGET")  # e.g., "192.0.2.10:514"

# App initialization
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("HONEY_SECRET_KEY", "not-a-secret"),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,  # 25MB upload cap
)

# ----------------------
# Helpers: Safe utilities & logging
# ----------------------
MAX_BODY_PREVIEW = 4096  # bytes

SQLI_PATTERN = re.compile(r"(\bunion\b|\bselect\b|--|;|/\*|\*/|\bdrop\b|\binsert\b|\bupdate\b)", re.I)
XSS_PATTERN = re.compile(r"(<script|onerror=|onload=|javascript:|<img|<svg|<iframe)", re.I)
# Detect common command-injection characters and constructs; explicit \n included
CMDI_PATTERN = re.compile(r"[;&|`$><]|\n|\$\(|\)\s*\|\||\|\|", re.I)
DESER_PATTERN = re.compile(r"(pickle|__reduce__|eval\(|base64|gAS|yaml\.|object_hook)", re.I)
TRAVERSAL_PATTERN = re.compile(r"(\.\./|^/|[A-Za-z]:\\)")

SAFE_DOWNLOADS: Dict[str, Tuple[str, bytes]] = {
    # key: logical file name -> (mime, content)
    "annual_report.pdf": ("application/pdf", b"%PDF-1.3\n% Fake PDF content for demo\n"),
    "policy.txt": ("text/plain; charset=utf-8", b"Corporate policy placeholder\n"),
}


def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _client_ip() -> str:
    # Try common headers but trust Flask remote_addr ultimately
    fwd = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if fwd:
        return fwd
    return request.remote_addr or "0.0.0.0"


def _headers_lite() -> Dict[str, str]:
    # Avoid logging cookies or overly sensitive headers; keep it minimal
    redacted = {}
    for k, v in request.headers.items():
        if k.lower() in {"cookie", "authorization"}:
            redacted[k] = "[redacted]"
        else:
            # Truncate very long header values
            redacted[k] = (v[:256] + "…") if len(v) > 256 else v
    return redacted


def _body_preview_and_hash() -> Tuple[Optional[str], Optional[str]]:
    if request.method in ("POST", "PUT", "PATCH"):
        raw = request.get_data(cache=False, as_text=False) or b""
        if not raw:
            return None, None
        if len(raw) > MAX_BODY_PREVIEW:
            h = hashlib.sha256(raw).hexdigest()
            preview = raw[:MAX_BODY_PREVIEW].decode(errors="replace")
            return preview, h
        else:
            return raw.decode(errors="replace"), None
    return None, None


def log_event(event: str, meta: Optional[Dict[str, Any]] = None) -> None:
    body_preview, body_sha256 = _body_preview_and_hash()
    payload = {
        "ts": _now_iso(),
        "event": event,
        "src_ip": _client_ip(),
        "user_agent": request.headers.get("User-Agent", ""),
        "method": request.method,
        "path": request.path,
        "query": request.args.to_dict(flat=True),
        "headers": _headers_lite(),
        "meta": meta or {},
    }
    if body_preview is not None:
        payload["body_preview"] = body_preview
        if body_sha256:
            payload["body_sha256"] = body_sha256

    line = json.dumps(payload, separators=(",", ":"))

    # Append to local log
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

    # Forward to syslog target if configured
    target = SYSLOG_TARGET
    if target:
        try:
            host, port_str = target.split(":", 1)
            port = int(port_str)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Plain JSON payload as the message body
            sock.sendto(line.encode("utf-8"), (host, port))
            sock.close()
        except Exception:
            # Never crash on forwarding errors
            pass


# ----------------------
# In-memory fake data (no external DBs)
# ----------------------
FAKE_USERS = {
    "admin": {"uid": "1", "name": "Administrator", "role": "admin"},
    "jane": {"uid": "2", "name": "Jane Doe", "role": "user"},
}

FAKE_SEARCH_RESULTS = [
    {"id": 101, "title": "Quarterly Financial Summary", "owner": "finance"},
    {"id": 102, "title": "Employee Onboarding Guide", "owner": "hr"},
    {"id": 103, "title": "Data Retention Policy", "owner": "legal"},
]

# ----------------------
# Routes
# ----------------------
@app.before_request
def _log_page_view_pre():
    # Lightweight page view for GET requests
    if request.method == "GET":
        log_event("page_view")


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        meta = {"username": username, "password": password}
        log_event("login_attempt", meta)
        # Always pretend success and redirect to admin to keep engagement
        time.sleep(0.5)
        return redirect(url_for("admin"))
    return render_template("login.html")


@app.route("/admin")
def admin():
    # Fake dashboard (no real privileged data)
    return render_template("admin.html")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    sqli_like = bool(SQLI_PATTERN.search(q))
    results = FAKE_SEARCH_RESULTS
    meta = {"query": q, "sqli_like": sqli_like}
    log_event("search", meta)
    return render_template("search.html", q=q, results=results, sqli_like=sqli_like)


@app.route("/reflect")
def reflect():
    q = request.args.get("q", "")
    xss_like = bool(XSS_PATTERN.search(q))
    meta = {"q": q, "xss_like": xss_like}
    log_event("reflect", meta)
    # Intentionally reflecting raw user input to simulate reflected XSS
    # This is marked clearly as a simulation and for telemetry only.
    return render_template("reflect.html", reflected=q)


@app.route("/store", methods=["GET", "POST"])
def store():
    if request.method == "POST":
        payload = request.form.get("payload", "")
        meta = {"length": len(payload)}
        log_event("store_payload", meta)
        # Store the raw payload text in a quarantined JSON file
        entry = {"ts": _now_iso(), "src_ip": _client_ip(), "payload": payload}
        try:
            items = []
            if STORED_PAYLOADS.exists():
                with open(STORED_PAYLOADS, "r", encoding="utf-8") as f:
                    items = json.load(f)
            items.append(entry)
            with open(STORED_PAYLOADS, "w", encoding="utf-8") as f:
                json.dump(items, f)
            os.chmod(STORED_PAYLOADS, 0o640)
        except Exception:
            pass
        return redirect(url_for("stored"))
    return render_template("store.html")


@app.route("/stored")
def stored():
    items = []
    try:
        if STORED_PAYLOADS.exists():
            with open(STORED_PAYLOADS, "r", encoding="utf-8") as f:
                items = json.load(f)
    except Exception:
        pass
    log_event("show_stored", {"count": len(items)})
    # Render payloads raw via |safe in template to simulate stored XSS behavior
    return render_template("stored.html", items=items)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file:
            abort(400)
        data = file.read()  # DO NOT process or execute
        sha = hashlib.sha256(data).hexdigest()
        safe_name = f"{sha}_{os.path.basename(file.filename)}"
        dest = QUARANTINE_DIR / safe_name
        try:
            with open(dest, "wb") as f:
                f.write(data)
            os.chmod(dest, 0o640)
        except Exception:
            pass
        meta = {
            "orig_name": file.filename,
            "saved_path": str(dest),
            "size": len(data),
            "sha256": sha,
        }
        log_event("file_upload", meta)
        return render_template("upload.html", saved=meta)
    return render_template("upload.html")


@app.route("/api/user/<uid>", methods=["GET", "POST"])
def api_user(uid: str):
    suspicious = False
    meta: Dict[str, Any] = {"uid": uid}

    if request.method == "POST":
        body = request.get_data(as_text=True) or ""
        suspicious = bool(SQLI_PATTERN.search(body) or XSS_PATTERN.search(body) or DESER_PATTERN.search(body))
        meta["suspicious"] = suspicious
    log_event("api_user", meta)

    # Return fake data regardless
    fake = {
        "uid": uid,
        "name": "Unknown User",
        "role": "guest",
    }
    for u in FAKE_USERS.values():
        if u["uid"] == uid:
            fake = u
            break
    return jsonify(fake)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    injection_like = bool(CMDI_PATTERN.search(host))
    meta = {"host": host, "injection_like": injection_like}
    log_event("ping_attempt", meta)
    # SIMULATED ping output; DO NOT execute system commands
    lines = [
        f"PING {host} (simulation): 56(84) bytes of data.",
        "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms",
        "64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.039 ms",
        "--- ping statistics ---",
        "2 packets transmitted, 2 received, 0% packet loss, time 1ms",
    ]
    return Response("\n".join(lines), mimetype="text/plain")


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    meta = {"url": url}
    ssrf_like = True
    # Very simple whitelist: local-only simulated responses
    if url in {"http://127.0.0.1/", "http://localhost/", "https://127.0.0.1/", "https://localhost/"}:
        ssrf_like = False
        content = "Simulated internal metadata service response (safe)."
        log_event("ssrf_attempt", {"url": url, "whitelisted": True})
        return Response(content, mimetype="text/plain")
    # Block everything else (DO NOT perform outbound requests)
    meta["blocked"] = True
    log_event("ssrf_attempt", meta)
    return Response("Outbound fetch blocked by policy (simulation).", mimetype="text/plain")


@app.route("/go")
def go():
    to = request.args.get("to", "")
    meta = {"to": to}
    log_event("open_redirect", meta)
    # Open redirect simulation: actually perform redirect to keep scanners engaged
    # Note: Recommend running on isolated lab networks due to this behavior.
    return redirect(to or url_for("home"))


@app.route("/deserialize", methods=["POST"])
def deserialize():
    # Insecure deserialization simulation — DO NOT evaluate or unpickle untrusted data
    body = request.get_data(as_text=True) or ""
    suspicious = bool(DESER_PATTERN.search(body))
    meta = {"suspicious": suspicious}
    log_event("deserialize_attempt", meta)
    return jsonify({"status": "ok", "suspicious": suspicious}), 200


@app.route("/download")
def download():
    # Directory traversal simulation — only serve from a safe in-memory mapping
    fn = request.args.get("file", "")
    traversal = bool(TRAVERSAL_PATTERN.search(fn))
    allowed = fn in SAFE_DOWNLOADS
    meta = {"file": fn, "traversal_like": traversal, "allowed": allowed}
    log_event("download_attempt", meta)

    if not allowed:
        return Response("File not found or access denied.", status=404)
    mime, content = SAFE_DOWNLOADS[fn]
    return Response(content, mimetype=mime)


@app.route("/_local_logs")
def local_logs():
    # Admin-only demo endpoint — recommend binding to localhost or removing before exposure
    try:
        n = int(request.args.get("n", "100"))
        n = max(1, min(n, 1000))
    except Exception:
        n = 100
    lines = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-n:]
    except Exception:
        pass
    log_event("local_logs_view", {"count": len(lines)})
    return Response("".join(lines), mimetype="application/json")


# ----------------------
# Error handlers (optional hardening of responses)
# ----------------------
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def errors(e):
    # Keep errors generic but continue logging via before_request hook
    return render_template("error.html", code=getattr(e, "code", 500)), getattr(e, "code", 500)


if __name__ == "__main__":
    # For local testing only; in containers use gunicorn
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
