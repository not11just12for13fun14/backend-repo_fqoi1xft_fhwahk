#!/usr/bin/env python3
import hashlib
import io
import json
import os
import time
from urllib.parse import urlencode

import requests

BASE = os.getenv("BASE", "http://localhost:8080")

s = requests.Session()

def go(path, **kwargs):
    url = f"{BASE}{path}"
    r = s.request(kwargs.pop("method", "GET"), url, **kwargs)
    print(path, r.status_code)
    if r.headers.get("content-type", "").startswith("application/json"):
        try:
            print(json.dumps(r.json(), indent=2))
        except Exception:
            print(r.text[:200])
    else:
        print(r.text[:200].replace("\n", " "))
    return r

# Home
go("/")

# Login attempt
go("/login", method="POST", data={"username":"admin","password":"Summer2025!"})

# Search with UNION SELECT
q = "1 UNION SELECT password FROM users;--"
go("/search?" + urlencode({"q": q}))

# Reflected XSS
x = "<script>alert('x')</script>"
go("/reflect?" + urlencode({"q": x}))

# Store + view stored payloads
s.post(f"{BASE}/store", data={"payload": "<img src=x onerror=alert(1)>"})
go("/stored")

# Upload a small text file
content = b"hello honeypot"
sha = hashlib.sha256(content).hexdigest()
files = {"file": ("note.txt", io.BytesIO(content), "text/plain")}
go("/upload", method="POST", files=files)

# API user
go("/api/user/1")

go("/api/user/999", method="POST", data="{\"test\":\"__reduce__\"}", headers={"Content-Type":"application/json"})

# Ping with command injection-like payload (simulation)
go("/ping?" + urlencode({"host": "127.0.0.1; ls -la"}))

# Fetch SSRF simulation
go("/fetch?" + urlencode({"url": "http://169.254.169.254/latest/meta-data/"}))

# Open redirect (be careful, follows redirect by default)
r = s.get(f"{BASE}/go?to=https://example.com", allow_redirects=False)
print("/go", r.status_code, r.headers.get("Location"))

# Deserialize attempt
go("/deserialize", method="POST", data="gASV...pickle...")

# Download safe and unsafe
go("/download?file=policy.txt")
go("/download?file=../../etc/passwd")

# Show local logs (demo)
go("/_local_logs?n=20")
