#!/usr/bin/env bash
set -euo pipefail

: "${PARTH_UPLOAD_ROOT:=/var/lib/parth/monitoring-uploads}"
: "${PARTH_UPLOAD_BIND_ADDR:=0.0.0.0}"
: "${PARTH_UPLOAD_PORT:=18090}"
: "${PARTH_UPLOAD_MAX_BYTES:=16777216}"
: "${PARTH_UPLOAD_TOKEN:=}"

export DEBIAN_FRONTEND=noninteractive
missing=""
command -v python3 >/dev/null 2>&1 || missing="$missing python3"
if [ -n "$missing" ]; then
  apt-get update
  apt-get install -y $missing
fi

install -d -m 0755 "$PARTH_UPLOAD_ROOT"
install -d -m 0755 /etc/parth

cat >/usr/local/bin/parth-upload-receiver.py <<'PY'
#!/usr/bin/env python3
import json
import os
import posixpath
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(os.environ.get("PARTH_UPLOAD_ROOT", "/var/lib/parth/monitoring-uploads")).resolve()
MAX_BYTES = int(os.environ.get("PARTH_UPLOAD_MAX_BYTES", "16777216"))
TOKEN = os.environ.get("PARTH_UPLOAD_TOKEN", "")


def safe_target(raw_path: str) -> Path:
    parsed = urlparse(raw_path)
    normalized = posixpath.normpath(unquote(parsed.path)).lstrip("/")
    if normalized in ("", ".") or normalized.startswith("../") or "/../" in normalized:
        raise ValueError("invalid upload path")
    target = (ROOT / normalized).resolve()
    if ROOT != target and ROOT not in target.parents:
        raise ValueError("upload path escapes root")
    return target


class Handler(BaseHTTPRequestHandler):
    server_version = "ParthUploadReceiver/1.0"

    def log_message(self, fmt, *args):
        print("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), fmt % args), flush=True)

    def send_json(self, status: HTTPStatus, payload: dict):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def require_token(self) -> bool:
        if not TOKEN:
            return True
        auth = self.headers.get("Authorization", "")
        upload_token = self.headers.get("X-Upload-Token", "")
        if auth == f"Bearer {TOKEN}" or upload_token == TOKEN:
            return True
        self.send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "unauthorized"})
        return False

    def do_GET(self):
        if urlparse(self.path).path == "/healthz":
            self.send_json(HTTPStatus.OK, {"ok": True})
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})

    def do_POST(self):
        self.do_PUT()

    def do_PUT(self):
        if not self.require_token():
            return
        try:
            target = safe_target(self.path)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return

        length_raw = self.headers.get("Content-Length")
        if not length_raw:
            self.send_json(HTTPStatus.LENGTH_REQUIRED, {"ok": False, "error": "missing content-length"})
            return
        try:
            length = int(length_raw)
        except ValueError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid content-length"})
            return
        if length < 0 or length > MAX_BYTES:
            self.send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "error": "upload too large"})
            return

        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    tmp.close()
                    os.unlink(tmp.name)
                    self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "short upload"})
                    return
                tmp.write(chunk)
                remaining -= len(chunk)
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, target)
        self.send_json(HTTPStatus.OK, {"ok": True, "path": str(target), "bytes": length})


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    bind = os.environ.get("PARTH_UPLOAD_BIND_ADDR", "0.0.0.0")
    port = int(os.environ.get("PARTH_UPLOAD_PORT", "18090"))
    server = ThreadingHTTPServer((bind, port), Handler)
    print(f"listening on {bind}:{port}, root={ROOT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
PY
chmod 0755 /usr/local/bin/parth-upload-receiver.py

cat >/etc/parth/upload-receiver.env <<EOF
PARTH_UPLOAD_ROOT=$PARTH_UPLOAD_ROOT
PARTH_UPLOAD_BIND_ADDR=$PARTH_UPLOAD_BIND_ADDR
PARTH_UPLOAD_PORT=$PARTH_UPLOAD_PORT
PARTH_UPLOAD_MAX_BYTES=$PARTH_UPLOAD_MAX_BYTES
PARTH_UPLOAD_TOKEN=$PARTH_UPLOAD_TOKEN
EOF
chmod 0600 /etc/parth/upload-receiver.env

cat >/etc/systemd/system/parth-upload-receiver.service <<'EOF'
[Unit]
Description=Parth monitoring upload receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/parth/upload-receiver.env
ExecStart=/usr/local/bin/parth-upload-receiver.py
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now parth-upload-receiver.service
systemctl restart parth-upload-receiver.service

echo "installed upload receiver: root=$PARTH_UPLOAD_ROOT bind=$PARTH_UPLOAD_BIND_ADDR port=$PARTH_UPLOAD_PORT"
systemctl --no-pager --full status parth-upload-receiver.service || true
