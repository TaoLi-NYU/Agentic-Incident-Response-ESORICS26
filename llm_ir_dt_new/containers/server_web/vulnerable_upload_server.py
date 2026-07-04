#!/usr/bin/env python3
"""Minimal intentionally writable HTTP endpoint for controlled IR experiments."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


UPLOAD_DIR = Path("/var/www/html/uploads")
MAX_UPLOAD_BYTES = 1024 * 1024


class UploadHandler(BaseHTTPRequestHandler):
    """Accept a small HTTP POST body and write it under the web root."""

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/upload":
            self.send_error(404, "not found")
            return

        query = parse_qs(parsed.query)
        filename = query.get("name", ["observed_web1_file.txt"])[0]
        safe_name = Path(filename).name
        if not safe_name:
            self.send_error(400, "missing filename")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "bad content length")
            return

        if content_length <= 0 or content_length > MAX_UPLOAD_BYTES:
            self.send_error(413, "invalid upload size")
            return

        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        body = self.rfile.read(content_length)
        destination = UPLOAD_DIR / safe_name
        destination.write_bytes(body)

        self.send_response(201)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"stored=/uploads/{safe_name}\n".encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        message = "%s - - [%s] %s" % (
            self.client_address[0],
            self.log_date_time_string(),
            fmt % args,
        )
        print(message, flush=True)


def main() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    HTTPServer(("0.0.0.0", 8080), UploadHandler).serve_forever()


if __name__ == "__main__":
    main()
