#!/usr/bin/env python3
"""Minimal command-injection endpoint for controlled IR experiments."""

from __future__ import annotations

import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


MAX_OUTPUT_BYTES = 8192


class DiagnosticHandler(BaseHTTPRequestHandler):
    """Run an intentionally unsafe diagnostic command using a query parameter."""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/diag":
            self.send_error(404, "not found")
            return

        query = parse_qs(parsed.query)
        target = query.get("target", ["127.0.0.1"])[0]
        command = f"echo diagnostic target={target}"
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (completed.stdout + completed.stderr)[:MAX_OUTPUT_BYTES]

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"exit_code={completed.returncode}\n".encode("utf-8"))
        self.wfile.write(output.encode("utf-8", errors="replace"))

    def log_message(self, fmt: str, *args: object) -> None:
        message = "%s - - [%s] %s" % (
            self.client_address[0],
            self.log_date_time_string(),
            fmt % args,
        )
        print(message, flush=True)


def main() -> None:
    HTTPServer(("0.0.0.0", 8081), DiagnosticHandler).serve_forever()


if __name__ == "__main__":
    main()
