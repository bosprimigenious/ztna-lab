"""Fixed local resource used to prove that the gateway relay works."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from .netguard import require_loopback


class _ResourceHandler(BaseHTTPRequestHandler):
    server_version = "ZTNA-Lab-Resource/0.2"

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        body = json.dumps(
            {
                "resource": self.server.resource_id,
                "path": self.path,
                "message": "request reached the fixed local resource",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


class ResourceServer:
    def __init__(self, resource_id: str = "demo-resource", host: str = "127.0.0.1", port: int = 0):
        require_loopback(host)
        if not (0 <= port <= 65_535):
            raise ValueError("invalid resource port")
        self.resource_id = resource_id
        self._server = ThreadingHTTPServer((host, port), _ResourceHandler)
        self._server.resource_id = resource_id
        self._thread: Thread | None = None
        self._started = False

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address

    def start(self) -> None:
        if self._started:
            return
        self._thread = Thread(target=self._server.serve_forever, name="ztna-resource", daemon=True)
        self._thread.start()
        self._started = True

    def stop(self) -> None:
        if not self._started:
            self._server.server_close()
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        self._started = False
