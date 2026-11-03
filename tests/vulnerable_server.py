"""A tiny, deliberately vulnerable HTTP target for offline integration tests.

It binds to 127.0.0.1 on an ephemeral port, so tests never touch the internet
and never collide with anything already listening. NEVER expose this to a
network: it exists to be scanned.

Behaviours it simulates:

  GET /?q=<text>     reflects ``q`` unescaped              -> reflected XSS
  GET /?id=<text>    leaks a MySQL error when ``id`` has ' -> SQL injection
  GET /.env          serves a fake secrets file             -> exposed path
  GET /              sets a cookie with no Secure/HttpOnly, loads an old jQuery
                     without SRI, and posts a form without a CSRF token
  OPTIONS /          advertises TRACE                       -> dangerous method
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlparse

HOME_PAGE = (
    "<html><head>"
    "<script src='https://cdn.example.com/jquery-1.12.4.min.js'></script>"
    "</head><body>"
    "<form method='post' action='/login'>"
    "<input name='user'><input name='pw' type='password'>"
    "</form></body></html>"
)


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):  # keep test output quiet
        pass

    def _send(self, code: int, body: str, content_type: str = "text/html", headers: dict | None = None):
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 (http.server naming)
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path == "/.env":
            return self._send(200, "SECRET_KEY=hunter2\n", "text/plain")

        if url.path == "/":
            if "q" in query:
                return self._send(200, f"<html><body>You searched: {query['q'][0]}</body></html>")
            if "id" in query and "'" in query["id"][0]:
                return self._send(
                    200,
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version",
                )
            return self._send(200, HOME_PAGE, headers={"Set-Cookie": "sid=abc123; Path=/"})

        return self._send(404, "not found")

    def do_POST(self):  # noqa: N802
        self._send(200, "ok")

    def do_OPTIONS(self):  # noqa: N802
        self._send(200, "", headers={"Allow": "GET, POST, PUT, DELETE, TRACE"})


@contextmanager
def running_server() -> Iterator[str]:
    """Start the vulnerable target and yield its base URL (``http://127.0.0.1:PORT/``)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    # `python -m tests.vulnerable_server` gives you a legal, local practice target.
    import time

    with running_server() as base_url:
        print("Deliberately vulnerable practice target (127.0.0.1 only). Press Ctrl-C to stop.")
        print(f"  Paste this into the dashboard:  {base_url}?id=1")
        print(f"  Reflected-XSS variant:          {base_url}?q=hello")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("\nStopped.")
