"""Mock HTTP server for testing — realistic responses for known paths."""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json

SQLI_ERROR_BODY = b"Warning: mysql_fetch_array() error in your SQL syntax near ''"
ROUTES = {
    "/":           (200, "text/html",        b"<html><body>Home</body></html>"),
    "/admin":      (200, "text/html",        b"<html><body>Admin Panel</body></html>"),
    "/login":      (200, "text/html",        b"<html><body><form>Login</form></body></html>"),
    "/api":        (200, "application/json", json.dumps({"version":"1.0"}).encode()),
    "/api/users":  (200, "application/json", json.dumps([{"id":1,"name":"alice"}]).encode()),
    "/api/health": (200, "application/json", json.dumps({"status":"ok"}).encode()),
    "/.git":       (403, "text/html",        b"Forbidden"),
    "/.env":       (403, "text/html",        b"Forbidden"),
    "/backup.zip": (200, "application/zip",  b"FAKE_ZIP"),
    "/config.php": (200, "text/html",        b"<?php // config ?>"),
    "/phpmyadmin": (301, "text/html",        b"Moved"),
}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        params = parse_qs(parsed.query)

        # Simulate SQLi: quote in any param -> DB error
        for values in params.values():
            for v in values:
                if "'" in v or '"' in v:
                    self._respond(500, "text/html", SQLI_ERROR_BODY)
                    return
                # Boolean blind: false condition -> short empty body
                if "1=2" in v or "x'='y" in v or "AND '1'='2" in v:
                    self._respond(200, "text/html", b"<html><body></body></html>")
                    return

        if path in ROUTES:
            code, ctype, body = ROUTES[path]
            self._respond(code, ctype, body, redirect="/login" if code in (301,302) else None)
        else:
            self._respond(404, "text/html", b"Not Found")

    def _respond(self, code, ctype, body: bytes, redirect=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if redirect:
            self.send_header("Location", redirect)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    server = HTTPServer(("localhost", 9998), Handler)
    print("Mock server running on http://localhost:9998")
    server.serve_forever()
