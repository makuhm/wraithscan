"""
Mock HTTP server for Wraithscan testing.
Simulates realistic vulnerable and safe endpoints.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json

# SQLi simulation
SQLI_ERROR_BODY = b"Warning: mysql_fetch_array() error in your SQL syntax near ''"

# Auth simulation — valid credentials
VALID_CREDENTIALS = {
    "admin":  "admin123",
    "root":   "toor",
}

# XSS simulation bodies
def xss_vulnerable_body(value: str) -> bytes:
    """Reflects input directly into page — classic reflected XSS."""
    return f"""<html><body>
<h1>Search Results</h1>
<p>You searched for: {value}</p>
</body></html>""".encode()

def xss_safe_body(value: str) -> bytes:
    """HTML-encodes the reflected value — properly escaped."""
    import html
    safe = html.escape(value)
    return f"""<html><body>
<h1>Search Results</h1>
<p>You searched for: {safe}</p>
</body></html>""".encode()

def xss_attr_body(value: str) -> bytes:
    """Reflects input inside an HTML attribute — attr context XSS."""
    return f'<html><body><input type="text" value="{value}"></body></html>'.encode()

ROUTES = {
    "/":           (200, "text/html",        b"<html><body>Home</body></html>"),
    "/admin":      (200, "text/html",        b"<html><body>Admin Panel</body></html>"),
    "/login":      (200, "text/html",        b"<html><body><form>Login</form></body></html>"),
    "/api":        (200, "application/json", json.dumps({"version": "1.0"}).encode()),
    "/api/users":  (200, "application/json", json.dumps([{"id": 1, "name": "alice"}]).encode()),
    "/api/health": (200, "application/json", json.dumps({"status": "ok"}).encode()),
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

        # --- SQLi simulation ---
        for values in params.values():
            for v in values:
                if "'" in v or '"' in v:
                    self._respond(500, "text/html", SQLI_ERROR_BODY)
                    return
                if "1=2" in v or "x'='y" in v or "AND '1'='2" in v:
                    self._respond(200, "text/html", b"<html><body></body></html>")
                    return

        # --- XSS simulation endpoints ---

        # /search?q=... — vulnerable, reflects raw input
        if path == "/search":
            q = params.get("q", [""])[0]
            self._respond(200, "text/html", xss_vulnerable_body(q))
            return

        # /search-safe?q=... — safe, HTML-encodes input
        if path == "/search-safe":
            q = params.get("q", [""])[0]
            self._respond(200, "text/html", xss_safe_body(q))
            return

        # /profile?name=... — reflects into attribute value
        if path == "/profile":
            name = params.get("name", [""])[0]
            self._respond(200, "text/html", xss_attr_body(name))
            return

        # --- Auth simulation ---
        if path == "/login-post":
            # handled in do_POST
            self._respond(405, "text/html", b"Method Not Allowed")
            return

        # --- Standard routes ---
        if path in ROUTES:
            code, ctype, body = ROUTES[path]
            self._respond(code, ctype, body, redirect="/login" if code in (301, 302) else None)
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

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        from urllib.parse import parse_qs
        fields = {k: v[0] for k, v in parse_qs(body).items()}

        if path == "/login-post":
            user = fields.get("username", "")
            pwd  = fields.get("password", "")
            if VALID_CREDENTIALS.get(user) == pwd:
                # Success — redirect to dashboard
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                # Failure — return login page with error
                body = b"<html><body>Invalid username or password. Try again.</body></html>"
                self._respond(200, "text/html", body)
            return

        self._respond(404, "text/html", b"Not Found")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("localhost", 9998), Handler)
    print("Mock server running on http://localhost:9998")
    server.serve_forever()
