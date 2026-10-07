"""Deliberately vulnerable test web application for CyberSec-MCP lab.
DO NOT EXPOSE TO UNTRUSTED NETWORKS. For local sandbox testing only.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

PORT = 8080

MOCK_ROUTES = {
    "/": {
        "status": 200,
        "content_type": "text/html",
        "body": "<html><head><title>Lab Target</title></head><body><h1>Internal Lab Portal</h1><p>Welcome to the isolated lab environment.</p></body></html>",
        "headers": {"Server": "Apache/2.4.52 (Ubuntu)", "X-Powered-By": "PHP/8.1.2"},
    },
    "/admin": {
        "status": 301,
        "content_type": "text/html",
        "body": "Redirecting to /admin/login",
        "headers": {"Location": "/admin/login"},
    },
    "/admin/login": {
        "status": 200,
        "content_type": "text/html",
        "body": "<html><body><h2>Admin Login Area</h2><form><input name='user'/><input type='password' name='pass'/></form></body></html>",
        "headers": {"Server": "Apache/2.4.52 (Ubuntu)"},
    },
    "/login": {
        "status": 200,
        "content_type": "text/html",
        "body": "<html><body><h2>User Login</h2></body></html>",
        "headers": {"Server": "Apache/2.4.52 (Ubuntu)"},
    },
    "/api": {
        "status": 200,
        "content_type": "application/json",
        "body": json.dumps({"status": "healthy", "version": "1.0.0-lab"}),
        "headers": {"Server": "Apache/2.4.52 (Ubuntu)"},
    },
    "/robots.txt": {
        "status": 200,
        "content_type": "text/plain",
        "body": "User-agent: *\nDisallow: /admin\nDisallow: /secret_backup\n",
        "headers": {},
    },
}


class LabRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        route = MOCK_ROUTES.get(path)
        if route:
            self.send_response(route["status"])
            self.send_header("Content-Type", route["content_type"])
            for h_name, h_val in route["headers"].items():
                self.send_header(h_name, h_val)
            self.end_headers()
            self.wfile.write(route["body"].encode("utf-8"))
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        # Clean logging
        pass


def run():
    server = HTTPServer(("0.0.0.0", PORT), LabRequestHandler)
    print(f"Lab vulnerable service running on port {PORT}...")
    server.serve_forever()


if __name__ == "__main__":
    run()
