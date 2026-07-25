#!/usr/bin/env python3
"""Aegis Shield - Chat API Server

HTTP server that proxies user prompts through a local Ollama LLM with
automatic PII detection, masking, and restoration.
"""

import json
import os
import sys
import http.server
import socketserver
from urllib.parse import urlparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ollama_gateway import process_prompt

FRONTEND_DIST = os.path.join(PROJECT_ROOT, "frontend", "dist")


class AegisHandler(http.server.SimpleHTTPRequestHandler):
    """Handles API routes and serves static files from frontend/dist."""

    def __init__(self, *args, **kwargs):
        if os.path.isdir(FRONTEND_DIST):
            kwargs["directory"] = FRONTEND_DIST
        super().__init__(*args, **kwargs)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/detect":
            self.do_POST()
        else:
            if parsed.path == "/":
                self.path = "/index.html"
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path in ("/api/detect", "/api/chat"):
            self._handle_chat()
        else:
            self.send_error(404, "Not found")

    def _handle_chat(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            self._send_json({"error": "Invalid JSON"}, status=400)
            return

        user_message = data.get("message", "") or data.get("query", "") or ""
        if not user_message:
            self._send_json({"error": "No message provided"}, status=400)
            return

        try:
            result = process_prompt(user_message)
            response = {
                "message": user_message,
                "sanitized_prompt": result["sanitized_prompt"],
                "reply": result["final_response"],
                "detections": result["detections"],
            }
            self._send_json(response)
        except Exception as exc:
            self._send_json({"error": str(exc)}, status=502)

    def _send_json(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")

    def log_message(self, format, *args):
        sys.stderr.write(f"{self.address_string()} - {format % args}\n")
        sys.stderr.flush()


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def run_server(port=None):
    if port is None:
        port = int(os.environ.get("PORT", 8080))

    with ReusableTCPServer(("", port), AegisHandler) as httpd:
        print(f"Aegis Shield server running on http://localhost:{port}")
        sys.stdout.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    run_server()
