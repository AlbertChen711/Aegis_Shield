#!/usr/bin/env python3
"""Aegis Shield - Chat API Server

HTTP server that proxies user prompts through Ollama with
automatic PII detection, masking, and restoration.
"""

import json
import os
import socket
import sys
import http.server
import socketserver
from urllib.parse import urlparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ollama_gateway import process_prompt

OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:latest")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_API_KEY = os.environ.get("OLLAMA_API_KEY", "")
FRONTEND_DIST = os.path.join(PROJECT_ROOT, "frontend", "dist")
MAX_REQUEST_BYTES = int(os.environ.get("MAX_REQUEST_BYTES", "20000"))
MAX_MESSAGE_CHARS = int(os.environ.get("MAX_MESSAGE_CHARS", "4000"))


class AegisHTTPServer(socketserver.TCPServer):
    allow_reuse_address = True


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

        if path in {"/api/detect", "/api/chat"}:
            self._handle_chat()
        else:
            self.send_error(404, "Not found")

    def _handle_chat(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"error": "Invalid Content-Length"}, status=400)
            return

        if content_length <= 0:
            self._send_json({"error": "No request body provided"}, status=400)
            return

        if content_length > MAX_REQUEST_BYTES:
            self._send_json({"error": "Request body too large"}, status=413)
            return

        try:
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self._send_json({"error": "Invalid JSON"}, status=400)
            return
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            self._send_json({"error": f"Failed to read request body: {exc}"}, status=400)
            return

        user_message = data.get("message", "") or data.get("query", "") or ""
        if not isinstance(user_message, str):
            self._send_json({"error": "Message must be a string"}, status=400)
            return

        user_message = user_message.strip()
        if not user_message:
            self._send_json({"error": "No message provided"}, status=400)
            return

        if len(user_message) > MAX_MESSAGE_CHARS:
            self._send_json({"error": "Message exceeds maximum supported length"}, status=413)
            return

        try:
            result = process_prompt(
                user_message,
                model=OLLAMA_MODEL,
                base_url=OLLAMA_URL,
                api_key=OLLAMA_API_KEY,
            )
            response = {
                "sanitized_prompt": result["sanitized_prompt"],
                "reply": result["final_response"],
                "detections": self._redact_detections(result["detections"]),
                "legend": result.get("legend", ""),
                "security_report": result.get("security_report", {}),
            }
            self._send_json(response)
        except RuntimeError as exc:
            self._send_json({"error": str(exc)}, status=503)
        except Exception as exc:
            self._send_json({"error": "AI processing failed"}, status=502)

    def _redact_detections(self, detections):
        redacted = []
        for detection in detections:
            redacted.append(
                {
                    "type": detection.get("type", "UNKNOWN"),
                    "start": detection.get("start", 0),
                    "end": detection.get("end", 0),
                    "value": f"[redacted {detection.get('type', 'data').lower()}]",
                }
            )
        return redacted

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


def _resolve_port(port):
    requested_port = int(port or os.environ.get("PORT", "8080"))
    for candidate in [requested_port] + list(range(requested_port + 1, requested_port + 11)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("0.0.0.0", candidate))
            return candidate
        except OSError:
            continue
    raise OSError(f"Unable to find an available port near {requested_port}")


def run_server(port=None):
    port = _resolve_port(port)

    try:
        with AegisHTTPServer(("0.0.0.0", port), AegisHandler) as httpd:
            print(f"Aegis Shield server running on http://localhost:{port}")
            sys.stdout.flush()
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nShutting down server.")
    except OSError as exc:
        raise RuntimeError(f"Failed to start server on port {port}: {exc}") from exc


if __name__ == "__main__":
    print(f"Using Ollama model: {OLLAMA_MODEL} at {OLLAMA_URL}")
    if OLLAMA_API_KEY:
        print("Using Ollama API key authentication.")
    try:
        run_server()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
