#!/usr/bin/env python3
"""Aegis Shield - Chat API Server

Minimal HTTP server that exposes the sensitive-info detector as a REST API,
and serves the frontend static files.
"""

import json
import re
import sys
import threading
import http.server
import socketserver
import os
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Detector logic (duplicated from detector.py so this file is self-contained)
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

MONEY_RE = re.compile(
    r"""
    (?:
        \$\s?\d{1,3}(?:,\d{3})*(?:\.\d+)? |
        \$?\d+(?:,\d{3})*(?:\.\d+)?(?:\s*(?:million|billion|thousand|m|bn|k))?
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

SECRET_RE = re.compile(
    r"""
    (?:
        (?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|token|password|auth[_-]?token)
        \s*[:=]\s*([A-Za-z0-9_\-]{6,})
        |
        \b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

PHONE_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?){1,2}\d{3,4}(?![A-Za-z0-9])"
)


def _add_result(results, entity_type, value, start, end):
    results.append({
        "type": entity_type,
        "value": value,
        "start": start,
        "end": end,
    })


def _detect_emails(text, results):
    for match in EMAIL_RE.finditer(text):
        _add_result(results, "EMAIL", match.group(0), match.start(), match.end())


def _detect_money(text, results):
    for match in MONEY_RE.finditer(text):
        candidate = match.group(0).strip()
        if candidate.startswith("$") or any(
            token in candidate.lower() for token in ["million", "billion", "thousand", "m", "bn", "k"]
        ):
            _add_result(results, "MONEY", candidate, match.start(), match.end())


def _detect_secrets(text, results):
    for match in SECRET_RE.finditer(text):
        value = match.group(0).strip()
        _add_result(results, "SECRET", value, match.start(), match.end())


def _detect_phones(text, results):
    for match in PHONE_RE.finditer(text):
        value = match.group(0).strip()
        _add_result(results, "PHONE", value, match.start(), match.end())


def detect_sensitive_info(text):
    """Return structured sensitive-entity detections for the provided text."""
    if not text:
        return []

    results = []
    _detect_emails(text, results)
    _detect_money(text, results)
    _detect_secrets(text, results)
    _detect_phones(text, results)

    results.sort(key=lambda item: (item["start"], item["end"], item["type"]))
    return results


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIST = os.path.join(PROJECT_ROOT, "frontend", "dist")


class AegisHandler(http.server.SimpleHTTPRequestHandler):
    """Handles API routes and serves static files."""

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/detect" or parsed.path == "/api/chat":
            # Let do_POST handle the logic even on GET fallback
            self.do_POST()
        else:
            # Serve static files from frontend/dist
            if parsed.path == "/":
                parsed = urlparse("/index.html")
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
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_json({"error": "Invalid JSON"}, status=400)
            return

        user_message = data.get("message", "") or data.get("query", "") or ""

        # Run detector
        detections = detect_sensitive_info(user_message)

        # Build response
        response = {
            "message": user_message,
            "detections": detections,
            "summary": {
                "total": len(detections),
                "by_type": self._count_by_type(detections),
            },
            "reply": self._generate_reply(detections, user_message),
        }
        self._send_json(response)

    def _count_by_type(self, detections):
        counts = {}
        for d in detections:
            t = d["type"]
            counts[t] = counts.get(t, 0) + 1
        return counts

    def _generate_reply(self, detections, message):
        """Generate a contextual reply based on detections."""
        if not detections:
            return "No sensitive information detected in your message."

        types_found = sorted(set(d["type"] for d in detections))
        type_list = ", ".join(types_found)
        total = len(detections)

        reply = f"I detected {total} potential sensitive item(s) of type(s): {type_list}.\n\n"

        for d in detections:
            value_display = d["value"][:50] + "..." if len(d["value"]) > 50 else d["value"]
            reply += f"- **{d['type']}**: `{value_display}`\n"

        return reply.strip()

    def _send_json(self, data, status=200):
        response = json.dumps(data, ensure_ascii=False)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response.encode("utf-8"))))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response.encode("utf-8"))

    def log_message(self, format, *args):
        """Log to stderr instead of stderr (for visibility)."""
        sys.stderr.write(f"{self.address_string()} - {format % args}\n")
        sys.stderr.flush()


def run_server(port=None, directory=None):
    if port is None:
        port = int(os.environ.get("PORT", 8080))
    if directory and os.path.isdir(directory):
        os.chdir(directory)

    # Allow address reuse
    def create_handler():
        return AegisHandler

    with socketserver.TCPServer(("", port), create_handler) as httpd:
        httpd.allow_reuse_address = True
        print(f"Aegis Shield server running on http://localhost:{port}")
        sys.stdout.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    # Determine frontend dist directory
    front_dist = os.path.join(PROJECT_ROOT, "frontend", "dist")
    if not os.path.isdir(front_dist):
        front_dist = None

    run_server(directory=front_dist)