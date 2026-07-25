#!/usr/bin/env bash
# Aegis Shield - Start Script
# Starts the backend server which serves both the API and frontend.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting Aegis Shield..."
echo "Frontend will be served from: frontend/dist"
echo "API endpoint: http://localhost:8080/api/chat"
echo ""
echo "Press Ctrl+C to stop."
echo ""

exec python3 backend/server.py