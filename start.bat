@echo off
REM Aegis Shield - Start Script (Windows)
REM Starts the backend server which serves both the API and frontend.

echo Starting Aegis Shield...
echo Frontend will be served from: frontend\dist
echo API endpoint: http://localhost:8080/api/chat
echo.
echo Press Ctrl+C to stop.
echo.

python backend\server.py
