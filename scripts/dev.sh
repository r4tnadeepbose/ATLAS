#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cleanup() {
  echo "Stopping ATLAS development processes..."
  if [ -n "${API_PID:-}" ]; then kill "$API_PID" 2>/dev/null || true; fi
  if [ -n "${UI_PID:-}" ]; then kill "$UI_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

(cd backend && ./.venv/bin/python -m uvicorn app.main:app --reload --port 8000) &
API_PID=$!

(cd frontend && npm run dev) &
UI_PID=$!

echo "ATLAS API  -> http://127.0.0.1:8000"
echo "ATLAS UI   -> http://127.0.0.1:5173"
wait
