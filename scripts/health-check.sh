#!/usr/bin/env bash
set -euo pipefail

BASE="${ATLAS_API_URL:-http://127.0.0.1:8000}"

check() {
  local name="$1" url="$2"
  if code="$(curl -fsS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)"; then
    echo "OK   $name ($code)"
  else
    echo "FAIL $name ($url)"
    return 1
  fi
}

check "liveness" "$BASE/health/live"
check "readiness" "$BASE/health/ready"
check "openapi" "$BASE/api/openapi.json"

echo
echo "Adapter availability requires an authenticated session: GET /api/v1/scans/tools"
