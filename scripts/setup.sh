#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "ATLAS setup"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Update ATLAS_SECRET_KEY before production use."
fi

python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install --upgrade pip --quiet
backend/.venv/bin/python -m pip install -r backend/requirements.txt --quiet

(cd backend && ./.venv/bin/python -m alembic upgrade head)

(cd frontend && npm install)

cat <<'EOF'

Setup complete.
Start the API:   cd backend && ./.venv/bin/python -m uvicorn app.main:app --reload --port 8000
Start the UI:    cd frontend && npm run dev
Open:            http://localhost:5173

First run: the login screen offers workspace bootstrap (first organization + super administrator).
Demo mode: ATLAS_APP_ENV=demo ATLAS_SEED_DEMO_DATA=true (admin@atlas.demo / AtlasDemo!2026)
EOF
