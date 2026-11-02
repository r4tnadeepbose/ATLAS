#!/usr/bin/env bash
set -euo pipefail

# Backup the ATLAS PostgreSQL database. Usage:
#   DATABASE_URL=postgresql://atlas:...@host:5432/atlas ./scripts/backup.sh [output-dir]
# Or with Docker Compose:
#   ./scripts/backup.sh --compose

OUT_DIR="${1:-./backups}"
mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$OUT_DIR/atlas-$STAMP.sql.gz"

if [ "${1:-}" = "--compose" ] || [ "${1:-}" = "" ] && [ -z "${DATABASE_URL:-}" ]; then
  docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-atlas}" "${POSTGRES_DB:-atlas}" | gzip > "$TARGET"
else
  : "${DATABASE_URL:?Set DATABASE_URL or pass --compose}"
  pg_dump "$DATABASE_URL" | gzip > "$TARGET"
fi

echo "Backup written to $TARGET"
echo "Restore with: gunzip -c $TARGET | psql \$DATABASE_URL"
