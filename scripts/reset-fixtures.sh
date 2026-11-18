#!/usr/bin/env bash
# Reset seeded fixtures between rounds.
# Usage: reset-fixtures.sh <repo> [--force]
# Only runs a hook declared by the repository. Refuses non-local targets.
set -euo pipefail
umask 077

if [ "$#" -lt 1 ]; then
  echo "usage: reset-fixtures.sh <repo> [--force]" >&2
  exit 2
fi

REPO="$1"
FORCE="${2:-}"
TARGET="${TARGET:-http://127.0.0.1:3000}"

case "$TARGET" in
  http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*) ;;
  *) echo "refusing non-local target: $TARGET" >&2; exit 1 ;;
esac

REPO="$(cd "$REPO" && pwd)"
STATE="$REPO/.redteam"
mkdir -p "$STATE/evidence"

if [ -x "$STATE/reset.sh" ]; then
  echo "running repository reset hook: $STATE/reset.sh"
  TARGET="$TARGET" "$STATE/reset.sh"
  echo "reset complete."
  exit 0
fi

if [ -f "$REPO/package.json" ] && grep -q '"db:reset"' "$REPO/package.json"; then
  echo "running npm run db:reset"
  ( cd "$REPO" && npm run db:reset )
  echo "reset complete."
  exit 0
fi

if [ -f "$REPO/manage.py" ]; then
  echo "running Django migrations (non-destructive)"
  ( cd "$REPO" && python3 manage.py migrate --noinput )
  echo "migrations complete. Seed data must be loaded by the repository hook."
  exit 0
fi

if { [ -f "$REPO/compose.yaml" ] || [ -f "$REPO/docker-compose.yml" ]; } && [ "$FORCE" = "--force" ]; then
  command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }
  echo "recreating compose stack with volumes removed (--force)"
  ( cd "$REPO" && docker compose down -v && docker compose up -d )
  echo "reset complete."
  exit 0
fi

echo "no reset hook found." >&2
echo "Add .redteam/reset.sh, an npm db:reset script, or rerun with --force for compose." >&2
exit 1
