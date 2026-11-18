#!/usr/bin/env bash
# Bootstrap a local target for redteam-self-audit.
# Usage: bootstrap-target.sh <repo> [port]
# The target is always bound to 127.0.0.1. This script never scans or attacks.
set -euo pipefail
umask 077

if [ "$#" -lt 1 ]; then
  echo "usage: bootstrap-target.sh <repo> [port]" >&2
  exit 2
fi

REPO="$1"
PORT="${2:-3000}"

case "$PORT" in
  ''|*[!0-9]*) echo "invalid port: $PORT" >&2; exit 2 ;;
esac

if [ ! -d "$REPO" ]; then
  echo "repo not found: $REPO" >&2
  exit 2
fi

REPO="$(cd "$REPO" && pwd)"
STATE="$REPO/.redteam"
EVIDENCE="$STATE/evidence"
mkdir -p "$EVIDENCE"
TARGET="http://127.0.0.1:$PORT"
LOG="$STATE/target.log"
PIDFILE="$STATE/target.pid"

if curl -fsS --max-time 2 "$TARGET/" >/dev/null 2>&1; then
  echo "target already healthy: $TARGET"
  echo "reuse it or stop it before bootstrapping again."
  exit 0
fi

if command -v nc >/dev/null 2>&1 && nc -z -w1 127.0.0.1 "$PORT" 2>/dev/null; then
  echo "port $PORT is already in use by another process; choose another port." >&2
  exit 1
fi

start_bg() {
  # $1 = command string, run from the repo root
  ( cd "$REPO" && eval "$1" >"$LOG" 2>&1 & echo $! >"$PIDFILE" )
}

wait_healthy() {
  i=1
  while [ "$i" -le 30 ]; do
    if curl -fsS --max-time 2 "$TARGET/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  return 1
}

if [ -f "$REPO/compose.yaml" ] || [ -f "$REPO/docker-compose.yml" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker compose file found but docker is not installed." >&2
    exit 1
  fi
  echo "starting compose stack (bind check is your responsibility)..."
  ( cd "$REPO" && docker compose up -d )
  if ! wait_healthy; then
    echo "compose started but the target did not become healthy at $TARGET" >&2
    ( cd "$REPO" && docker compose logs --tail=40 ) >&2 || true
    exit 1
  fi
  echo "compose healthy at $TARGET"
elif [ -f "$REPO/package.json" ]; then
  command -v npm >/dev/null 2>&1 || { echo "npm not found" >&2; exit 1; }
  if [ ! -d "$REPO/node_modules" ]; then
    echo "installing node dependencies with --ignore-scripts..."
    if [ -f "$REPO/package-lock.json" ]; then
      ( cd "$REPO" && npm ci --ignore-scripts )
    else
      ( cd "$REPO" && npm install --ignore-scripts )
    fi
  fi
  if grep -q '"start"' "$REPO/package.json"; then
    start_bg "PORT=$PORT HOST=127.0.0.1 npm start"
  elif grep -q '"dev"' "$REPO/package.json"; then
    start_bg "PORT=$PORT HOST=127.0.0.1 npm run dev"
  else
    echo "package.json has no start/dev script; add one or start the target manually." >&2
    exit 1
  fi
elif [ -f "$REPO/manage.py" ]; then
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 1; }
  start_bg "python3 manage.py runserver 127.0.0.1:$PORT"
elif [ -f "$REPO/app.py" ] || [ -f "$REPO/main.py" ]; then
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 1; }
  ENTRY="app.py"
  [ -f "$REPO/main.py" ] && ENTRY="main.py"
  start_bg "PORT=$PORT HOST=127.0.0.1 python3 $ENTRY"
else
  echo "no supported stack detected (compose, package.json, manage.py, app.py, main.py)." >&2
  echo "start the target manually on 127.0.0.1:$PORT and write .redteam/BRIEF.md." >&2
  exit 1
fi

if ! wait_healthy; then
  echo "target did not become healthy at $TARGET" >&2
  echo "--- last 40 log lines ---" >&2
  tail -40 "$LOG" >&2 || true
  exit 1
fi

COMMIT="unknown"
if git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
  COMMIT="$(git -C "$REPO" rev-parse HEAD)"
fi
BUILD_HASH="$( (cd "$REPO" && find . -type f -not -path './.git/*' -not -path './node_modules/*' -print0 2>/dev/null | xargs -0 shasum 2>/dev/null | shasum | cut -d' ' -f1) )"
[ -n "$BUILD_HASH" ] || BUILD_HASH="unknown"

cat > "$STATE/BRIEF.draft.md" <<EOF
# Black-Box Brief (draft)

- Base URL: $TARGET
- Allowed hosts: 127.0.0.1
- Port: $PORT
- Commit: $COMMIT
- Build hash: $BUILD_HASH
- Rate limit: <fill>
- Window: <fill>

Add Test Identities and seeded object IDs before handing this to the Attacker.
Do not add source, framework names, stack traces, PID, logs, or repository paths.
EOF

echo "target healthy: $TARGET"
echo "pid: $(cat "$PIDFILE" 2>/dev/null || echo unknown) (operator only; do not put in BRIEF)"
echo "commit: $COMMIT"
echo "build hash: $BUILD_HASH"
echo "brief draft: $STATE/BRIEF.draft.md"
echo "log: $LOG (operator only; do not put in BRIEF)"
