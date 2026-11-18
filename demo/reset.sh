#!/usr/bin/env bash
# Reset the deliberately vulnerable fixture to its seeded state.
# Usage: reset.sh [port]
set -euo pipefail
umask 077

PORT="${1:-5002}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="$HERE/.redteam/target.pid"

if [ -f "$PIDFILE" ]; then
  PID="$(cat "$PIDFILE")"
  if kill -0 "$PID" 2>/dev/null && ps -p "$PID" -o command= 2>/dev/null | grep -q 'app.py'; then
    kill "$PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      kill -0 "$PID" 2>/dev/null || break
      sleep 0.2
    done
  fi
fi

rm -f "$HERE/vulnapp.db"
cd "$HERE"
python3 app.py --port "$PORT" > .redteam/target.log 2>&1 &
echo $! > "$PIDFILE"

for _ in $(seq 1 30); do
  if curl -fsS --max-time 1 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "fixture reset and healthy on http://127.0.0.1:$PORT"
    exit 0
  fi
  sleep 0.2
done

echo "fixture did not become healthy" >&2
tail -20 .redteam/target.log >&2 || true
exit 1
