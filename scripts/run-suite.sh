#!/usr/bin/env bash
# Safe, non-destructive smoke suite for a local target.
# Usage: run-suite.sh <target-url> [cookie-jar]
# Emits JSONL evidence. It does not exploit, fuzz, or scan the network.
set -euo pipefail
umask 077

if [ "$#" -lt 1 ]; then
  echo "usage: run-suite.sh <target-url> [cookie-jar]" >&2
  exit 2
fi

TARGET="${1%/}"
COOKIE="${2:-}"

case "$TARGET" in
  http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*) ;;
  *) echo "refusing non-local target: $TARGET" >&2; exit 1 ;;
esac

OUT="${OUT:-.redteam/evidence}"
mkdir -p "$OUT"
JSONL="$OUT/suite.jsonl"
: > "$JSONL"

have_jq=0
command -v jq >/dev/null 2>&1 && have_jq=1

emit() {
  # name, url, status, bytes, signal
  local name="$1" url="$2" status="$3" bytes="$4" signal="$5"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$have_jq" -eq 1 ]; then
    jq -nc --arg ts "$ts" --arg check "$name" --arg url "$url" \
      --argjson status "$status" --argjson bytes "$bytes" --arg signal "$signal" \
      '{ts:$ts,check:$check,url:$url,status:$status,bytes:$bytes,signal:$signal}' >> "$JSONL"
  else
    printf '{"ts":"%s","check":"%s","url":"%s","status":%s,"bytes":%s,"signal":"%s"}\n' \
      "$ts" "$name" "$url" "$status" "$bytes" "$signal" >> "$JSONL"
  fi
  echo "[$status] $name $url $signal"
}

check() {
  # name, path, method, data
  local name="$1" path="$2" method="${3:-GET}" data="${4:-}"
  local url="$TARGET$path"
  local body status size
  body="$(mktemp)"
  if [ -n "$data" ]; then
    if [ -n "$COOKIE" ]; then
      status="$(curl -sS -o "$body" -w '%{http_code}' -X "$method" -b "$COOKIE" \
        -H 'Content-Type: application/json' --data "$data" "$url" 2>/dev/null || true)"
    else
      status="$(curl -sS -o "$body" -w '%{http_code}' -X "$method" \
        -H 'Content-Type: application/json' --data "$data" "$url" 2>/dev/null || true)"
    fi
  else
    if [ -n "$COOKIE" ]; then
      status="$(curl -sS -o "$body" -w '%{http_code}' -X "$method" -b "$COOKIE" "$url" 2>/dev/null || true)"
    else
      status="$(curl -sS -o "$body" -w '%{http_code}' -X "$method" "$url" 2>/dev/null || true)"
    fi
  fi
  case "$status" in
    ''|*[!0-9]*) status=000 ;;
  esac
  size="$(wc -c < "$body" | tr -d ' ')"
  local signal=""
  case "$name" in
    git-head) grep -q '^ref:' "$body" && signal="git-metadata" ;;
    env) grep -qE '^[A-Z0-9_]+=' "$body" && signal="env-values" ;;
    openapi) grep -qiE '"openapi"|"swagger"' "$body" && signal="api-spec" ;;
    actuator) grep -qE 'propertySources|activeProfiles|"beans"' "$body" && signal="actuator-data" ;;
    graphql) grep -q '__schema' "$body" && signal="introspection" ;;
    trace) [ "$status" = "200" ] && grep -qi 'TRACE' "$body" && signal="trace-echo" ;;
    admin) [ "$status" = "200" ] && signal="admin-200" ;;
    debug) grep -qE 'secret|password|token|DB_|DATABASE' "$body" && signal="debug-data" ;;
    robots) signal="$(head -c 120 "$body" | tr '\n' ' ')" ;;
    *) ;;
  esac
  emit "$name" "$url" "$status" "$size" "$signal"
  rm -f "$body"
}

# Baseline
check root /
check robots /robots.txt
check sitemap /sitemap.xml
check git-head /.git/HEAD
check env /.env
check openapi /openapi.json
check swagger /swagger.json
check actuator /actuator/env
check debug /debug
check admin /admin
check login /login
check uploads /uploads/

# Methods
check options / OPTIONS
check trace / TRACE
check graphql /graphql POST '{"query":"{__schema{types{name}}}"}'

# Headers and CORS (recorded, not judged automatically)
HDR="$OUT/headers.txt"
curl -sS -D "$HDR" -o /dev/null "$TARGET/" 2>/dev/null || true
for h in content-security-policy strict-transport-security x-frame-options x-content-type-options referrer-policy permissions-policy; do
  if grep -qi "^$h:" "$HDR"; then
    emit "header-$h" "$TARGET/" 200 0 "present"
  else
    emit "header-$h" "$TARGET/" 200 0 "missing"
  fi
done

CORS="$OUT/cors.txt"
curl -sS -D "$CORS" -o /dev/null -H 'Origin: http://evil.local' "$TARGET/" 2>/dev/null || true
if grep -qi '^access-control-allow-origin:' "$CORS"; then
  emit cors "$TARGET/" 200 0 "$(grep -i '^access-control-allow-origin:' "$CORS" | tr -d '\r')"
else
  emit cors "$TARGET/" 200 0 "no-cors-header"
fi

echo "wrote $JSONL"
