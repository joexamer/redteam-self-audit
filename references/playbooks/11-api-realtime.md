# 11 — API and Realtime

## 1. Scope and preconditions

The app exposes REST, GraphQL, WebSocket, SSE, or gRPC. Test the API directly, not through the UI. The ROE allows local traffic only; do not call external identity providers or third-party APIs.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/api"
A="$OUT/cookies_a.txt"
B="$OUT/cookies_b.txt"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

User A and user B with separate objects; admin for privileged fields. Seed a realtime channel or subscription owned by each identity so cross-user delivery can be tested.

## 3. Enumeration

```bash
for p in /openapi.json /swagger.json /api-docs /graphql /api/v1 /api/v2; do
  code=$(curl -sS -o "$OUT/$(echo "$p" | tr '/' '_')" -w '%{http_code}' "$TARGET$p")
  echo "$p $code"
done
curl -sS -X POST "$TARGET/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name} mutationType{name} types{name kind}}}"}' | jq .
```

Check for older API versions, undocumented endpoints, and a GraphQL schema that exposes admin mutations.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | GraphQL introspection | `-d '{"query":"{__schema{types{name fields{name}}}}"}'` | Full schema exposed |
| 2 | GraphQL depth | Send a 20-level nested query | Server accepts unbounded depth |
| 3 | GraphQL batching | `-d '[{"query":"{me{id}}"},{"query":"{me{id}}"}]'` | Batch bypasses rate limit |
| 4 | GraphQL field authz | Query `users { email role }` as A | Admin fields returned |
| 5 | REST mass assignment | PATCH `/api/users/me` with `{"role":"admin","tenant":"other"}` | Fields updated |
| 6 | Resource consumption | Request a large page size or expensive filter repeatedly | No limit, CPU/memory spike |
| 7 | WebSocket handshake auth | `curl -i -N -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H 'Sec-WebSocket-Version: 13' "$TARGET/ws"` | `101` without a valid session |
| 8 | WebSocket origin | Same handshake with `-H 'Origin: http://evil.local'` | `101` accepted cross-origin |
| 9 | WebSocket authz | Subscribe to user B's channel as A (use `websocat` if installed) | B's events delivered |
| 10 | SSE authz | `curl -N -b "$A" "$TARGET/events?user=<B_ID>"` | B's events delivered |
| 11 | API inventory | Request `/api/v1/...` and `/api/v2/...` for the same route | Old version lacks a fix |
| 12 | gRPC reflection | `grpcurl -plaintext 127.0.0.1:50051 list` (if gRPC) | Services exposed unauthenticated |
| 13 | Method override | `-H 'X-HTTP-Method-Override: DELETE'` on a GET/POST route | Method bypass |
| 14 | CORS | `curl -sS -i -H 'Origin: http://evil.local' -b "$A" "$TARGET/api/me" \| grep -i access-control` | `*` with credentials or reflected origin |

### WebSocket frame test

If `websocat` is installed:

```bash
websocat -H="Cookie: $(cat "$A" | sed -n 's/.*\t//p' | tail -1)" \
  "ws://127.0.0.1:5001/ws" <<'EOF'
{"action":"subscribe","channel":"user-b"}
EOF
```

If no WebSocket client is available, the handshake test still proves missing auth or origin checks. Mark message-level authz as `blocked` with the reason; do not claim it passed.

## 5. Bypass variants

- GraphQL: aliases, fragments, `node(id:)`, batched arrays, GET requests, content-type switching.
- REST: version downgrade, path case, trailing slash, `.json` suffix, method override headers.
- Auth: cookie vs bearer, query token, duplicate headers, `X-User-Id` trust.
- Rate limits: distributed across endpoints, batch, WebSocket frames, SSE reconnect.
- Realtime: origin null, subprotocol confusion, channel name enumeration, reconnect replay.
- gRPC: reflection, health service, unknown methods, metadata injection.

## 6. Evidence to capture

- The schema or API inventory.
- The exact query/request and the privileged response.
- The WebSocket handshake and the delivered frame.
- The channel or subscription and the owning identity.
- Rate-limit headers and the burst count.

## 7. False-positive traps

- GraphQL introspection may be intentionally enabled in development. Check whether it exposes mutations or sensitive fields, not just types.
- A `101` handshake does not prove message access; auth may be enforced on the first frame.
- CORS `*` without credentials may be safe for public data. Check `Access-Control-Allow-Credentials`.
- An old API version may be a stub. Confirm it returns real data.
- A rate limit may be applied at the proxy; test the app port and the proxied port.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| GraphQL authz bypass to admin | Critical | CWE-862, API5:2023 |
| WebSocket authz across users | High | CWE-862, WSTG-CLNT-10 |
| WebSocket no auth | High | CWE-306, WSTG-CLNT-10 |
| Mass assignment | High | CWE-915, API3:2023 |
| Unbounded GraphQL depth | Medium | CWE-400, API4:2023 |
| CORS with credentials and reflected origin | High | CWE-942, WSTG-CLNT-07 |
| Old API version without a fix | High | CWE-1059, API9:2023 |
| Introspection enabled | Low to Medium | CWE-200, WSTG-APIT-01 |

## 9. Remediation patterns

- Enforce authorization on every resolver, subscription, and REST handler; do not rely on the gateway.
- Disable introspection and the playground in production, or restrict them to admins.
- Limit query depth, complexity, and batch size.
- Authenticate the WebSocket handshake and every message; validate `Origin`.
- Scope SSE and channel subscriptions to the session identity.
- Retire old API versions or apply the same controls.
- Configure CORS with an exact allowlist and credentials only where required.

## 10. Retest procedure

Replay the schema query; expect introspection disabled or restricted. Replay the privileged field query; expect `null` or an auth error. Replay the WebSocket handshake without a session; expect `401`/`403`. Replay the cross-user subscription; expect no delivery. Replay the mass-assignment and CORS requests; expect rejection and an exact origin allowlist.

## Resources

- OWASP WSTG: WSTG-APIT, WSTG-CLNT-07, WSTG-CLNT-10.
- OWASP API Security Top 10: API1, API3, API4, API5, API9.
- OWASP Cheat Sheet: GraphQL, WebSocket, CORS.
- CWE-306, CWE-400, CWE-862, CWE-915, CWE-942.
- PortSwigger Academy: GraphQL, WebSocket, CORS labs.
