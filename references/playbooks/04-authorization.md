# 04 — Authorization

## 1. Scope and preconditions

The app has authenticated users and at least one object owned by user B. Authorization bugs are the highest-yield class in most apps; test them with real sessions, not by reading the UI.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/authz"
A="$OUT/cookies_a.txt"
B="$OUT/cookies_b.txt"
ADMIN="$OUT/cookies_admin.txt"
B_OBJECT_ID="<id owned by user B>"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

| Identity | Owns |
|---|---|
| User A | Object A, order A, profile A |
| User B | Object B, order B, profile B |
| Admin | Admin-only object and route |

Record the exact object IDs in the BRIEF. Verify A cannot see B's object before you start; otherwise the baseline is broken.

## 3. Enumeration

```bash
curl -sS -b "$A" "$TARGET/api/orders" | jq .
curl -sS -b "$B" "$TARGET/api/orders" | jq .
curl -sS -b "$A" "$TARGET/api/users/me" | jq .
```

Map every route that takes an object ID: path segment, query parameter, JSON body, GraphQL argument, header, or cookie. Map every role-gated route: admin, internal, billing, export, impersonate.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | IDOR read | `curl -sS -b "$A" "$TARGET/api/orders/$B_OBJECT_ID"` | B's data returned to A |
| 2 | IDOR write | `curl -sS -b "$A" -X PATCH "$TARGET/api/orders/$B_OBJECT_ID" -H 'Content-Type: application/json' -d '{"note":"a-was-here"}'` | B's object changed |
| 3 | BOLA in body | `-d '{"order_id":"<B_ID>","action":"refund"}'` as A | Refund on B's order |
| 4 | BFLA | `curl -sS -b "$A" "$TARGET/api/admin/users"` | Admin data returned |
| 5 | Mass assignment | `curl -sS -b "$A" -X PATCH "$TARGET/api/users/me" -H 'Content-Type: application/json' -d '{"role":"admin"}'` | Role changed |
| 6 | Tenant isolation | Change `tenant_id` or `org_id` in the session or body | Cross-tenant read/write |
| 7 | Forced browsing | `curl -sS "$TARGET/admin"` with no cookie | Admin page or API |
| 8 | GraphQL field authz | `curl -sS -b "$A" -X POST "$TARGET/graphql" -H 'Content-Type: application/json' -d '{"query":"{ users { id email role } }"}'` | Admin-only fields returned |
| 9 | Method bypass | Repeat a denied request as `GET`, `PUT`, `PATCH`, `DELETE`, and `POST` | One method skips the check |
| 10 | Duplicate IDs | `?id=<A_ID>&id=<B_ID>` or duplicate JSON keys | Parser uses the unchecked value |
| 11 | Nested object | `{"user":{"id":"<B_ID>"},"action":"..."}` | Acts on B's object |
| 12 | Export / report route | Request an export with another user's ID | Bulk data leak |

## 5. Bypass variants

- ID encoding: base64, hex, UUID vs integer, negative numbers, zero, very large numbers.
- Path tricks: `/orders/42.json`, `/orders/42/`, `/orders//42`, `/orders/42%00`.
- Parameter pollution: duplicate query keys, JSON duplicate keys, array vs scalar.
- Header trust: `X-User-Id`, `X-Tenant-Id`, `X-Forwarded-User` supplied by the client.
- Role injection: `role=admin`, `is_admin=true`, `permissions[]=admin`.
- GraphQL: aliases, fragments, nested fields, batched queries, `node(id:)`.
- Tenant switching: change a cookie, a JWT claim, or a hidden form field.

## 6. Evidence to capture

- The request as A, the response containing B's data, and the same request as B for comparison.
- The object ownership marker and the object ID.
- For writes, the before and after state, and the restore.
- The role or tenant claim used.
- The exact route and method.

## 7. False-positive traps

- A `200` with an empty object may be a safe denial. Check whether any B-owned field is present.
- Cached responses may show another user's data because of a shared cache, not an authz bug. Vary the session and repeat.
- A UI hide is not a server check. Test the API directly.
- Admin routes may be protected by a proxy rule; test the app port directly.
- GraphQL may return `null` for unauthorized fields. Check each field, not just the HTTP status.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Cross-tenant read | High | CWE-639, WSTG-ATHZ-04 |
| Cross-tenant write | Critical | CWE-639, WSTG-ATHZ-04 |
| User to admin escalation | Critical | CWE-269, WSTG-ATHZ-03 |
| BFLA on admin API | High to Critical | CWE-862, API5:2023 |
| Mass assignment to role | High | CWE-915, API3:2023 |
| Missing auth on internal route | High | CWE-306, WSTG-ATHZ-02 |
| Object enumeration with no data | Low | CWE-639, WSTG-ATHZ-04 |

## 9. Remediation patterns

- Enforce authorization server-side on every object access, using the session identity and the object's owner/tenant, not a client-supplied ID.
- Centralize the check in a policy layer; do not duplicate it per route.
- Deny by default; explicitly allow roles and fields.
- Allowlist mass-assignment fields; never bind a request body directly to a model.
- Scope every query by tenant at the data layer, not just the controller.
- Return `404` for objects the caller cannot see, to avoid enumeration.

## 10. Retest procedure

Replay every request as A against B's object. Expect `403` or `404` and no B-owned field. Replay the mass-assignment and role-injection requests; expect the role unchanged. Replay the GraphQL query; expect `null` or an authorization error for protected fields. Confirm B can still access their own object.

## Resources

- OWASP WSTG: WSTG-ATHZ, WSTG-IDNT.
- OWASP API Security Top 10: API1:2023 BOLA, API3:2023 BOPLA, API5:2023 BFLA.
- OWASP Cheat Sheet: Authorization.
- CWE-269, CWE-306, CWE-639, CWE-862, CWE-915.
- PortSwigger Academy: access control and IDOR labs.
