# 01 — Recon and Surface

## 1. Scope and preconditions

The target is running on loopback and the ROE is signed. Recon is non-destructive: read-only requests, no fuzzing that can exhaust the host. The goal is to map the attack surface before touching authentication.

Set these once per session:

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/recon"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

None for anonymous recon. If the app has a public profile or catalog, seed one object per identity so later phases can compare what anonymous, user A, and user B see.

## 3. Enumeration

```bash
curl -sS -D "$OUT/root.headers" "$TARGET/" -o "$OUT/root.body"
for p in robots.txt sitemap.xml security.txt .well-known/security.txt; do
  code=$(curl -sS -o "$OUT/$p" -w '%{http_code}' "$TARGET/$p")
  echo "$p $code"
done
curl -sS "$TARGET/" | grep -oE '(src|href)="[^"]+"' | sort -u > "$OUT/assets.txt"
```

Inspect `assets.txt` for JS bundles, source maps, API prefixes, and admin routes. Fetch each bundle and look for endpoints, feature flags, and secrets.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Exposed dotfiles | `curl -sS -i "$TARGET/.git/HEAD"` | `ref: refs/heads/...` or a git object |
| 2 | Environment file | `curl -sS -i "$TARGET/.env"` | `APP_KEY=`, `DB_`, `SECRET` |
| 3 | API spec | `curl -sS -i "$TARGET/openapi.json"`; repeat `swagger.json`, `api-docs` | JSON schema with hidden routes |
| 4 | GraphQL introspection | `curl -sS -X POST "$TARGET/graphql" -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name fields{name}}}}"}'` | Full type system returned |
| 5 | Source maps | `curl -sS -i "$TARGET/static/app.js.map"` | `"sources":["webpack://..."]` |
| 6 | Debug / actuator | `curl -sS -i "$TARGET/actuator/env"`; repeat `/debug`, `/metrics`, `/server-status` | Environment, heap, or request data |
| 7 | Directory listing | `curl -sS "$TARGET/static/"`; repeat `/uploads/`, `/backup/` | `Index of /` or file links |
| 8 | Error leakage | `curl -sS -i "$TARGET/api/users/not-a-number"` | Stack trace, SQL error, framework path |
| 9 | HTTP methods | `curl -sS -i -X OPTIONS "$TARGET/"; curl -sS -i -X TRACE "$TARGET/"` | Allowed methods, TRACE echo |
| 10 | Backup artifacts | `curl -sS -i "$TARGET/backup.zip"`; repeat `app.bak`, `db.sql`, `dump.tar.gz` | Downloadable archive or SQL |

Use a small, rate-limited wordlist for admin paths only after the manual checks:

```bash
for p in admin administrator manage internal debug console; do
  code=$(curl -sS -o "$OUT/$p.body" -w '%{http_code}' "$TARGET/$p")
  size=$(wc -c < "$OUT/$p.body")
  echo "$p $code $size"
done
```

## 5. Bypass variants

- Path normalization: `/%2e%2e/`, `//admin`, `/admin/..;/`, `/.;/admin`.
- Extension tricks: `.json`, `.bak`, `~`, `.old`, `.swp`, `.map`.
- Case and trailing slash: `/Admin`, `/admin/`, `/admin%2f`.
- Header-based routing: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`.
- Cache deception: append a static extension to a dynamic route and check whether a proxy caches it.

## 6. Evidence to capture

- Raw status line, headers, and a body snippet for every hit.
- The exact request and the response hash.
- A screenshot only when the visual rendering proves something the body does not.
- A note on whether the response is a real artifact or an SPA catch-all.

## 7. False-positive traps

- A single-page app returns `200 text/html` for every unknown path. Check the body marker, not just the status.
- A WAF or reverse proxy may return a branded 404 with `200`. Compare content length and markers.
- `/.git/HEAD` may be a custom 404 that contains the string `HEAD`. Require `ref:` or a valid object.
- Source maps may exist but be empty stubs. Verify `sourcesContent` or real source paths.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Exposed `.git` with secrets | High to Critical | CWE-538, WSTG-CONF-04 |
| Debug/actuator with env or heap | High | CWE-215, WSTG-CONF-02 |
| Downloadable database backup | High to Critical | CWE-538, WSTG-CONF-04 |
| Source maps with full source | Medium | CWE-540, WSTG-INFO-05 |
| Stack traces with paths | Low to Medium | CWE-209, WSTG-ERRH-02 |
| Directory listing | Low to Medium | CWE-548, WSTG-CONF-04 |

Raise severity when the artifact contains credentials, tokens, or a path to admin access.

## 9. Remediation patterns

- Deny dotfiles and backup extensions at the server or proxy.
- Remove source maps from production builds, or restrict them to authenticated internal users.
- Disable debug, actuator, and metrics endpoints publicly; bind them to loopback or an admin network.
- Return generic errors; log details server-side with a correlation ID.
- Disable directory listing; serve static files from an explicit allowlist.

## 10. Retest procedure

Replay each hit exactly. Expect `403`, `404`, or a generic page with no artifact. For source maps, verify the `.map` is absent or returns `401`. For debug endpoints, verify they are unreachable from the anonymous and user identities.

## Resources

- OWASP WSTG: WSTG-INFO, WSTG-CONF-04, WSTG-CONF-05, WSTG-ERRH-02.
- CWE-538, CWE-540, CWE-548, CWE-209.
- HackTricks: web enumeration; SecLists for small targeted wordlists.
