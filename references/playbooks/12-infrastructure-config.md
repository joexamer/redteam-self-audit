# 12 — Infrastructure and Config

## 1. Scope and preconditions

The target is a local service, container, or host-run process. Test only the ports and endpoints created for this engagement. Do not scan the host's other services or the local network.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/infra"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

Anonymous for headers and default services; admin for admin panels. Seed an admin session so a panel that requires auth can be distinguished from one that does not.

## 3. Enumeration

```bash
curl -sS -D "$OUT/headers.txt" "$TARGET/" -o /dev/null
for port in 22 2375 5000 5432 6379 8080 9090 9200 27017; do
  nc -z -w1 127.0.0.1 "$port" 2>/dev/null && echo "open: $port"
done
```

Only the target's declared ports are in scope. If an unexpected port is open, record it and stop; do not scan further.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Security headers | Inspect `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` | Missing or unsafe values |
| 2 | TLS configuration | `openssl s_client -connect 127.0.0.1:443 -tls1_1` (if HTTPS) | Weak protocol or cipher |
| 3 | CORS | `curl -sS -i -H 'Origin: http://evil.local' -b "$OUT/cookies_a.txt" "$TARGET/api/me"` | Reflected origin with credentials |
| 4 | Debug / actuator | `curl -sS -i "$TARGET/actuator/env"`; repeat `/debug`, `/metrics`, `/heapdump` | Environment, heap, or metrics |
| 5 | Admin panel | `curl -sS -i "$TARGET/admin"`; repeat `/admin/`, `/manager`, `/console` | Login page or direct access |
| 6 | Default services | Connect to an exposed Redis/Postgres/Elasticsearch port | `PING`, auth-less access, open index |
| 7 | HTTP methods | `curl -sS -i -X TRACE "$TARGET/"`; `OPTIONS` | TRACE echo or dangerous methods |
| 8 | Host header injection | `curl -sS -i -H 'Host: evil.local' "$TARGET/"`; password reset with the same header | Poisoned link or cache |
| 9 | Cache poisoning | `-H 'X-Forwarded-Host: evil.local'` on a cacheable page | Poisoned cached response |
| 10 | Proxy trust | `-H 'X-Forwarded-For: 127.0.0.1'` on an admin route | IP allowlist bypass |
| 11 | Error pages | Request a malformed path and a bad method | Stack trace, server version, paths |
| 12 | Docker socket | `curl --unix-socket /var/run/docker.sock http://localhost/version` (only if the target exposes it) | Host control |
| 13 | Static file serving | Request `/..%2f..%2fetc%2fpasswd`, `/.env`, `/server-status` | File read or status page |
| 14 | Container metadata | Point the target at the local mock from playbook 07 (`http://127.0.0.1:9098/latest/meta-data/`); never send traffic to `169.254.169.254` | Mock credentials returned |

### Header review

```bash
curl -sS -D - "$TARGET/" -o /dev/null | grep -iE 'content-security-policy|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|server|x-powered-by'
```

A missing header is not automatically a Finding. Tie it to an exploit: missing `X-Frame-Options` plus a sensitive action is clickjacking; missing CSP plus an XSS sink is an enabler; `Server` version disclosure is Low.

## 5. Bypass variants

- Host header: duplicate `Host`, `X-Forwarded-Host`, `X-Original-Host`, absolute URI in the request line.
- IP trust: `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Client-IP`, `X-Client-IP`.
- Path normalization: `//admin`, `/admin/..;/`, `/%2e%2e/admin`, `/.%2fadmin`.
- Method override: `X-HTTP-Method-Override`, `_method=DELETE`.
- Cache keys: unkeyed headers, query parameter cloaking, fat GET.
- Service exposure: Unix socket, Docker API, Redis `CONFIG`, Postgres `trust`, Elasticsearch open index.

## 6. Evidence to capture

- The raw headers and the missing or unsafe values.
- The exact request that reached an admin/debug endpoint.
- The open port and the banner or response.
- The poisoned cache response and the key used.
- The proxy-trust header and the resulting access.

## 7. False-positive traps

- A header may be added by a proxy that is not in the repo; check the deployed response, not the source.
- An open port may be the test harness. Confirm it belongs to the target.
- A `200` on `/admin` may be a login page, not access. Check the body and the session.
- Host header reflection in a link is not exploitable unless the link is used for a password reset or cache.
- `TRACE` may be disabled at the proxy while enabled at the app. Test both.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Docker socket / host control | Critical | CWE-668, CWE-306 |
| Debug endpoint with secrets | High | CWE-215, WSTG-CONF-02 |
| Auth-less Redis/Postgres | Critical | CWE-306, CWE-1188 |
| Host header password reset poisoning | High | CWE-640, WSTG-INPV-17 |
| Cache poisoning | High | CWE-349, CWE-444 |
| IP allowlist bypass via header | High | CWE-290, CWE-348 |
| CORS with credentials | High | CWE-942 |
| Missing security headers | Low to Medium | CWE-693, CWE-1021 |
| Version disclosure | Low | CWE-200, WSTG-INFO-02 |

## 9. Remediation patterns

- Bind debug, admin, and data services to loopback or an internal network; require auth.
- Never expose the Docker socket to the app.
- Validate the `Host` header against an allowlist; build absolute URLs from configuration.
- Trust forwarded headers only from a known proxy; strip them at the edge.
- Configure CORS with an exact allowlist.
- Add security headers at the app or edge; use `frame-ancestors` and a strict CSP.
- Disable TRACE and unnecessary methods.
- Remove version banners and stack traces.

## 10. Retest procedure

Replay each request. Expect `403`/`404` for debug and admin paths, no open data port, a canonical host in reset links, and no cache poisoning. Recheck the headers and the proxy-trust behavior. Confirm the Docker socket is unreachable from the app.

## Resources

- OWASP WSTG: WSTG-CONF, WSTG-INFO-02, WSTG-INPV-17.
- OWASP Cheat Sheet: HTTP Security Headers, CORS, Host Header Injection.
- CWE-200, CWE-290, CWE-306, CWE-349, CWE-444, CWE-640, CWE-668, CWE-693, CWE-942.
- PortSwigger Academy: host header, cache poisoning, CORS labs.
