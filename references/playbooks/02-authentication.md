# 02 — Authentication

## 1. Scope and preconditions

The app has a login flow and at least one seeded account. The ROE allows credential testing against the local target only. Never test credentials against a real user, a production system, or a third-party identity provider.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/auth"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

| Identity | Purpose |
|---|---|
| Anonymous | Baseline: no session, no token |
| User A | Valid low-privilege session |
| User B | Same role as A, different objects |
| Admin | Valid elevated session |

Seed the passwords locally and store them in the BRIEF, never in the report. Verify each identity logs in before testing bypasses, or every result is ambiguous.

## 3. Enumeration

```bash
curl -sS -i "$TARGET/login" -o "$OUT/login.html"
curl -sS -i -X POST "$TARGET/login" -H 'Content-Type: application/json' \
  -d '{"username":"user-a","password":"correct"}' -c "$OUT/cookies_a.txt" -o /dev/null
curl -sS -i "$TARGET/api/me" -b "$OUT/cookies_a.txt"
```

Identify the login endpoint, the request format, the session cookie or token, and the response differences for success, wrong password, and unknown user.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Default credentials | Try `admin/admin`, `admin/password`, `test/test`, `guest/guest` with a single request each | 200 + session |
| 2 | SQL injection login | `curl -sS -i -X POST "$TARGET/api/login" -H 'Content-Type: application/json' -d "{\"username\":\"' OR 1=1--\",\"password\":\"x\"}"` | Session issued or auth bypass |
| 3 | SQL injection, admin comment | `-d "{\"username\":\"admin'--\",\"password\":\"x\"}"` | Admin session |
| 4 | Username enumeration | Compare valid user + wrong password, invalid user + wrong password | Different message, status, or timing |
| 5 | Rate limit / lockout | 10 failed logins for one user, then a valid login | No 429, no lockout, no delay |
| 6 | Password reset token | Request reset for A, capture token, inspect length/entropy/predictability | Guessable token or token bound to email only |
| 7 | Reset host poisoning | `-H 'Host: attacker.local'` on reset request | Reset link points at attacker host |
| 8 | MFA bypass | Skip the second step, reuse an old code, send `mfa=verified`, call the post-MFA route directly | Access without a valid second factor |
| 9 | Session fixation | Set a known cookie before login, then log in | Cookie does not change |
| 10 | Logout invalidation | Save cookie, log out, replay the cookie | Cookie still valid |
| 11 | Alternate auth path | `/admin` vs `/admin/`, `/api/v1/admin`, `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin` | Protected route reachable |
| 12 | Password change without current password | POST new password with only the session cookie | Password changed |

## 5. Bypass variants

- JSON vs form encoding; duplicate keys (`{"username":"user","username":"admin"}`).
- Unicode normalization, trailing spaces, null bytes in the username.
- Case variation and alternate field names (`user`, `email`, `login`).
- HTTP parameter pollution: `?username=user&username=admin`.
- Content-Type switching: `application/x-www-form-urlencoded` vs `application/json`.
- Method switching: `POST` to `PUT`, `PATCH`, or `GET` on the login route.
- Header trust: `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`.

## 6. Evidence to capture

- The exact login request and the response that issued a session.
- The cookie or token, redacted.
- The identity and the object accessed after bypass.
- Timing for enumeration checks, repeated at least three times.
- The state before and after logout, with a replay of the old session.

## 7. False-positive traps

- A generic "invalid credentials" message on both paths is good behavior, but a measurable timing difference may still leak.
- A 200 response to a failed login may be the app's normal error page. Check for a session cookie or a profile response.
- Rate limiting may be enforced at the proxy; test both the app port and the proxied port.
- A password reset email may not be sent in a local environment. Inspect the mail catcher or logs, not the UI.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Auth bypass to admin | Critical | CWE-287, WSTG-ATHN-04 |
| SQLi login bypass | Critical | CWE-89, WSTG-ATHN-04 |
| Default admin credentials | Critical | CWE-1392, WSTG-ATHN-02 |
| MFA bypass | High | CWE-287, WSTG-ATHN-04 |
| Username enumeration | Low to Medium | CWE-204, WSTG-IDNT-04 |
| No rate limit on login | Medium | CWE-307, WSTG-ATHN-03 |
| Session fixation | High | CWE-384, WSTG-SESS-03 |
| Logout does not invalidate | Medium | CWE-613, WSTG-SESS-06 |

## 9. Remediation patterns

- Parameterize every credential query; never concatenate input.
- Use a vetted identity library with constant-time password verification.
- Return a single generic error for unknown user and wrong password.
- Enforce per-account and per-IP rate limits with exponential backoff.
- Bind reset tokens to the user, a single use, a short expiry, and a server-side secret; never trust the Host header.
- Rotate the session ID on login and logout; invalidate server-side state.
- Require the current password for sensitive account changes.
- Enforce MFA server-side on every protected route, not just in the UI flow.

## 10. Retest procedure

Replay each bypass exactly. Expect a generic failure and no session. For enumeration, confirm the response body, status, and timing are indistinguishable across three runs. For logout, replay the old cookie and expect `401`. For reset poisoning, confirm the link uses the configured canonical host.

## Resources

- OWASP WSTG: WSTG-ATHN, WSTG-IDNT-04, WSTG-SESS-03, WSTG-SESS-06.
- OWASP Cheat Sheet: Authentication, Session Management, Password Storage.
- CWE-287, CWE-89, CWE-307, CWE-384, CWE-613, CWE-1392.
- PortSwigger Academy: authentication and session labs.
