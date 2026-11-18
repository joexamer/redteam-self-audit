# Demo target — deliberately vulnerable app

A small, self-contained Python (stdlib) web app that is **intentionally full of holes**. It exists so you can run the skill end to end without needing your own project: bring it up, seed the identities, attack it, read the code, prove the findings, and fix-and-retest.

> **This app is for local testing only.** It binds to `127.0.0.1`. Do not run it on a host reachable from other machines, and do not deploy it anywhere.

## Run

```bash
cd demo
python3 app.py --port 5002
# health check
curl -sS http://127.0.0.1:5002/health
```

Only the Python standard library is required. The SQLite database `demo/vulnapp.db` is created and seeded on first run. To wipe and reseed between Rounds:

```bash
cd demo
./reset.sh 5002
```

## Seeded identities

| Identity | Username | Password | Owns |
|---|---|---|---|
| User A | `alice` | `alice123` | order 1 |
| User B | `bob` | `bob123` | order 2 |
| Admin | `admin` | `admin123` | admin panel |

## Known vulnerabilities

These are planted on purpose. Start here if you want a written answer key (beating it without peeking is the point of the skill):

1. SQL injection in the login query (`admin' --` bypasses to admin).
2. Reflected XSS in `/search?q=`.
3. Stored XSS in `/comments`.
4. IDOR: any authenticated user reads any `/orders/<id>`.
5. Missing authentication on `/admin`.
6. Plaintext credential disclosure on `/api/users`.
7. Path traversal and absolute-path read in `/download?file=`.
8. Mass assignment of `role` on `/profile`.
9. Open redirect in `/redirect?next=`.
10. Hardcoded secret and filesystem-path disclosure on `/debug`.