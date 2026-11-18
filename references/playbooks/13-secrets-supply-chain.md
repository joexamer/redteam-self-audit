# 13 — Secrets and Supply Chain

## 1. Scope and preconditions

This annex is a white-box review of the repository and its build inputs. It complements the black-box attack; it does not replace it. Do not publish or copy any secret found. If a live secret appears, stop the engagement, redact it, and notify the owner.

```bash
REPO="<REPO_PATH>"
OUT=".redteam/evidence/secrets"
mkdir -p "$OUT"
```

## 2. Required Test Identities and seeded data

None. This class reads the repository, lockfiles, CI configuration, and build context. If a secret is found, verify whether it is live only against the local target or a mock; never test a real third-party credential.

## 3. Enumeration

```bash
grep -RInE '(api[_-]?key|apikey|secret|token|password|passwd|private[_-]?key|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|AKIA[0-9A-Z]{16})' \
  "$REPO" --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=venv > "$OUT/grep.txt" || true

git -C "$REPO" log --all --oneline -S 'AKIA' -- . | head -20
git -C "$REPO" log --all -p -S 'password' -- . | head -200
```

Check `.env`, `.env.*`, `config/*`, `docker-compose*.yml`, CI workflows, Dockerfiles, test fixtures, and client bundles.

## 4. Test cases

| # | Test | Exact request / command | Signal |
|---|---|---|---|
| 1 | Working-tree secrets | `grep -RInE` above | Hardcoded key, token, password |
| 2 | Git history | `git log -p --all -S 'secret'` | Deleted secret still recoverable |
| 3 | Environment files | `find "$REPO" -name '.env*' -maxdepth 3 -print` | Real values committed |
| 4 | CI configuration | Inspect `.github/workflows`, `.gitlab-ci.yml`, `Jenkinsfile` | Secrets in plaintext, overbroad permissions |
| 5 | Client bundle | `grep -RInE 'apiKey|secret|token' "$REPO/dist" "$REPO/build" 2>/dev/null` | Server secret shipped to browser |
| 6 | Dependency audit | `npm audit --json` or `pip-audit -r requirements.txt` | Known Critical/High CVE |
| 7 | Lockfile integrity | Compare `package-lock.json`/`poetry.lock` to the manifest | Unpinned or unexpected source |
| 8 | Dockerfile | Inspect `ARG`, `ENV`, `COPY .`, build layers | Secret baked into an image layer |
| 9 | Test fixtures | Search for real emails, tokens, production URLs | Real data in tests |
| 10 | Crypto keys | Search for hardcoded AES/HMAC/JWT keys | Static key used in production |
| 11 | Logs | Search app logs for tokens, cookies, passwords | Secret written to logs |
| 12 | SBOM / licenses | Generate or inspect the SBOM | Unknown or vulnerable component |
| 13 | CI permissions | Check `permissions:` in workflows | `write-all` or unsecured `pull_request_target` |
| 14 | CDN / SRI | Check external scripts for missing integrity | Supply-chain substitution risk |

### Dependency audit

```bash
if [ -f "$REPO/package-lock.json" ]; then
  (cd "$REPO" && npm audit --json) > "$OUT/npm-audit.json" || true
fi
if [ -f "$REPO/requirements.txt" ]; then
  pip-audit -r "$REPO/requirements.txt" > "$OUT/pip-audit.txt" 2>&1 || true
fi
command -v osv-scanner >/dev/null && osv-scanner -r "$REPO" > "$OUT/osv.txt" 2>&1 || true
```

If a tool is missing, inspect the lockfile manually and record the substitution. Do not install a scanner from an untrusted source mid-engagement.

## 5. Bypass variants

- Secret formats: base64, hex, split across variables, concatenated at runtime.
- History: deleted branches, tags, reflog, forks, submodules.
- Build context: `.dockerignore` missing, `COPY .`, multi-stage leaks, layer history.
- CI: `pull_request_target`, cached credentials, artifacts, logs.
- Client: source maps, inline scripts, `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`.
- Dependencies: typosquats, git URLs, unpinned ranges, postinstall scripts.
- Logs: debug mode, verbose errors, request bodies.

## 6. Evidence to capture

- The file, line, and a redacted value.
- Whether the secret is live, test, or a placeholder; do not test a real third-party credential.
- The commit and whether it is in history.
- The dependency, version, CVE, and reachability.
- The CI workflow and the permission that enables abuse.

## 7. False-positive traps

- A placeholder (`changeme`, `example`, `${SECRET}`) is not a live secret.
- A public key is not a private key. Check the header and use.
- A test fixture may be intentionally fake. Verify format and context.
- A dependency CVE may not be reachable. Record the path and the exploit preconditions.
- A client-side `NEXT_PUBLIC_` variable is public by design; only a server secret is a finding.
- A secret in git history may already be rotated. Verify with the owner; still report the exposure.

## 8. Severity guidance

| Finding | Typical severity | CWE / WSTG |
|---|---|---|
| Live cloud key with write access | Critical | CWE-798, CWE-522 |
| Live database password | Critical | CWE-798 |
| JWT/HMAC signing key exposed | Critical | CWE-321, CWE-798 |
| Secret in client bundle | High | CWE-200, CWE-798 |
| Secret in git history | High | CWE-540, CWE-798 |
| Critical dependency CVE, reachable | High to Critical | CWE-1395, CWE-1104 |
| CI `write-all` on fork PR | High | CWE-269, CWE-829 |
| Test fixture with real PII | High | CWE-200, CWE-359 |
| Placeholder or public key | Info | — |

## 9. Remediation patterns

- Remove the secret from code; load it from a secret manager or environment at runtime.
- Rotate every exposed credential, then purge it from history.
- Add `.env*`, keys, and build artifacts to `.gitignore`; use `.dockerignore`.
- Use short-lived credentials and least privilege.
- Pin dependencies and verify lockfile integrity; review postinstall scripts.
- Generate an SBOM and track CVEs; patch or isolate unreachable components.
- Restrict CI permissions; never run untrusted PR code with secrets.
- Scan client bundles in CI for server-only names.

## 10. Retest procedure

Re-scan the working tree and history for the exact secret. Confirm the value is gone or rotated. Rebuild the image and inspect layers. Re-run the dependency audit and confirm the CVE is patched or reachability is documented. Verify the CI workflow permission change.

## Resources

- OWASP WSTG: WSTG-CONF-04, WSTG-INFO-05.
- OWASP Cheat Sheet: Secrets Management, Dependency-Check.
- CWE-200, CWE-269, CWE-321, CWE-522, CWE-540, CWE-798, CWE-829, CWE-1104, CWE-1395.
- NVD, OSV, GitHub Advisory Database for CVE verification.
- Gitleaks/TruffleHog patterns for secret formats (use as references, not targets).
