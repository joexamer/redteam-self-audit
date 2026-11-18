# Rules of Engagement

The ROE is the authorization boundary. No attack starts without it. It is written before the target is touched and lives at `.redteam/ROE.md` for the duration of the engagement.

## Refuse without these

Stop immediately if any of the following is true:

- The user cannot attest ownership or written authorization for the target.
- The target is public, production, customer-facing, or a third party.
- The target is not reachable on loopback or a private network created for this run.
- The request includes DoS, destructive writes, persistence, C2, ransomware behavior, or exfiltration beyond the Proof Cap.
- The target contains real user data and no sanitized copy is available.
- The user asks to skip the ROE "just this once".

Refusal script:

> I can't test that target. This skill is limited to systems you own and that run on loopback or a private network created for this assessment. Point me at a local copy and I'll write the ROE and begin. If you don't have a local copy, I can do a static review only and label the result accordingly.

Do not negotiate the local-only rule. Do not accept a promise that "it's fine" without an attestation naming the owner and the target.

## Template

Copy this into `.redteam/ROE.md` and fill every field.

```markdown
# Rules of Engagement

## Engagement
- Engagement ID:
- Date:
- Assessor:
- Target owner:
- Authorization: I attest that I own or am authorized in writing to test the targets below.

## Target allowlist
- Base URLs:
- Hostnames / IPs / ports:
- Environment: local / private Docker network
- Repository:
- Commit:
- Build hash:
- Start:
- Expiry:

## Excluded
- Production and customer-facing systems
- Third-party APIs and services
- Real user accounts and real personal data
- Anything not listed in the allowlist

## Test identities
| Identity | Username | Secret location | Owned seeded objects |
|---|---|---|---|
| Anonymous | — | — | — |
| User A | | | |
| User B | | | |
| Admin | | | |

## Allowed techniques
- Black-box HTTP and browser testing against the allowlist
- Authenticated testing with the identities above
- Proof-capped exploitation (see below)
- Local source review by the White-Box Auditor
- Local tooling: curl, python3, browser automation, and optional scanners

## Prohibited
- DoS, load floods, resource exhaustion
- Destructive writes, data corruption, dropping tables
- Persistence, C2, reverse shells to external hosts, malware
- Exfiltration beyond the Proof Cap
- Attacks on real users, real credentials, or third-party services
- Social engineering
- Testing anything outside the allowlist

## Proof Cap
- Read: one record or the first 512 bytes of one file owned by a Test Identity.
- Write: one reversible change to a seeded object owned by a Test Identity.
- Execute: one harmless command (`id`, `whoami`, `hostname`) proving code execution.
- Admin: one action on a seeded admin account that changes no real data.
- Stop immediately after proof. Do not pivot, persist, or expand.

## Data handling
- Raw evidence: `.redteam/evidence/`, mode 0600, gitignored.
- Reports: redact Authorization, Cookie, Set-Cookie, tokens, API keys, emails, names, card numbers, and PII.
- No production data. No real credentials.
- Delete raw evidence at engagement close unless the owner asks to retain it.

## Stop conditions
- Target unhealthy or unreachable.
- Unexpected egress or a redirect outside the allowlist.
- Discovery of real PII, live secrets, or production data.
- Any test that could corrupt data or take the host down.
- Scope drift.

## Kill switch
- Stop all testing, preserve evidence, and notify the owner.
- Do not resume until the owner re-authorizes in writing.

## Approval
- Owner:
- Signature / written approval reference:
- Date:
```

## Scope drift

A redirect, an external callback, a CDN, a payment sandbox, or an OAuth provider is outside the allowlist even if the app uses it. Test the local behavior, mock the external dependency, and record the gap. Never follow the redirect with attack traffic.

If the app requires an external service to boot, stub it locally. If it cannot be stubbed, dynamic testing is blocked; record the reason and cap the verdict at CONDITIONAL.

## Proof Cap examples

- SQL injection: retrieve one row from a seeded table. Do not dump the database.
- Path traversal: read the first 512 bytes of one seeded file. Do not walk the filesystem.
- Command injection: run `id` or `hostname`. Do not establish a shell or persist.
- IDOR: read one object owned by user B using user A's session. Do not modify or enumerate the whole dataset.
- SSRF: reach one local mock service and return its banner. Do not scan the network.
- File upload: upload one harmless marker file. Do not upload a real webshell or execute a payload beyond `id`.

## Identity rules

- Anonymous, user A, user B, and admin where the app supports roles.
- Seed objects owned by each identity before the attack.
- Reset fixtures between Rounds so results are comparable.
- Credentials live in the BRIEF and the operator's environment, never in the repository or the report.
- If the app has no accounts, record the authorization coverage gap.

## Expiry

The ROE expires at the stated time. An expired ROE stops the engagement. Re-authorize before the next Round.
