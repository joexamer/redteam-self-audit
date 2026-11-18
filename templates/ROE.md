# Rules of Engagement

> Copy to `.redteam/ROE.md`, fill every field, and sign before the first request. No ROE, no attack.

## Engagement

- Engagement ID:
- Date:
- Assessor:
- Target owner:
- Authorization attestation: I own or am authorized in writing to test the targets below.

## Target allowlist

- Base URLs:
- Hostnames / IPs / ports:
- Environment: local / private Docker network
- Repository:
- Commit:
- Build hash:
- Window start:
- Expiry:

## Excluded

- Production and customer-facing systems
- Third-party APIs and services
- Real user accounts and real personal data
- Anything not listed above

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
- Proof-capped exploitation
- Local source review by the White-Box Auditor
- Local tooling: curl, python3, browser automation, optional scanners

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
- Execute: one harmless command (`id`, `whoami`, `hostname`).
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
- Real PII, live secrets, or production data.
- Any test that could corrupt data or take the host down.
- Scope drift.

## Kill switch

- Stop all testing, preserve evidence, notify the owner.
- Do not resume until the owner re-authorizes in writing.

## Approval

- Owner:
- Signature / written approval reference:
- Date:
