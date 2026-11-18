# Black-Box Brief

> This is the only document the Black-Box Attacker receives. Do not add source code, framework names, stack traces, repository paths, or audit notes. If the Attacker needs something not listed here, the Operator adds it to this file explicitly.

## Target

- Base URL(s):
- Allowed hosts:
- Protocol:
- Rate limit:
- Window:

## Test identities

| Identity | Login URL | Username | Secret | Notes |
|---|---|---|---|---|
| Anonymous | — | — | — | — |
| User A | | | | |
| User B | | | | |
| Admin | | | | |

## Seeded objects

| Object | ID | Owner | Purpose |
|---|---|---|---|
| Order A | | User A | Baseline |
| Order B | | User B | Cross-user test |
| File A | | User A | Download baseline |
| File B | | User B | Cross-user file test |
| Admin object | | Admin | Privileged baseline |

## Known constraints

- All traffic must resolve to the allowlist above.
- Do not follow redirects or callbacks outside the allowlist.
- Proof Cap: one record, first 512 bytes of one file, one harmless command, one admin read.
- Stop on unexpected egress, real PII, or destructive risk.
- Report evidence under `.redteam/evidence/`; redact secrets in the report.

## Out of scope

- Everything not listed in this brief.
- Production, third-party services, real users, and real data.
- DoS, persistence, C2, destructive writes.

## Handoff

- Attacker output: `.redteam/findings.json`, evidence paths, coverage notes.
- Do not read the repository or the audit notes. If the harness forces the same context, declare the run Gray-Box in the report.
