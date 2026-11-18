# Security Self-Audit — <project> — Round <n>

## Metadata

- Date:
- Commit:
- Build hash:
- Target(s):
- Isolation mode: Black-Box / Gray-Box
- Capability tier: A / B / C
- Tools and versions:
- ROE: `.redteam/ROE.md`

## Executive summary

<Three to six sentences: what was tested, what matters most, and the decision.>

## Release verdict

- Verdict: BLOCK / CONDITIONAL / PASS
- Score: <0-100>
- Open Critical:
- Open High:
- Open Medium:
- Open Low:
- Open Suspected:
- Coverage: <0-100>%
- Retest Gate: met / not met / not applicable

## Scope and authorization

- In scope:
- Out of scope:
- Test identities:
- Proof Cap:
- Limitations:

## Attack narrative

<The kill chain, not a tool log. What the attacker did, what it unlocked, where it stopped.>

## Findings table

| ID | Title | Severity | Status | Confidence | CVSS | Chain |
|---|---|---|---|---|---|---|
| | | | | | | |

## Detailed findings

### F-001 — <title>

- Severity / CVSS:
- Status:
- Confidence:
- CWE / WSTG / API Top 10:
- Identity and object:
- Request:
- Response:
- Impact:
- Evidence:
- Remediation:
- Retest:

## Exploit chains

### C-001 — <title>

| Order | Finding | Action |
|---|---|---|
| 1 | F-00X | |
| 2 | F-00Y | |

- Combined impact:
- Severity / CVSS:
- Why the chain is worse than the parts:

## Coverage matrix

| # | Class | Status | Tests run | Reason if not tested |
|---|---|---|---|---|
| 1 | Recon and surface | | | |
| 2 | Authentication | | | |
| 3 | Session and tokens | | | |
| 4 | Authorization | | | |
| 5 | Injection | | | |
| 6 | XSS and client-side | | | |
| 7 | SSRF and network trust | | | |
| 8 | File handling | | | |
| 9 | Deserialization and parsers | | | |
| 10 | Business logic and state | | | |
| 11 | API and realtime | | | |
| 12 | Infrastructure and config | | | |
| 13 | Secrets and supply chain | | | |

## Remediation status

| Finding | Decision | Patch commit | Regression test | Retest result |
|---|---|---|---|---|
| | | | | |

## Residual risk

<What remains after fixes and what the owner accepted.>

## Limitations

<What could not be tested, why, and what that means for the verdict.>

## Evidence index

| Path | Finding | Redacted |
|---|---|---|
| | | |
