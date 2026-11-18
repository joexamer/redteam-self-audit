# Report Schema

Every Round produces one report and one `findings.json`. The report is for humans; the JSON is for the next Round, the dashboard, and the retest suite.

## Report structure

Use this exact order. Do not omit a section; write "none" when there is nothing to report.

```markdown
# Security Self-Audit — <project> — Round <n>

## Metadata
- Date:
- Commit:
- Build hash:
- Target(s):
- Isolation mode: Black-Box / Gray-Box
- Capability tier:
- Tools and versions:
- ROE: `.redteam/ROE.md`

## Executive summary
Three to six sentences: what was tested, what matters most, and the decision.

## Release verdict
- Verdict: BLOCK / CONDITIONAL / PASS
- Score: <0-100>
- Open Critical/High/Medium/Low:
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
The kill chain, not a tool log. What the attacker did, what it unlocked, and where it stopped.

## Findings table
| ID | Title | Severity | Status | Confidence | CVSS | Chain |
|---|---|---|---|---|---|---|

## Detailed findings
### <ID> — <title>
- Severity / CVSS:
- Status:
- Confidence:
- CWE / WSTG / API Top 10:
- Identity and object:
- Request / response:
- Impact:
- Evidence:
- Remediation:
- Retest:

## Exploit chains
For each chain: ordered steps, linked Finding IDs, combined impact, and why the chain is worse than the parts.

## Coverage matrix
| # | Class | Status | Tests run | Reason if not tested |
|---|---|---|---|---|

## Remediation status
| Finding | Decision | Patch commit | Regression test | Retest result |
|---|---|---|---|---|

## Residual risk
What remains after fixes and what the owner accepted.

## Limitations
What could not be tested, why, and what that means for the verdict.

## Evidence index
Paths under `.redteam/evidence/`, with redaction status.
```

## `findings.json`

Use JSON Schema draft 2020-12. The schema lives at `templates/findings.schema.json`. The runtime file is `.redteam/findings.json`. Validate it before you call the Round done:

```bash
python3 scripts/validate-findings.py .redteam/findings.json --report .redteam/report.md
```

The validator checks required fields, the 13-class coverage, chain references, evidence for Confirmed Findings, score/verdict consistency, and banned completeness claims. It is structural; a human still decides whether the evidence proves the impact. Add `--strict-evidence` to fail when a referenced evidence file is missing next to `findings.json`.

Compute the base score from the vector instead of estimating it:

```bash
python3 scripts/cvss31.py 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
# score: 6.5
# severity: medium
```

Required fields per Finding:

| Field | Type | Notes |
|---|---|---|
| `id` | string | `F-001`, stable across Rounds |
| `title` | string | Short, specific |
| `class` | string | One of the 13 matrix classes |
| `status` | enum | `confirmed`, `suspected`, `fixed`, `retest-failed`, `risk-accepted` |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` |
| `cvss` | object | `vector`, `score` |
| `confidence` | enum | `high`, `medium`, `low` |
| `cwe` | string | `CWE-639` |
| `owasp_ref` | string | `API1:2023` or `A01:2021` |
| `wstg_ref` | string | `WSTG-ATHZ-04` |
| `target` | string | URL or host |
| `commit` | string | Commit tested |
| `build_hash` | string | Build/image hash |
| `identity` | string | `anonymous`, `user-a`, `user-b`, `admin` |
| `request` | string | Redacted request or interaction |
| `response` | string | Redacted response or observation |
| `evidence_paths` | array | Relative paths |
| `impact` | string | What an attacker gains |
| `chain_id` | string or null | Links chained Findings |
| `remediation` | string | Fix guidance |
| `retest` | string | Exact retest procedure |
| `timestamps` | object | `found_at`, `fixed_at`, `retested_at` |

Example:

```json
{
  "id": "F-001",
  "title": "IDOR: user A can read user B's order",
  "class": "authorization",
  "status": "confirmed",
  "severity": "high",
  "cvss": { "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N", "score": 7.7 },
  "confidence": "high",
  "cwe": "CWE-639",
  "owasp_ref": "API1:2023",
  "wstg_ref": "WSTG-ATHZ-04",
  "target": "http://127.0.0.1:5001",
  "commit": "abc1234",
  "build_hash": "sha256:...",
  "identity": "user-a",
  "request": "GET /orders/42 HTTP/1.1\nCookie: sid=[REDACTED:session]",
  "response": "HTTP/1.1 200 OK\n{\"owner\":\"user-b\",\"total\":199.00}",
  "evidence_paths": ["evidence/F-001/request.txt", "evidence/F-001/response.txt"],
  "impact": "Any authenticated user can read another user's order by changing the numeric ID.",
  "chain_id": null,
  "remediation": "Scope the order lookup to the session owner and return 404 on mismatch.",
  "retest": "As user A, request /orders/42; expect 404 and no body.",
  "timestamps": { "found_at": "2026-01-01T10:00:00Z", "fixed_at": null, "retested_at": null }
}
```

## Status transitions

```
suspected ──prove──> confirmed ──fix──> fixed ──retest pass──> fixed (closed)
                         │                  │
                         │                  └─retest fail──> retest-failed ──fix──> fixed
                         └─risk accepted──> risk-accepted
```

- A Finding may move from `confirmed` to `fixed` only with a patch commit and a retest result.
- `retest-failed` reopens the Finding and counts against the Round cap.
- `risk-accepted` requires a written owner decision and an expiry or review date.

## Exploit chains

A chain is an ordered list of steps, each linked to a Finding or a Candidate:

```json
{
  "chain_id": "C-001",
  "title": "Token leak to account takeover",
  "steps": [
    { "order": 1, "finding_id": "F-004", "action": "Read token from exposed debug endpoint" },
    { "order": 2, "finding_id": "F-007", "action": "Replay token against admin API" }
  ],
  "combined_impact": "Unauthenticated attacker becomes admin.",
  "severity": "critical",
  "cvss": { "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8 }
}
```

Chains are scored once at their combined impact, not as the sum of the parts. A Finding that is a step in a chain is scored through that chain and is **not** deducted again on its own:

```
deduction = sum(chain severities) + sum(severities of Confirmed Findings in no chain)
```

List the component Findings in the Findings table, but score the chain in their place. Never deduct both.

## Redaction

Redact before writing the report:

- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`
- Bearer tokens, JWTs, API keys, session IDs
- Email addresses, names, phone numbers, addresses
- Card numbers, bank details, government IDs
- Passwords and password hashes
- Internal hostnames and file paths that reveal infrastructure

Replace values with `[REDACTED:<type>]` and preserve the surrounding structure so the request is still reproducible in shape. Use `scripts/redact-evidence.py`. Raw evidence stays `0600` under `.redteam/evidence/` and is gitignored.

## Confidence

- **High** — reproduced multiple times, unambiguous impact, stable.
- **Medium** — reproduced once, or impact depends on a configuration that is present but not guaranteed.
- **Low** — suspected only, or proof blocked by a fixture/race/environment limitation.

A Confirmed Finding cannot have Low confidence. If confidence is Low, it is Suspected.

## Severity discipline

Tie severity to demonstrated impact:

- Unauthenticated RCE or admin takeover: Critical.
- Authenticated RCE, cross-tenant read/write, privilege escalation: High.
- Limited IDOR, reflected XSS, CSRF on a sensitive action: Medium.
- Information disclosure with no proven path: Low.
- Missing header with no proven exploit: Info, not a Finding.

If a scanner says Critical but the PoC only proves a banner, the Finding is Low or Suspected. Evidence outranks tool output.
