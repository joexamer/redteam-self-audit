# Methodology

This is the operating manual behind `SKILL.md`. Load it when you start an engagement, when a Round stalls, or when you need the exact scoring and coverage rules.

## The two-lens model

**Attack → Audit → Prove.**

1. **Attack.** The Black-Box Attacker works from the BRIEF and the running target only. It finds what is reachable and proves impact. This phase is intentionally blind to source.
2. **Audit.** The White-Box Auditor reads the repository after the attack. It hunts what traffic cannot reveal: authorization logic, tenant isolation, state machines, race conditions, crypto misuse, trust boundaries between services, and parser paths. It emits Candidate Findings.
3. **Prove.** Every Candidate goes back to the Attacker. If it can be reproduced against the running target, it becomes Confirmed. If not, it is Suspected, with the reason it could not be proven.

Why this order: attacking first keeps the black-box result honest. Auditing first anchors the Attacker to the code and turns the exercise into a source review with extra steps. The audit still matters: a black-box-only test misses logic flaws that never show up in a single request.

## Phases

### Phase 0 — Authorize

**Inputs:** repository path or running URL, owner attestation.
**Actions:** write `.redteam/ROE.md`; resolve targets to loopback/private; set window, identities, Proof Cap, expiry; detect capability tier.
**Outputs:** ROE, capability tier, target allowlist.
**Exit:** signed attestation and a local target. No exceptions.

### Phase 1 — Bring up

**Inputs:** ROE, repository, credentials.
**Actions (Operator):**
- Capture `git rev-parse HEAD` and a build hash (image digest or build artifact hash).
- Build and run on loopback; bind `127.0.0.1`, never `0.0.0.0`.
- Seed Test Identities and owned objects; reset fixtures.
- Verify health with a request that exercises the app, not just a TCP connect.
- Write `.redteam/BRIEF.md` with URLs, allowed hosts, identities, object IDs, rate limit, and window. No source, framework, or stack traces.

**Outputs:** running target, seeded data, BRIEF.
**Exit:** a health check passes and the BRIEF is complete.

### Phase 2 — Attack

**Inputs:** BRIEF only.
**Actions (Black-Box Attacker):**
- Recon: routes, JS bundles, source maps, API specs, GraphQL introspection, debug endpoints, error leakage, default files.
- Run the attack matrix in order, but follow leads. The matrix is coverage, not a script.
- Exploit to the Proof Cap. Capture raw request/response and timestamps.
- Chain: combine findings and test whether the chain reaches a higher impact.
- Record every test as `tested-pass`, `tested-fail`, `not-applicable`, or `blocked`, with a reason.

**Outputs:** evidence, candidate findings, coverage notes.
**Exit:** every reachable class has a status; confirmed findings have evidence.

### Phase 3 — Audit

**Inputs:** repository, BRIEF, attack coverage notes (not the raw exploit payloads).
**Actions (White-Box Auditor):**
- Map source to the matrix. Look for missing authorization checks, tenant scoping, state-machine gaps, race windows, unsafe deserialization, crypto misuse, trust in client input, and secrets.
- Emit Candidate Findings with file/line references and a concrete abuse hypothesis.
- Do not mark anything Confirmed. The Attacker proves it.

**Outputs:** Candidate Findings.
**Exit:** every matrix class has an audit note or a written reason it was not applicable.

### Phase 4 — Prove

**Inputs:** Candidate Findings, running target, BRIEF.
**Actions (Black-Box Attacker):**
- For each Candidate, build the smallest request or browser interaction that demonstrates impact.
- Confirm only if the impact is real and within the Proof Cap. Otherwise mark Suspected and state what blocked proof (needs a race window, missing fixture, unreachable code path, and so on).

**Outputs:** Confirmed and Suspected Findings.
**Exit:** no Candidate remains unclassified.

### Phase 5 — Report

**Inputs:** all Findings, coverage, evidence, ROE, commit/build.
**Actions:** write the report and `findings.json`; score; set the Release Verdict; fill the Coverage Matrix; list residual risk and limitations.
**Outputs:** report, machine-readable findings, state update.
**Exit:** every Confirmed Finding has evidence and a retest step.

### Phase 6 — Fix

**Inputs:** approved Findings.
**Actions:** the user approves, defers, or risk-accepts each Finding. The Implementer reproduces, patches minimally, adds a regression test or verification step, and commits once per Finding with the Finding ID.
**Outputs:** patches, tests, updated state.
**Exit:** every approved Finding has a patch and a retest plan; deferred items have a written decision.

### Phase 7 — Retest

**Inputs:** patched build, original PoCs, regression suite, bypass variants.
**Actions:** rerun the original PoC (must fail), the full regression suite (must pass), and fresh bypass variants (must fail). Check for regressions in adjacent classes.
**Outputs:** retest evidence, reopened Findings.
**Exit:** the Retest Gate is met or a Finding is reopened and a Round is consumed.

### Phase 8 — Verdict

**Inputs:** retest results, open Findings, coverage, risk acceptance.
**Actions:** recompute score and verdict; update `STATE.md`; decide whether to run another Round.
**Outputs:** Release Verdict, next action.
**Exit:** PASS, BLOCK, CONDITIONAL with accepted risk, user stop, or Round cap.

## Test identities

Authorization bugs need identities. Seed at least:

- **Anonymous** — no session.
- **User A** — owns object A.
- **User B** — owns object B, same role as A.
- **Admin** — where the app has roles.

Store credentials only in the BRIEF and the operator environment. Create objects with distinctive markers (for example `owner=A`, `owner=B`) so cross-tenant access is unambiguous. Reset fixtures between Rounds.

If the app has no account model, record the gap: authorization and tenant isolation cannot be dynamically tested.

## Coverage Matrix

Every class gets exactly one status:

| Status | Meaning |
|---|---|
| `tested-pass` | Tests ran and no exploitable behavior was confirmed. |
| `tested-fail` | At least one Confirmed Finding. |
| `not-applicable` | The class cannot exist in this app; written justification required. |
| `blocked` | The class exists but could not be tested; written reason and residual risk required. |

Rules:

- "Not applicable" is a claim about the app, not about the tester's time.
- A blocked class with a plausible exposure caps the verdict at CONDITIONAL.
- Coverage is the percentage of applicable classes with `tested-pass` or `tested-fail`.
- Never inflate coverage by marking a class passed when only one trivial check ran.

## Evidence standard

A Confirmed Finding needs enough evidence for a second person to reproduce it without guessing:

- Raw HTTP request and response, or a browser trace with timestamps.
- The identity and the owned object used.
- `COMMIT` and `BUILD_HASH`.
- The exact command or interaction.
- The observed result and why it proves impact.
- Redacted report copy plus raw local evidence.

Store raw evidence under `.redteam/evidence/<finding-id>/`. Use `scripts/redact-evidence.py` before placing anything in the report. File mode `0600`; add `.redteam/` to `.gitignore`.

## Attacker Posture in practice

- **Feature misuse.** A coupon field is not just a number; it is a state transition. A profile update is not just a form; it is a mass-assignment surface. A PDF export is not just a download; it is a parser and a file path.
- **Trust boundaries.** Trace where the client stops being trusted. Try to cross each boundary: role, tenant, parser, queue, cache, filesystem, template, shell.
- **Chains.** A low-severity information leak plus a permissive CORS policy plus a token in local storage can be a full account takeover. Report the chain, not three disconnected lows.
- **Escalation.** Once you have read access, ask what write access buys. Once you have write, ask what execution buys. Stop at the Proof Cap, not at the first interesting response.
- **Economics.** An attacker takes the cheapest path. Test the boring path first: default creds, exposed admin, missing auth on an API route, a debug endpoint.
- **Persistence.** After a hit, ask what the new access unlocks. Then test that next step. One finding is a door, not a destination.
- **No theater.** A missing header is not a Finding unless it enables an attack. A stack trace is a lead until it reveals a secret or a path. A scanner alert is a hypothesis.

## Feature-to-abuse map

Every feature is a primitive. Use this map to turn a product surface into an attack surface:

| Feature | Abuse primitive | Playbook |
|---|---|---|
| Login | SQLi, enumeration, lockout bypass, session fixation | 02 |
| Profile update | Mass assignment, stored XSS, role injection | 04, 06 |
| Object IDs | IDOR/BOLA, tenant breakout, enumeration | 04 |
| Search | Reflected XSS, SQLi, template injection | 05, 06 |
| File upload | Extension bypass, parser abuse, traversal, SVG XSS | 08 |
| Export / download | IDOR, path traversal, bulk data leak | 04, 08 |
| URL fetch / webhook | SSRF, redirect bypass, blind callback | 07 |
| Password reset | Host header poisoning, token weakness | 02, 12 |
| OAuth / SSO | Redirect abuse, missing state, code theft | 03 |
| GraphQL | Introspection, batching, depth, field authz | 11 |
| WebSocket / SSE | Handshake auth, origin, channel authz | 11 |
| Cart / coupon / refund | Negative values, stacking, race, double spend | 10 |
| Admin panel | Missing auth, forced browsing, weak role check | 04, 12 |
| Debug / actuator | Env secrets, heap, metrics, config | 01, 12 |
| Archive import | Zip slip, XXE, parser traversal | 08 |
| Serialized state | Pickle/Java/PHP/Node RCE, cookie forgery | 09 |
| JWT | `alg: none`, weak secret, `kid`, claim tampering | 03 |
| CI/CD | Secret exposure, overbroad permissions, artifact leak | 13 |

## Scoring

Start at 100.

| Severity | Deduction |
|---|---|
| Critical | −35 |
| High | −12 |
| Medium | −4 |
| Low | −1 |

- Deduct only for Confirmed Findings.
- Floor at 0.
- Fixed-and-retested Findings restore their points.
- Suspected Findings are unscored but cap the verdict at CONDITIONAL until triaged.
- Coverage below 90% caps the score at 79.
- **Scoring unit.** A Confirmed Finding that is a step in an Exploit Chain is scored through its chain, not again on its own. Deduct each Chain once at its combined severity, plus each Confirmed Finding that belongs to no Chain. Never deduct both the chain and its components.
- If a set of Findings might be a chain but you are not sure, score the components and leave the chain as unscored narrative. Do not deduct both.

Severity anchors:

- **Critical** — unauthenticated RCE, auth bypass to admin, full tenant breakout, mass data read.
- **High** — authenticated RCE, privilege escalation, IDOR across tenants, stored XSS in an admin flow, SSRF to internal control planes.
- **Medium** — limited IDOR, reflected XSS with user interaction, CSRF on a sensitive action, business-logic abuse with limited impact.
- **Low** — information disclosure with no direct path, missing hardening with a plausible but unproven chain.
- **Info** — no security impact; do not deduct.

## Release Verdict

Verdict precedence overrides the score:

- **BLOCK** — any open Critical/High, or score below 70.
- **CONDITIONAL** — any open Medium, unresolved Suspected High/Critical, coverage below 90%, or dynamic testing impossible.
- **PASS** — zero open Critical/High/Medium, coverage at least 90%, and the Retest Gate met.

A PASS is scoped to the tested commit and surface. It is not a statement that the app is secure.

## Round loop

- Default cap: three Rounds.
- A Round ends with a report and a decision: fix, accept risk, or stop.
- A failed retest reopens the Finding and consumes a Round.
- If the Round cap is reached with open Critical/High, the verdict is BLOCK and the report lists the unclosed gaps.
- Mediums and Lows may be risk-accepted in writing; they stay in the report as open risk.

## Anti-patterns

- **Source contamination.** The Attacker reads the repo and "finds" exactly what the code says. Label Gray-Box if this happens; do not pretend it was black-box.
- **Scanner theater.** Running nuclei and pasting its output is not an audit.
- **Checklist compliance.** Marking classes passed because a tool ran, without testing abuse.
- **Fix by deletion.** Removing a feature to close a Finding is not a fix unless the user explicitly accepts the feature loss.
- **Retest by hope.** Marking fixed without rerunning the original PoC and a bypass variant.
- **Completeness claims.** "No vulnerabilities found" is forbidden. Say what was tested and what was not.
- **Severity inflation.** A missing header is not Critical because it feels scary. Tie severity to demonstrated impact.
