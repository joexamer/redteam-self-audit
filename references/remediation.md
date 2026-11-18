# Remediation

The fix loop is where the audit earns its keep. A Finding is closed only when the original attack fails, the regression suite passes, and a fresh bypass attempt fails.

## Approval

The user decides per Finding, in writing:

- **Approve** — implement the fix this Round.
- **Defer** — keep it open; the Finding stays in the report and caps the verdict.
- **Risk-accept** — the owner accepts the risk with a reason and a review date. The Finding moves to `risk-accepted` and remains visible.

No patch without approval. No batch approval that hides individual decisions. Record every decision in `.redteam/STATE.md` and the report's remediation table.

## Implementer protocol

The Implementer is a separate role from the Black-Box Attacker. It may read the repository and the Finding, but not the Attacker's hidden notes.

1. Reproduce the Finding against the current build. If it no longer reproduces, mark it `retest-failed` or `fixed` only with evidence.
2. Read the surrounding code and the project's conventions.
3. Write the smallest patch that removes the root cause, not the symptom.
4. Add a regression test or a concrete verification step that would fail before the patch.
5. Run the relevant test suite and the retest procedure.
6. Commit once per Finding. Message format: `fix(security): <short title> [F-001]`.
7. Update `findings.json` with the patch commit, test, and retest status.
8. Do not bundle unrelated refactors. Do not weaken logging, monitoring, or tests.

## Fix quality bar

A fix must:

- Remove the root cause: parameterize the query, enforce the authorization check server-side, scope the tenant, validate the upload, escape the output context.
- Preserve behavior the user relies on, unless the feature is explicitly removed.
- Be idiomatic to the repository.
- Include a regression test or a repeatable verification step.
- Be revertible.
- Not depend on a previous fix without stating the dependency.

## Banned fixes

These do not count as remediation:

- Disabling a security control (auth, CSRF, rate limiting, TLS verification).
- Client-side-only validation for a server-side trust boundary.
- Blanket `try/except` or `catch` that swallows the error.
- A WAF rule, regex filter, or blocklist over an injection sink.
- Deleting the feature or route to make the Finding disappear.
- Hiding the endpoint from the UI while leaving it reachable.
- Rotating a secret without fixing the exposure path.
- Adding a header without proving the underlying attack is blocked.

If a proper fix needs an architectural change, write a **Remediation Plan**:

```markdown
## Remediation Plan — F-00X
- Root cause:
- Proposed change:
- Why it cannot be a small patch:
- Risk while open:
- Owner:
- Target date:
- Interim mitigation:
- Acceptance:
```

The Finding stays open or becomes `risk-accepted`; it does not become `fixed`.

## Retest procedure

For every patched Finding:

1. **Original PoC.** Run the exact request/interaction from the report. It must fail.
2. **Regression suite.** Run the project's tests plus the security regression checks for the class. They must pass.
3. **Fresh bypass variants.** Try at least three variants the original PoC did not use: encoding, alternate route, alternate identity, parser edge case, race timing, or chained path. They must fail.
4. **Adjacent classes.** Check that the fix did not open a neighboring gap (for example, fixing IDOR by hiding the ID but leaving the endpoint enumerable).
5. **Evidence.** Save the retest request/response and the test output. Update `findings.json` and `STATE.md`.

If any step fails, reopen the Finding as `retest-failed`, restore or amend the patch, and consume a Round.

## Retest Gate

The Round passes only when:

- Every open Critical and High is `fixed` with retest evidence.
- No new Critical or High appeared in the full regression run.
- The final full pass finds no open Critical/High.
- Mediums are fixed, deferred, or risk-accepted in writing.

The default cap is three Rounds. At the cap with open Critical/High, the verdict is BLOCK.

## Rollback

Every fix must be revertible. Record the commit and the revert command. If a patch depends on a schema migration or data change, include the down migration and a test that exercises it.

## Security regression suite

Keep the PoCs as a growing suite under `.redteam/regression/`:

- One script or request file per Finding.
- A runner that exits non-zero on a confirmed regression.
- A mapping from Finding ID to script.
- Run the entire suite before every Release Verdict, not only the touched classes.

The suite is the institutional memory. The next Round should not have to rediscover the same gap.
