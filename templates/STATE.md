# Engagement State

> Update after every phase. This is the resume point if the session is interrupted.

## Identity

- Engagement ID:
- Project:
- Repository:
- Commit:
- Build hash:
- Target URL:
- Isolation mode: Black-Box / Gray-Box
- Capability tier: A / B / C
- ROE: `.redteam/ROE.md`
- Expiry:

## Current Round

- Round: 1
- Phase: 0 / 1 / 2 / 3 / 4 / 5 / 6 / 7 / 8
- Started:
- Last update:

## Findings

- Open Critical:
- Open High:
- Open Medium:
- Open Low:
- Suspected:
- Fixed this Round:
- Retest failed:

## Score and verdict

- Score:
- Verdict: BLOCK / CONDITIONAL / PASS
- Retest Gate: met / not met / not applicable

## Decisions

| Finding | Decision | Owner | Date | Notes |
|---|---|---|---|---|
| | approve / defer / risk-accept | | | |

## Next action

- [ ] Authorize
- [ ] Bring up
- [ ] Attack
- [ ] Audit
- [ ] Prove
- [ ] Report
- [ ] Fix
- [ ] Retest
- [ ] Verdict

## Preflight (complete before Phase 2)

- [ ] ROE signed with an ownership attestation and an expiry.
- [ ] Target resolves to `127.0.0.1`, `localhost`, `[::1]`, or a private network created for this run.
- [ ] Health check exercises the app, not just a TCP connect.
- [ ] `.redteam/` is gitignored; evidence directory is `0700`; files are `0600`.
- [ ] Anonymous, user A, user B, and admin identities exist where roles apply.
- [ ] Each identity owns at least one seeded object with a distinctive marker.
- [ ] `BRIEF.md` has URLs, identities, object IDs, rate limit, and window; it has no source, framework, stack trace, PID, or repo path.
- [ ] A reset hook restores the seed between Rounds.
- [ ] `COMMIT` and `BUILD_HASH` are recorded.
- [ ] Capability tier and isolation mode are recorded; Gray-Box is declared if isolation is not enforced.

## Notes

- Blocked classes:
- Environment issues:
- Evidence location:
