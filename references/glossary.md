# Glossary

Canonical terms for this skill. Use them exactly so the roles, the report, and the retest loop mean the same thing to every agent.

**Black-Box Attacker** — The role that attacks the running target with network and browser tooling only, receiving no repository access and no source context.
_Avoid_: pentester, red team, hacker (each is ambiguous about access level).

**Operator** — The role allowed to read the repository solely to build, run, and seed the target, then issue a sanitized brief.
_Avoid_: deployer, DevOps, setup agent.

**Implementer** — The role that patches approved Findings with repository access, separate from the Black-Box Attacker.
_Avoid_: fixer, developer agent.

**Rules of Engagement (ROE)** — The explicit, per-run authorization block fixing target hosts, allowed techniques, and prohibited actions. No attack starts without it.
_Avoid_: scope doc, permission note.

**Proof Cap** — The limit on exploitation: enough access or data to prove impact, never more.
_Avoid_: safe mode, dry run.

**Finding** — A security-relevant behavior tied to a specific target and evidence. Confirmed Findings carry reproduction evidence; Suspected Findings do not yet.
_Avoid_: vuln, issue, bug (each is too broad).

**Candidate Finding** — A suspected weakness produced by audit or tooling that has not been exploited. It is not a Finding until the Black-Box Attacker proves it or it is demoted to Suspected.
_Avoid_: audit issue, potential vuln.

**Coverage Matrix** — The enumerated record of which attack classes were tested, passed, failed, or not tested, with a reason for every gap.
_Avoid_: checklist, test plan.

**Retest Gate** — The exit condition: the original PoC fails, the full regression suite passes, fresh bypass variants fail, and no new Critical or High appears.
_Avoid_: verification, recheck.

**Round** — One attack-report-fix-retest cycle. A Round opens with a brief and closes with a Release Verdict or a blocked state.
_Avoid_: iteration, sprint.

**Release Verdict** — The terminal judgment of a Round: BLOCK, CONDITIONAL, or PASS, backed by evidence.
_Avoid_: score, rating (a score may support the verdict but does not replace it).

**White-Box Auditor** — The role that reads the repository after the black-box phase to surface Candidate Findings that traffic could not reveal.
_Avoid_: code reviewer, SAST.

**Test Identity** — A seeded account (anonymous, user A, user B, admin) with owned objects, used to test authorization boundaries.
_Avoid_: test user, dummy account.

**Attacker Posture** — The mandatory operating stance that treats every feature as an abuse primitive, chains weaknesses into exploit paths, and escalates to the maximum reachable impact within the Proof Cap.
_Avoid_: scanner mode, checklist mode.

**Exploit Chain** — Two or more weaknesses combined to reach impact that neither achieves alone; the unit of reporting when chaining is what makes an attack real.
_Avoid_: attack path, kill chain (reserve "kill chain" for the narrative).

**Remediation Plan** — A fix that requires architectural change, recorded with owner, risk, and acceptance instead of being patched superficially.
_Avoid_: workaround, quick fix.
