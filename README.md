# Redteam Self-Audit

Hack yourself before the bad guys do.

A portable agent skill for an authorized, black-box-first security audit of a locally running application. It attacks the target, proves what is exploitable, audits the source for what traffic cannot reveal, reports CVSS-scored findings with a release verdict, and drives approved fixes through retest Rounds until the gaps are closed.

## What it does

1. **Authorize** — writes a Rules of Engagement with an ownership attestation and a local-only target allowlist.
2. **Bring up** — builds, runs, and seeds the app on loopback with Test Identities and owned objects.
3. **Attack** — a Black-Box Attacker with no repository access runs the 13-class attack matrix, exploits to a Proof Cap, and chains findings.
4. **Audit** — a White-Box Auditor reads the source and emits Candidate Findings for logic, race, tenant, crypto, and parser flaws.
5. **Prove** — every Candidate goes back to the Attacker; only reproduced impact becomes Confirmed.
6. **Report** — evidence, CVSS 3.1, CWE/WSTG/API mapping, Coverage Matrix, residual risk, and a BLOCK/CONDITIONAL/PASS verdict.
7. **Fix** — the user approves per Finding; a separate Implementer patches minimally with a regression test.
8. **Retest** — original PoC must fail, full regression must pass, fresh bypasses must fail. Repeat up to three Rounds.

It is not a scanner. Scanner output is a lead, not a Finding.

## Install

### From source (recommended)

```bash
git clone https://github.com/<you>/redteam-self-audit.git ~/.agents/skills/redteam-self-audit
```

The clone target can be any skill directory. OpenCode and Claude Code both look for skills by folder name:

| Harness | User-level | Project-level |
|---|---|---|
| OpenCode | `~/.agents/skills/` | `.agents/skills/` |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |

### From a zip or local copy

```bash
# User-level (OpenCode)
cp -R redteam-self-audit ~/.agents/skills/

# Project-level
mkdir -p .agents/skills
cp -R redteam-self-audit .agents/skills/
```

The skill is harness-agnostic. It uses normal shell, HTTP, and file tools. Optional tools (`nmap`, `ffuf`, `nuclei`, `sqlmap`, ZAP, browser automation) are detected and substituted, never assumed.

## Requirements and capability tiers

- **Tier A** — shell + Docker. Best isolation: target in a container, Attacker in a network-only context.
- **Tier B** — shell, host-run server. Bind to `127.0.0.1`; isolate the Attacker in a separate session or subagent.
- **Tier C** — no shell. Static review only. Dynamic claims are forbidden; verdict capped at CONDITIONAL.

Required: `bash`, `curl`, `python3`. Optional: `jq`, `git`, `docker`, `npm`, browser automation.

## Quick start

```bash
# Run from the target repository. Point SKILL_DIR at this folder.
SKILL_DIR=/path/to/redteam-self-audit
REPO_PATH="$PWD"

# 0. Protect local evidence
mkdir -p .redteam
cat "$SKILL_DIR/templates/gitignore.redteam" >> .gitignore

# 1. Authorize
cp "$SKILL_DIR/templates/ROE.md" .redteam/ROE.md
$EDITOR .redteam/ROE.md          # fill it in, attest ownership

# 2. Bring up and seed (Operator)
bash "$SKILL_DIR/scripts/bootstrap-target.sh" "$REPO_PATH" 3000

# 3. Write the brief
cp "$SKILL_DIR/templates/BRIEF.md" .redteam/BRIEF.md
$EDITOR .redteam/BRIEF.md        # URLs, identities, seeded object IDs

# 4. Attack (Black-Box Attacker; give it BRIEF.md only)
# 5. Audit (White-Box Auditor; separate context)
# 6. Report, approve fixes, retest
python3 "$SKILL_DIR/scripts/validate-findings.py" .redteam/findings.json --report .redteam/report.md
```

If the target is already running on loopback, skip step 2 and write the brief from the known URL and identities.

No project handy? Run the bundled demo and attack it:

```bash
python3 "$SKILL_DIR/demo/app.py" --port 5002   # deliberately vulnerable local target
# identities and known vulns are documented in demo/README.md
```

## Attack matrix

| # | Class | Playbook |
|---|---|---|
| 1 | Recon and surface | `references/playbooks/01-recon-surface.md` |
| 2 | Authentication | `references/playbooks/02-authentication.md` |
| 3 | Session and tokens | `references/playbooks/03-session-tokens.md` |
| 4 | Authorization | `references/playbooks/04-authorization.md` |
| 5 | Injection | `references/playbooks/05-injection.md` |
| 6 | XSS and client-side | `references/playbooks/06-xss-client-side.md` |
| 7 | SSRF and network trust | `references/playbooks/07-ssrf-network-trust.md` |
| 8 | File handling | `references/playbooks/08-file-handling.md` |
| 9 | Deserialization and parsers | `references/playbooks/09-deserialization-parsers.md` |
| 10 | Business logic and state | `references/playbooks/10-business-logic-state.md` |
| 11 | API and realtime | `references/playbooks/11-api-realtime.md` |
| 12 | Infrastructure and config | `references/playbooks/12-infrastructure-config.md` |
| 13 | Secrets and supply chain | `references/playbooks/13-secrets-supply-chain.md` |

Exploit-chain recipes live in `references/chains.md`.

## Hard rules

- Local and private targets only. Public, production, and third-party targets are refused.
- No ROE, no attack.
- Proof Cap: one record, first bytes of one file, one harmless command, one admin read.
- Black-Box Attacker gets the brief only; if the harness cannot isolate it, the report says Gray-Box.
- No destructive actions, DoS, persistence, C2, or external exfiltration.
- Confirmed requires evidence. No "secure" or "all clear" claims.
- Fixes need per-Finding approval and a retest.

See `SKILL.md` for the full rules and `references/roe.md` for the refusal script.

## Scoring

Start at 100; deduct for Confirmed Findings only: Critical −35, High −12, Medium −4, Low −1. A Finding that is a step in an Exploit Chain is scored through its chain, not again on its own: deduct each chain once at its combined severity plus each Confirmed Finding that belongs to no chain. Coverage below 90% caps the score at 79. Verdict precedence: BLOCK on any open Critical/High or score <70; CONDITIONAL on open Medium, unresolved Suspected High/Critical, coverage <90%, or no dynamic testing; PASS only with no open Critical/High/Medium, coverage ≥90%, and the Retest Gate met.

## Resources

OWASP WSTG, Top 10, API Security Top 10, ASVS, Cheat Sheets, Juice Shop; PortSwigger Academy; HackTricks; PayloadsAllTheThings; Exploit-DB/SearchSploit; CWE; CVSS 3.1; NVD; MITRE ATT&CK; SecLists; Nuclei templates; GTFOBins; LOLBAS; ZAP; Burp; sqlmap; ffuf; nmap; jwt_tool; hashcat; ysoserial; Semgrep; Trivy; Gitleaks; TruffleHog; OSV-Scanner; Playwright; HackerOne Hacktivity; Bugcrowd University. See `references/resources.md` for URLs and usage rules.

## Validation

- **Local fixture:** validated — an independent agent ran the skill end to end against a deliberately vulnerable local app and produced 10 Confirmed Findings, 3 Exploit Chains, 92% coverage, and a BLOCK verdict, all with raw request/response evidence. See [`VALIDATION.md`](VALIDATION.md).
- **Juice Shop calibration:** NOT RUN — Docker is not installed on the build machine. Run the calibration in a Docker-capable environment before relying on the skill for a release decision.
- **Lobotomy tests:** PASS — seven refusal scenarios (public target, ROE skip, production data, destructive proof, external callback, unapproved fix, blind-run PoC) were all refused or redirected to the compliant path. See `tests/refusal-prompts.md`.
- **Fix-and-retest loop:** NOT RUN end to end — the live run stopped at the report. Phase 6–8 behavior is specified and tooled but unverified dynamically.

## Assumptions

- The user can provide a repository and a local run command, or an already-running loopback URL.
- The app has a way to seed test users; if not, authorization coverage is recorded as a gap.
- The harness may or may not support subagents or containers; the skill degrades to a disclosed Gray-Box run.
- No Docker on the build machine, so container isolation and the Juice Shop calibration are unverified here.

## Files

```
redteam-self-audit/
├── SKILL.md
├── README.md
├── LICENSE
├── VALIDATION.md
├── agents/openai.yaml
├── references/
│   ├── roe.md
│   ├── glossary.md
│   ├── methodology.md
│   ├── report-schema.md
│   ├── remediation.md
│   ├── resources.md
│   ├── chains.md
│   └── playbooks/01..13
├── templates/
│   ├── ROE.md
│   ├── BRIEF.md
│   ├── STATE.md
│   ├── findings.schema.json
│   ├── gitignore.redteam
│   └── report.md
├── scripts/
│   ├── bootstrap-target.sh
│   ├── reset-fixtures.sh
│   ├── run-suite.sh
│   ├── redact-evidence.py
│   ├── cvss31.py
│   └── validate-findings.py
├── demo/
│   ├── README.md
│   ├── app.py          # deliberately vulnerable local target
│   ├── reset.sh
│   └── files/
└── tests/
    └── refusal-prompts.md
```

## License and intent

Use only on systems you own or are authorized in writing to test. The skill is built to refuse anything else. If you point it at a public target, it should stop.
