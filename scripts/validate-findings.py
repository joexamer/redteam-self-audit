#!/usr/bin/env python3
"""Validate .redteam/findings.json against the package contract.

No third-party dependencies. This is a structural and consistency check, not a
full JSON Schema implementation; it enforces the rules that change a verdict.

Usage:
  python3 validate-findings.py .redteam/findings.json
  python3 validate-findings.py .redteam/findings.json --report .redteam/report.md

Exit codes: 0 valid, 1 invalid, 2 usage or parse error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CLASSES = [
    "recon",
    "authentication",
    "session",
    "authorization",
    "injection",
    "xss",
    "ssrf",
    "file",
    "deserialization",
    "business-logic",
    "api",
    "infrastructure",
    "secrets",
]
SEVERITIES = {"critical", "high", "medium", "low", "info"}
STATUSES = {"confirmed", "suspected", "fixed", "retest-failed", "risk-accepted"}
DEDUCTION = {"critical": 35, "high": 12, "medium": 4, "low": 1, "info": 0}
BANNED_CLAIMS = [
    r"\bfully secure\b",
    r"\bno vulnerabilities\b",
    r"\ball clear\b",
    r"\b100% secure\b",
    r"\bprovably secure\b",
]

errors: list[str] = []
warnings: list[str] = []
STRICT_EVIDENCE = False


def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def require(obj: dict, key: str, where: str) -> object | None:
    if key not in obj:
        err(f"{where}: missing required key '{key}'")
        return None
    return obj[key]


def check_cvss(value: object, where: str) -> None:
    if not isinstance(value, dict):
        err(f"{where}: cvss must be an object")
        return
    vector = value.get("vector")
    score = value.get("score")
    if not isinstance(vector, str) or not re.match(r"^CVSS:3\.1/", vector):
        err(f"{where}: cvss.vector must start with CVSS:3.1/")
    if not isinstance(score, (int, float)) or not 0 <= score <= 10:
        err(f"{where}: cvss.score must be 0..10")
    if isinstance(score, (int, float)):
        if score >= 9.0 and value.get("severity") not in (None, "critical"):
            warn(f"{where}: cvss.score >= 9 but severity is not critical")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("findings")
    parser.add_argument("--report", help="optional report.md to scan for banned claims")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument(
        "--strict-evidence",
        action="store_true",
        help="error when an evidence path does not exist next to findings.json",
    )
    args = parser.parse_args()
    global STRICT_EVIDENCE
    STRICT_EVIDENCE = args.strict_evidence

    path = Path(args.findings)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"error: not found: {path}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(data, dict):
        print("error: top level must be an object", file=sys.stderr)
        return 1

    for key in (
        "schema_version",
        "engagement_id",
        "round",
        "commit",
        "build_hash",
        "findings",
        "chains",
        "coverage",
        "score",
        "verdict",
    ):
        require(data, key, "root")

    if data.get("schema_version") != "1.0":
        err("root: schema_version must be '1.0'")
    if not isinstance(data.get("round"), int) or data.get("round", -1) < 0:
        err("root: round must be a non-negative integer")
    for key in ("engagement_id", "commit", "build_hash"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            err(f"root: {key} must be a non-empty string")

    findings = data.get("findings")
    if not isinstance(findings, list):
        err("root: findings must be an array")
        findings = []

    ids: set[str] = set()
    severities: dict[str, str] = {}
    statuses: dict[str, str] = {}

    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            err(f"{where}: must be an object")
            continue
        fid = f.get("id", "")
        if not isinstance(fid, str) or not re.match(r"^F-[0-9]{3,}$", fid):
            err(f"{where}: id must match F-<3+ digits>")
        elif fid in ids:
            err(f"{where}: duplicate id {fid}")
        else:
            ids.add(fid)
            severities[fid] = str(f.get("severity", ""))
            statuses[fid] = str(f.get("status", ""))

        for key in (
            "title",
            "class",
            "status",
            "severity",
            "cvss",
            "confidence",
            "cwe",
            "owasp_ref",
            "wstg_ref",
            "target",
            "commit",
            "build_hash",
            "identity",
            "request",
            "response",
            "evidence_paths",
            "impact",
            "chain_id",
            "remediation",
            "retest",
            "timestamps",
        ):
            require(f, key, where)

        if f.get("class") not in CLASSES:
            err(f"{where}: class must be one of the 13 classes")
        if f.get("status") not in STATUSES:
            err(f"{where}: invalid status")
        if f.get("severity") not in SEVERITIES:
            err(f"{where}: invalid severity")
        if f.get("confidence") not in {"high", "medium", "low"}:
            err(f"{where}: invalid confidence")
        if isinstance(f.get("cwe"), str) and not re.match(r"^CWE-[0-9]+$", f["cwe"]):
            err(f"{where}: cwe must match CWE-<number>")

        cvss = f.get("cvss")
        check_cvss(cvss, where)
        if isinstance(cvss, dict) and f.get("severity") in SEVERITIES:
            score = cvss.get("score")
            if isinstance(score, (int, float)):
                if score >= 9.0 and f["severity"] != "critical":
                    warn(f"{where}: score {score} but severity {f['severity']}")
                if 7.0 <= score < 9.0 and f["severity"] not in {"high", "critical"}:
                    warn(f"{where}: score {score} but severity {f['severity']}")

        evidence = f.get("evidence_paths")
        if not isinstance(evidence, list) or not all(isinstance(x, str) for x in evidence):
            err(f"{where}: evidence_paths must be an array of strings")
        elif f.get("status") == "confirmed" and not evidence:
            err(f"{where}: confirmed finding needs at least one evidence path")

        if evidence:
            base = path.parent
            for rel in evidence:
                target = Path(rel) if Path(rel).is_absolute() else base / rel
                if not target.exists():
                    msg = f"{where}: evidence path not found: {target}"
                    if STRICT_EVIDENCE:
                        err(msg)
                    else:
                        warn(msg)

        if f.get("status") == "confirmed" and f.get("confidence") == "low":
            err(f"{where}: confirmed finding cannot have low confidence")

        timestamps = f.get("timestamps")
        if isinstance(timestamps, dict):
            if not timestamps.get("found_at"):
                err(f"{where}: timestamps.found_at is required")
            if f.get("status") == "fixed" and not timestamps.get("retested_at"):
                err(f"{where}: status 'fixed' requires timestamps.retested_at")
        else:
            err(f"{where}: timestamps must be an object")

    chains = data.get("chains")
    if not isinstance(chains, list):
        err("root: chains must be an array")
        chains = []
    chain_ids: set[str] = set()
    for i, c in enumerate(chains):
        where = f"chains[{i}]"
        if not isinstance(c, dict):
            err(f"{where}: must be an object")
            continue
        cid = c.get("chain_id", "")
        if not isinstance(cid, str) or not re.match(r"^C-[0-9]{3,}$", cid):
            err(f"{where}: chain_id must match C-<3+ digits>")
        elif cid in chain_ids:
            err(f"{where}: duplicate chain_id {cid}")
        else:
            chain_ids.add(cid)
        steps = c.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            err(f"{where}: a chain needs at least 2 steps")
        else:
            for j, step in enumerate(steps):
                if not isinstance(step, dict):
                    err(f"{where}.steps[{j}]: must be an object")
                    continue
                sid = step.get("finding_id")
                if sid not in ids:
                    err(f"{where}.steps[{j}]: unknown finding_id {sid!r}")
                if not isinstance(step.get("action"), str) or not step["action"].strip():
                    err(f"{where}.steps[{j}]: action is required")
        if c.get("severity") not in SEVERITIES:
            err(f"{where}: invalid severity")
        check_cvss(c.get("cvss"), where)

    coverage = data.get("coverage")
    covered: set[str] = set()
    if not isinstance(coverage, list) or len(coverage) < 13:
        err("root: coverage must contain all 13 classes")
        coverage = coverage if isinstance(coverage, list) else []
    for i, c in enumerate(coverage):
        where = f"coverage[{i}]"
        if not isinstance(c, dict):
            err(f"{where}: must be an object")
            continue
        cls = c.get("class")
        if cls not in CLASSES:
            err(f"{where}: invalid class {cls!r}")
        elif cls in covered:
            err(f"{where}: duplicate class {cls}")
        else:
            covered.add(cls)
        if c.get("status") not in {"tested-pass", "tested-fail", "not-applicable", "blocked"}:
            err(f"{where}: invalid status")
        if not isinstance(c.get("tests_run"), int) or c.get("tests_run", -1) < 0:
            err(f"{where}: tests_run must be a non-negative integer")
        if c.get("status") != "tested-pass" and not c.get("reason"):
            warn(f"{where}: non-pass coverage should carry a reason")

    missing = [c for c in CLASSES if c not in covered]
    if missing:
        err(f"coverage: missing classes {missing}")

    tested = sum(1 for c in coverage if isinstance(c, dict) and c.get("status") in {"tested-pass", "tested-fail"})
    pct = round(100 * tested / 13) if coverage else 0
    if pct < 90:
        warn(f"coverage: {pct}% dynamic coverage caps the verdict at CONDITIONAL")

    score = data.get("score")
    verdict = data.get("verdict")
    if not isinstance(score, (int, float)) or not 0 <= score <= 100:
        err("root: score must be 0..100")
        score = None
    if verdict not in {"BLOCK", "CONDITIONAL", "PASS"}:
        err("root: verdict must be BLOCK, CONDITIONAL, or PASS")
        verdict = None

    open_sev = {
        fid: sev
        for fid, sev in severities.items()
        if sev in {"critical", "high", "medium"}
        and statuses.get(fid) in {"confirmed", "retest-failed"}
    }
    suspected_high = [
        fid
        for fid, sev in severities.items()
        if sev in {"critical", "high"} and statuses.get(fid) == "suspected"
    ]
    open_critical_high = [fid for fid, sev in open_sev.items() if sev in {"critical", "high"}]

    if verdict == "PASS":
        if open_sev:
            err(f"verdict: PASS with open critical/high/medium findings: {sorted(open_sev)}")
        if suspected_high:
            err(f"verdict: PASS with unresolved suspected high/critical: {suspected_high}")
        if pct < 90:
            err(f"verdict: PASS requires coverage >= 90%, got {pct}%")
    if verdict == "BLOCK" and not open_critical_high and score is not None and score >= 70:
        warn("verdict: BLOCK without an open critical/high finding and score >= 70")
    if verdict == "CONDITIONAL" and score is not None and score < 70:
        err("verdict: score < 70 requires BLOCK")
    if verdict == "PASS" and score is not None and score < 70:
        err("verdict: score < 70 cannot be PASS")

    # Scoring unit: a Finding that is a step in a chain is scored through its chain.
    # Expected deduction = chain severities + severities of Confirmed Findings in no chain.
    chained_ids: set[str] = set()
    for c in chains:
        if isinstance(c, dict):
            for step in c.get("steps", []) or []:
                if isinstance(step, dict) and isinstance(step.get("finding_id"), str):
                    chained_ids.add(step["finding_id"])

    expected = 0
    for c in chains:
        if isinstance(c, dict):
            expected += DEDUCTION.get(str(c.get("severity", "")), 0)
    for fid, sev in severities.items():
        if statuses.get(fid) == "confirmed" and fid not in chained_ids:
            expected += DEDUCTION.get(sev, 0)
    expected = max(0, 100 - expected)
    if pct < 90:
        expected = min(expected, 79)

    if score is not None and chains and score != expected:
        warn(
            f"score: {score} != {expected} under the scoring unit "
            f"(chains scored once; {len(chained_ids)} component finding(s) not deducted separately)"
        )
    elif score is not None and not chains and score != expected:
        warn(f"score: {score} != {expected} from raw Confirmed deductions")

    if args.report:
        rp = Path(args.report)
        if not rp.exists():
            err(f"report: not found: {rp}")
        else:
            text = rp.read_text(encoding="utf-8", errors="replace")
            for pattern in BANNED_CLAIMS:
                if re.search(pattern, text, re.I):
                    err(f"report: banned claim matching /{pattern}/")
            for need in ("Coverage matrix", "Residual risk"):
                if need.lower() not in text.lower():
                    warn(f"report: expected section missing: {need}")
            if verdict and verdict.lower() not in text.lower():
                warn(f"report: stated verdict '{verdict}' not found in the report text")

    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(f"INVALID: {len(errors)} error(s), {len(warnings)} warning(s)", file=sys.stderr)
        return 1

    if args.strict and warnings:
        print(f"INVALID (strict): {len(warnings)} warning(s)", file=sys.stderr)
        return 1

    print(
        f"VALID: {len(findings)} finding(s), {len(chains)} chain(s), "
        f"coverage {pct}%, score {score}, verdict {verdict}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
