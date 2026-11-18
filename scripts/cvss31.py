#!/usr/bin/env python3
"""Compute a CVSS 3.1 base score from a vector string.

Usage:
  python3 cvss31.py 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
  python3 cvss31.py --json 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'

Base metrics only. Temporal and environmental metrics are reported as ignored;
the skill's scoring uses the base score.
"""
from __future__ import annotations

import argparse
import json
import math
import sys

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def parse(vector: str) -> dict[str, str]:
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("vector must start with CVSS:3.1/")
    parts = vector.strip().split("/")[1:]
    metrics: dict[str, str] = {}
    ignored: list[str] = []
    for part in parts:
        if ":" not in part:
            raise ValueError(f"malformed metric: {part!r}")
        key, value = part.split(":", 1)
        key = key.upper()
        value = value.upper()
        if key in REQUIRED:
            metrics[key] = value
        elif key in {"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}:
            ignored.append(key)
        else:
            raise ValueError(f"unknown metric: {key}")
    missing = [key for key in REQUIRED if key not in metrics]
    if missing:
        raise ValueError(f"missing base metrics: {', '.join(missing)}")
    if metrics["S"] not in {"U", "C"}:
        raise ValueError("S must be U or C")
    for key, table in (("AV", AV), ("AC", AC), ("UI", UI), ("C", CIA), ("I", CIA), ("A", CIA)):
        if metrics[key] not in table:
            raise ValueError(f"invalid {key}: {metrics[key]}")
    if metrics["PR"] not in PR_UNCHANGED:
        raise ValueError(f"invalid PR: {metrics['PR']}")
    return {"metrics": metrics, "ignored": ignored}


def roundup(value: float) -> float:
    return math.ceil(round(value, 6) * 10) / 10


def base_score(metrics: dict[str, str]) -> float:
    scope_changed = metrics["S"] == "C"
    iss = 1 - (
        (1 - CIA[metrics["C"]]) * (1 - CIA[metrics["I"]]) * (1 - CIA[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = (PR_CHANGED if scope_changed else PR_UNCHANGED)[metrics["PR"]]
    exploitability = 8.22 * AV[metrics["AV"]] * AC[metrics["AC"]] * pr * UI[metrics["UI"]]

    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute a CVSS 3.1 base score.")
    parser.add_argument("vector")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    try:
        parsed = parse(args.vector)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    metrics = parsed["metrics"]
    score = base_score(metrics)
    result = {
        "vector": f"CVSS:3.1/{'/'.join(f'{k}:{metrics[k]}' for k in REQUIRED)}",
        "score": score,
        "severity": severity(score),
        "ignored_metrics": parsed["ignored"],
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"score: {score}")
        print(f"severity: {result['severity']}")
        if parsed["ignored"]:
            print(f"ignored (not used in base score): {', '.join(parsed['ignored'])}")
        print(result["vector"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
