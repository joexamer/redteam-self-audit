#!/usr/bin/env python3
"""Redact secrets and PII from evidence before it enters a report.

Usage:
  python3 redact-evidence.py evidence.txt
  python3 redact-evidence.py evidence/ -o redacted/
  python3 redact-evidence.py - < evidence.txt

Raw inputs are never modified. Output files are written with mode 0600.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        "[REDACTED:private-key]",
    ),
    (
        "authorization",
        re.compile(r"(?im)^(Authorization|Proxy-Authorization)\s*:\s*.*$"),
        r"\1: [REDACTED:authorization]",
    ),
    (
        "cookie",
        re.compile(r"(?im)^(Set-Cookie|Cookie)\s*:\s*.*$"),
        r"\1: [REDACTED:cookie]",
    ),
    (
        "bearer",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{10,}"),
        "Bearer [REDACTED:token]",
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}"),
        "[REDACTED:jwt]",
    ),
    (
        "aws-key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "[REDACTED:aws-key]",
    ),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "[REDACTED:github-token]",
    ),
    (
        "slack-token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "[REDACTED:slack-token]",
    ),
    (
        "stripe-key",
        re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
        "[REDACTED:stripe-key]",
    ),
    (
        "json-password",
        re.compile(r'(?i)("(?:password|passwd|secret|token|api[_-]?key)"\s*:\s*")[^"]*(")'),
        r"\1[REDACTED:secret]\2",
    ),
    (
        "key-value-secret",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|token|passwd|password)\s*([:=])\s*['\"]?([A-Za-z0-9_\-./+=]{12,})['\"]?"
        ),
        r"\1\2[REDACTED:secret]",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED:email]",
    ),
    (
        "card",
        re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
        "[REDACTED:card]",
    ),
]

SUMMARY: dict[str, int] = {}


def redact(text: str) -> str:
    out = text
    for name, pattern, replacement in PATTERNS:
        out, count = pattern.subn(replacement, out)
        if count:
            SUMMARY[name] = SUMMARY.get(name, 0) + count
    return out


def iter_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(f for f in p.rglob("*") if f.is_file()))
        elif p.is_file():
            files.append(p)
        else:
            raise SystemExit(f"not found: {raw}")
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact secrets and PII from evidence.")
    parser.add_argument("inputs", nargs="+", help="files, directories, or - for stdin")
    parser.add_argument("-o", "--output", help="output file or directory")
    parser.add_argument("--stdout", action="store_true", help="print to stdout instead of files")
    args = parser.parse_args()

    if args.inputs == ["-"]:
        data = sys.stdin.read()
        redacted = redact(data)
        if args.output and not args.stdout:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(redacted, encoding="utf-8")
            os.chmod(out, 0o600)
            print(f"wrote {out} (0600)", file=sys.stderr)
        else:
            sys.stdout.write(redacted)
        print(f"redactions: {SUMMARY}", file=sys.stderr)
        return 0

    files = iter_files(args.inputs)
    out_dir = Path(args.output) if args.output else None
    if out_dir and len(files) > 1:
        out_dir.mkdir(parents=True, exist_ok=True)

    for src in files:
        data = src.read_text(encoding="utf-8", errors="replace")
        redacted = redact(data)
        if args.stdout:
            print(f"===== {src} =====")
            sys.stdout.write(redacted)
            if not redacted.endswith("\n"):
                sys.stdout.write("\n")
            continue
        if out_dir and len(files) > 1:
            dest = out_dir / f"{src.name}.redacted"
        elif out_dir:
            dest = out_dir
        else:
            dest = src.with_suffix(src.suffix + ".redacted")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(redacted, encoding="utf-8")
        os.chmod(dest, 0o600)
        print(f"wrote {dest} (0600)", file=sys.stderr)

    print(f"redactions: {SUMMARY}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
