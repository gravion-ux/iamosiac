"""Command-line entry point for IAMosaic.

The CLI reports problems as one-line messages instead of Python tracebacks, so
it can be used directly in CI pipelines.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_policy, policy_edges, policy_version

EXIT_OK = 0
EXIT_INVALID_POLICY = 1
EXIT_USAGE = 2


class PolicyFileError(Exception):
    """The policy file is missing or cannot be read."""


class PolicyFormatError(Exception):
    """The policy file was read but does not contain a usable IAM policy."""


def _load_policy(path: Path) -> dict:
    """Read and parse an exported policy file.

    ``utf-8-sig`` keeps files exported on Windows readable: those often carry a
    UTF-8 byte-order mark that plain ``utf-8`` decoding rejects.
    """
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise PolicyFileError(f"cannot read policy file {path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyFormatError(
            f"invalid JSON in {path} at line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise PolicyFormatError(f"policy file {path} must contain a JSON object")
    return data


def _build_report(data: dict) -> dict:
    return {
        "tool": "IAMosaic",
        "mode": "offline-policy-analysis",
        "schema_version": 1,
        "policy_version": policy_version(data),
        "findings": analyze_policy(data),
        "edges": policy_edges(data),
        "notice": (
            "Findings are review hints that require human validation. "
            "No cloud API was contacted and no credential was read."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iamosaic",
        description="Offline cloud-IAM policy review from exported policy JSON.",
    )
    parser.add_argument("policy", type=Path, help="Exported IAM policy JSON file")
    parser.add_argument("--output", type=Path, help="Optional path for the JSON report")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with status 1 when at least one finding is reported",
    )
    args = parser.parse_args(argv)

    try:
        data = _load_policy(args.policy)
    except PolicyFileError as exc:
        print(f"iamosaic: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except PolicyFormatError as exc:
        print(f"iamosaic: {exc}", file=sys.stderr)
        return EXIT_INVALID_POLICY

    report = _build_report(data)
    text = json.dumps(report, indent=2)
    if args.output:
        try:
            args.output.write_text(text + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"iamosaic: cannot write report to {args.output}: {exc.strerror or exc}",
                  file=sys.stderr)
            return EXIT_INVALID_POLICY
    print(text)

    if args.fail_on_findings and report["findings"]:
        return EXIT_INVALID_POLICY
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
