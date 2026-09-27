"""Command-line entry point: `qag scan <path>`."""

from __future__ import annotations

import argparse
import sys

from . import __version__, report, scanner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qag",
        description="Scan an AI agent codebase for agentic vulnerability patterns and quantum-readiness gaps.",
    )
    parser.add_argument("--version", action="version", version=f"quantumagentguard {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan a directory")
    scan_parser.add_argument("path", help="Path to the project root to scan")
    scan_parser.add_argument("--json", action="store_true", help="Emit JSON instead of a text report")
    scan_parser.add_argument(
        "--fail-on",
        choices=["HIGH", "MEDIUM", "INFO", "never"],
        default="never",
        help="Exit non-zero if any finding at or above this severity is present (for CI gating).",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        result = scanner.scan_directory(args.path)
        output = report.to_json(result) if args.json else report.to_text(result)
        print(output)

        if args.fail_on != "never":
            threshold = {"HIGH": ("HIGH",), "MEDIUM": ("HIGH", "MEDIUM"), "INFO": ("HIGH", "MEDIUM", "INFO")}[args.fail_on]
            if any(f.severity in threshold for f in result.findings):
                return 1
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
