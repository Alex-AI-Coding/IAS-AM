from __future__ import annotations

import argparse
import json
import sys

from pathlib import Path

from antivirus.services.scanner import Scanner
from antivirus.services.report_formatter import ReportFormatter


def main() -> int:
    parser = argparse.ArgumentParser(description="Educational antivirus backend CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("target", help="File or directory to scan")
    scan_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )

    args = parser.parse_args()

    scanner = Scanner()

    if args.command == "scan":
        target = args.target
        try:
            if Path(target).is_dir():
                report = scanner.scan_directory(target)
            else:
                from antivirus.model.scan_report import ScanReport
                result = scanner.scan_file(target)
                report = ScanReport()
                report.add_result(result)

            if args.format == "csv":
                print(ReportFormatter.to_csv(report), end="")
            else:
                print(ReportFormatter.to_json(report))

            return 0
        except Exception as exc:  # pragma: no cover - CLI boundary
            print(f"Scan failed: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
