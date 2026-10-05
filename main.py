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

    verify_parser = subparsers.add_parser(
        "verify-report", help="Verify a signed report against a trusted public key"
    )
    verify_parser.add_argument("report", help="Signed JSON bundle")
    verify_parser.add_argument(
        "--public-key", required=True, help="Independently trusted report-public.pem"
    )

    args = parser.parse_args()

    if args.command == "verify-report":
        from antivirus.services.report_signer import ReportSigner

        try:
            bundle = json.loads(Path(args.report).read_text(encoding="utf-8"))
            valid = ReportSigner.verify(bundle, Path(args.public_key).read_bytes())
        except (OSError, ValueError):
            valid = False
        print(
            "Signature verified against trusted key."
            if valid
            else "Signature verification FAILED."
        )
        return 0 if valid else 2

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

            return 1 if report.threat_files else (2 if report.outcome != "clean" else 0)
        except Exception as exc:  # pragma: no cover - CLI boundary
            print(f"Scan failed: {exc}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
