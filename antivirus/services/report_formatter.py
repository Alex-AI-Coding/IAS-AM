"""Consistent report exports with spreadsheet-formula escaping."""

import csv
import json
from io import StringIO

from antivirus.model.scan_report import ScanReport


def csv_cell(value):
    text = "" if value is None else str(value)
    # Spreadsheet programs can execute formulas even in quoted CSV fields.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(
        ("\t", "\r", "\n")
    ):
        return "'" + text
    return text


class ReportFormatter:
    @staticmethod
    def to_dict(report: ScanReport) -> dict:
        return {
            "schema_version": 2,
            "summary": {
                "total_files": report.total_files,
                "clean_files": report.clean_files,
                "threat_files": report.threat_files,
                "error_files": report.error_files,
                "skipped_files": report.skipped_files,
                "incomplete_files": report.incomplete_files,
                "outcome": report.outcome,
                "cancelled": report.cancelled,
                "duration_seconds": report.duration,
                "started_at": report.started_at,
                "completed_at": report.completed_at,
                "warnings": report.warnings,
            },
            "results": [
                {
                    "file_path": result.file_path,
                    "status": result.status.value,
                    "sha256": result.sha256,
                    "scan_duration_seconds": result.scan_duration,
                    "started_at": result.started_at,
                    "completed_at": result.completed_at,
                    "detection_methods": result.detection_methods,
                    "engine_results": result.engine_results,
                    "threats": [
                        {
                            "name": threat.name,
                            "category": threat.category,
                            "severity": threat.severity,
                            "description": threat.description,
                            "source": threat.source,
                        }
                        for threat in result.threats
                    ],
                    "error_message": result.error_message,
                    "warnings": result.warnings,
                }
                for result in report.results
            ],
        }

    @staticmethod
    def to_json(report: ScanReport) -> str:
        return json.dumps(ReportFormatter.to_dict(report), indent=2)

    @staticmethod
    def to_csv(report: ScanReport) -> str:
        output = StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(
            [
                "File Path",
                "Status",
                "SHA256",
                "Threat Name",
                "Category",
                "Severity",
                "Source",
                "Detection Methods",
                "Error Message",
                "Engine Results",
                "Scan Outcome",
            ]
        )
        for result in report.results:
            for threat in result.threats or [None]:
                writer.writerow(
                    [
                        csv_cell(value)
                        for value in [
                            result.file_path,
                            result.status.value,
                            result.sha256,
                            threat.name if threat else "",
                            threat.category if threat else "",
                            threat.severity if threat else "",
                            threat.source if threat else "",
                            ";".join(result.detection_methods),
                            result.error_message,
                            ";".join(
                                f"{key}:{value}"
                                for key, value in result.engine_results.items()
                            ),
                            report.outcome,
                        ]
                    ]
                )
        # Keep incomplete/empty scan context even when there are no result rows.
        if report.warnings or report.cancelled or not report.results:
            writer.writerow(
                [
                    csv_cell(value)
                    for value in [
                        "",
                        "summary",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "; ".join(report.warnings),
                        "",
                        report.outcome,
                    ]
                ]
            )
        return output.getvalue()
