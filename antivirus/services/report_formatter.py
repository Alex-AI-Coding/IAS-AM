import json
import csv
from io import StringIO
from typing import Any, Dict

from antivirus.model.scan_report import ScanReport


class ReportFormatter:
    """Export scan results in various formats."""

    @staticmethod
    def to_json(report: ScanReport) -> str:
        """Export scan report as JSON."""
        data = {
            "summary": {
                "total_files": report.total_files,
                "clean_files": report.clean_files,
                "threat_files": report.threat_files,
                "error_files": report.error_files,
            },
            "results": [
                {
                    "file_path": result.file_path,
                    "status": result.status.value,
                    "sha256": result.sha256,
                    "detection_methods": result.detection_methods,
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
                }
                for result in report.results
            ],
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def to_csv(report: ScanReport) -> str:
        """Export scan report as CSV."""
        output = StringIO()
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
            ]
        )

        for result in report.results:
            if result.threats:
                for threat in result.threats:
                    writer.writerow(
                        [
                            result.file_path,
                            result.status.value,
                            result.sha256,
                            threat.name,
                            threat.category,
                            threat.severity,
                            threat.source,
                            ";".join(result.detection_methods),
                            result.error_message or "",
                        ]
                    )
            else:
                writer.writerow(
                    [
                        result.file_path,
                        result.status.value,
                        result.sha256,
                        "",
                        "",
                        "",
                        "",
                        ";".join(result.detection_methods),
                        result.error_message or "",
                    ]
                )

        return output.getvalue()

    @staticmethod
    def to_dict(report: ScanReport) -> Dict[str, Any]:
        """Export scan report as dictionary."""
        return {
            "summary": {
                "total_files": report.total_files,
                "clean_files": report.clean_files,
                "threat_files": report.threat_files,
                "error_files": report.error_files,
            },
            "results": [
                {
                    "file_path": result.file_path,
                    "status": result.status.value,
                    "sha256": result.sha256,
                    "detection_methods": result.detection_methods,
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
                }
                for result in report.results
            ],
        }
