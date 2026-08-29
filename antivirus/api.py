from flask import Flask, request, jsonify
from pathlib import Path
import sys

from antivirus.services.scanner import Scanner
from antivirus.services.report_formatter import ReportFormatter
from antivirus.model.scan_report import ScanReport
from antivirus.utils.logging import get_logger

logger = get_logger("antivirus.api")

app = Flask(__name__)
scanner = Scanner()


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"}), 200


@app.route("/api/v1/scan", methods=["POST"])
def scan_file_api():
    """Scan a file via REST API."""
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data.get("target"), str) or not data["target"]:
            return jsonify({"error": "Missing 'target' parameter"}), 400

        target = data["target"]
        target_path = Path(target)

        if not target_path.exists():
            return jsonify({"error": f"Target not found: {target}"}), 404

        if target_path.is_dir():
            report = scanner.scan_directory(str(target_path))
        else:
            result = scanner.scan_file(str(target_path))
            report = ScanReport()
            report.add_result(result)

        return jsonify(ReportFormatter.to_dict(report)), 200
    except Exception as exc:
        logger.error(f"Scan failed: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/v1/scan/batch", methods=["POST"])
def scan_batch_api():
    """Scan multiple files via REST API."""
    try:
        data = request.get_json(silent=True)
        if not data or "targets" not in data:
            return jsonify({"error": "Missing 'targets' parameter"}), 400

        targets = data["targets"]
        if not isinstance(targets, list):
            return jsonify({"error": "'targets' must be a list"}), 400
        if not all(isinstance(target, str) and target for target in targets):
            return jsonify({"error": "Each target must be a non-empty string"}), 400

        report = ScanReport()
        for target in targets:
            target_path = Path(target)
            if target_path.exists():
                if target_path.is_dir():
                    dir_report = scanner.scan_directory(str(target_path))
                    for result in dir_report.results:
                        report.add_result(result)
                else:
                    result = scanner.scan_file(str(target_path))
                    report.add_result(result)

        return jsonify(ReportFormatter.to_dict(report)), 200
    except Exception as exc:
        logger.error(f"Batch scan failed: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/v1/report/<format_type>", methods=["POST"])
def export_report_api(format_type):
    """Export scan report in specified format."""
    try:
        if format_type not in ["json", "csv"]:
            return jsonify({"error": "Invalid format. Use 'json' or 'csv'"}), 400

        data = request.get_json(silent=True)
        if not data or not isinstance(data.get("target"), str) or not data["target"]:
            return jsonify({"error": "Missing 'target' parameter"}), 400

        target = data["target"]
        target_path = Path(target)

        if not target_path.exists():
            return jsonify({"error": f"Target not found: {target}"}), 404

        if target_path.is_dir():
            report = scanner.scan_directory(str(target_path))
        else:
            result = scanner.scan_file(str(target_path))
            report = ScanReport()
            report.add_result(result)

        if format_type == "csv":
            return ReportFormatter.to_csv(report), 200, {"Content-Type": "text/csv"}
        else:
            return ReportFormatter.to_json(report), 200, {"Content-Type": "application/json"}
    except Exception as exc:
        logger.error(f"Export failed: {exc}")
        return jsonify({"error": str(exc)}), 500


def create_app():
    """Application factory for testing."""
    return app


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
