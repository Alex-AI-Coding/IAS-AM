"""Authenticated local API with an explicit filesystem capability boundary."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from threading import BoundedSemaphore
from time import monotonic
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from antivirus.config.settings import BASE_DIR
from antivirus.model.scan_report import ScanReport
from antivirus.services.report_formatter import ReportFormatter
from antivirus.services.scanner import Scanner
from antivirus.utils.logging import get_logger

logger = get_logger(__name__)
# Kept as an injection point for integrations; each factory owns a scan gate.
scanner = Scanner()


def create_app(config=None, scanner_instance=None):
    application = Flask(__name__)
    default_root = BASE_DIR / "api_targets"
    default_root.mkdir(parents=True, exist_ok=True)
    application.config.update(
        API_TOKEN=os.getenv("ANTIVIRUS_API_TOKEN", ""),
        SCAN_ROOT=os.getenv("ANTIVIRUS_API_SCAN_ROOT", str(default_root)),
        MAX_CONTENT_LENGTH=16 * 1024,
        MAX_BATCH_TARGETS=32,
        SCANNER=scanner_instance or scanner,
    )
    if config:
        application.config.update(config)
    scan_gate = BoundedSemaphore(1)
    application.extensions["scan_gate"] = scan_gate

    @application.before_request
    def authorize():
        if not request.path.startswith("/api/"):
            return None
        token = application.config["API_TOKEN"]
        if not isinstance(token, str) or len(token) < 32:
            return (
                jsonify(
                    error="Configure ANTIVIRUS_API_TOKEN with at least 32 characters before using the API."
                ),
                503,
            )
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(
            supplied.encode("utf-8"), ("Bearer " + token).encode("utf-8")
        ):
            return (
                jsonify(error="A valid Bearer token is required."),
                401,
                {"WWW-Authenticate": "Bearer"},
            )
        return None

    @application.after_request
    def secure_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        return response

    @application.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.name), exc.code

    @application.get("/health")
    def health():
        return jsonify(status="healthy"), 200

    def validate_target(target):
        if not isinstance(target, str) or not target.strip() or "\x00" in target:
            return None, (
                jsonify(error="Each target must be a non-empty path string."),
                400,
            )
        try:
            root = (
                Path(application.config["SCAN_ROOT"]).expanduser().resolve(strict=True)
            )
            path = Path(target).expanduser()
            if not path.is_absolute():
                path = root / path
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                return None, (
                    jsonify(error="Target is outside the configured scan root."),
                    403,
                )
            if not resolved.exists():
                return None, (
                    jsonify(error="Target was not found in the scan root."),
                    404,
                )
            # Reject links even when they happen to point back inside the allowed root.
            if any(
                part.is_symlink()
                or (hasattr(part, "is_junction") and part.is_junction())
                for part in (path, *path.parents)
                if part != root and part.is_relative_to(root)
            ):
                return None, (jsonify(error="Linked targets are not allowed."), 403)
            if not resolved.is_file() and not resolved.is_dir():
                return None, (
                    jsonify(error="Target must be a regular file or directory."),
                    400,
                )
            return resolved, None
        except (OSError, ValueError, RuntimeError):
            return None, (
                jsonify(error="The target or scan root cannot be accessed."),
                400,
            )

    def scan_request(batch=False, format_type="json"):
        if format_type not in ("json", "csv"):
            return jsonify(error="Invalid format. Use 'json' or 'csv'."), 400
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="A JSON object is required."), 400
        key = "targets" if batch else "target"
        if key not in data:
            return jsonify(error=f"Missing '{key}' parameter"), 400
        targets = data[key] if batch else [data[key]]
        if (
            not isinstance(targets, list)
            or not 1 <= len(targets) <= application.config["MAX_BATCH_TARGETS"]
        ):
            return (
                jsonify(error="targets must be a non-empty list of at most 32 paths."),
                400,
            )
        if not all(
            isinstance(target, str) and target.strip() and "\x00" not in target
            for target in targets
        ):
            return jsonify(error="Each target must be a non-empty path string."), 400
        validated = []
        for target in targets:
            path, error = validate_target(target)
            if error:
                return error
            if path not in validated:
                validated.append(path)
        if not scan_gate.acquire(blocking=False):
            return (
                jsonify(
                    error="A scan is already running. Try again after it finishes."
                ),
                429,
                {"Retry-After": "5"},
            )
        try:
            report = ScanReport(started_at=datetime.now(timezone.utc).isoformat())
            started = monotonic()
            service = application.config["SCANNER"]
            seen_files = set()
            for path in validated:
                # A target can change after request validation.
                checked_path, error = validate_target(str(path))
                if error:
                    return error
                if checked_path.is_dir():
                    part = service.scan_directory(str(checked_path))
                    report.warnings.extend(part.warnings)
                    results = part.results
                else:
                    results = [service.scan_file(str(checked_path))]
                for result in results:
                    if result.file_path not in seen_files:
                        seen_files.add(result.file_path)
                        report.add_result(result)
            report.duration = monotonic() - started
            report.completed_at = datetime.now(timezone.utc).isoformat()
            if format_type == "csv":
                return (
                    ReportFormatter.to_csv(report),
                    200,
                    {
                        "Content-Type": "text/csv; charset=utf-8",
                        "Content-Disposition": 'attachment; filename="scan-report.csv"',
                    },
                )
            return jsonify(ReportFormatter.to_dict(report)), 200
        except Exception:
            logger.exception("API scan failed")
            return jsonify(error="Scan failed. Check the local application log."), 500
        finally:
            scan_gate.release()

    @application.post("/api/v1/scan")
    def scan_target():
        return scan_request()

    @application.post("/api/v1/scan/batch")
    def scan_batch():
        return scan_request(batch=True)

    @application.post("/api/v1/report/<format_type>")
    def export_report(format_type):
        return scan_request(format_type=format_type)

    return application


app = create_app()

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
