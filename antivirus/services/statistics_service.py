from typing import Dict, List
from datetime import datetime, timedelta, timezone
from antivirus.repository.scan_repository import ScanRepository
from antivirus.repository.threat_repository import ThreatRepository
from antivirus.model.scan_report import ScanReport


class StatisticsService:
    """Threat statistics and analytics service."""

    def __init__(self, scan_repo=None, threat_repo=None):
        self.scan_repo = scan_repo or ScanRepository()
        self.threat_repo = threat_repo or ThreatRepository()

    def get_scan_statistics(self, hours: int | None = 24) -> Dict:
        """Get scan statistics for the last N hours."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours or 0)
        recent_scans = self.scan_repo.get_recent_scans(limit=1000)

        filtered_scans = []
        threat_scans = 0
        clean_scans = 0

        for scan in recent_scans:
            scan_time = scan.get("started_at")
            if scan_time and hours is not None:
                try:
                    scan_datetime = datetime.fromisoformat(scan_time)
                    if scan_datetime.tzinfo is None:
                        scan_datetime = scan_datetime.replace(tzinfo=timezone.utc)
                    if scan_datetime < cutoff_time:
                        continue
                except (ValueError, TypeError):
                    pass

            filtered_scans.append(scan)
            status = scan.get("status", "unknown")

            if status == "detected":
                threat_scans += 1
            elif status == "clean":
                clean_scans += 1

        total_scans = len(filtered_scans)

        return {
            "total_scans": total_scans,
            "threat_scans": threat_scans,
            "clean_scans": clean_scans,
            "detection_rate": (
                round((threat_scans / total_scans * 100), 2) if total_scans > 0 else 0
            ),
            "time_period_hours": hours,
            "files_scanned": sum(
                int(scan.get("file_count", 0)) for scan in filtered_scans
            ),
            "threats_found": sum(
                int(scan.get("threats_found", 0)) for scan in filtered_scans
            ),
            "clean_files": sum(
                int(scan.get("clean_files", 0)) for scan in filtered_scans
            ),
        }

    def get_threat_distribution(self) -> Dict[str, int]:
        """Get distribution of threats by category."""
        recent_scans = self.scan_repo.get_recent_scans(limit=1000)
        distribution: Dict[str, int] = {}

        for scan in recent_scans:
            threats = scan.get("threats", [])
            if threats:
                if isinstance(threats, list):
                    threat_list = threats
                else:
                    try:
                        import json

                        threat_list = json.loads(threats)
                    except (json.JSONDecodeError, TypeError):
                        threat_list = [
                            {"category": name.strip().split(".")[0]}
                            for name in str(threats).split(",")
                            if name.strip()
                        ]
                for threat in threat_list:
                    category = threat.get("category", "Unknown")
                    distribution[category] = distribution.get(category, 0) + 1

        return distribution

    def get_top_threats(self, limit: int = 10) -> List[Dict]:
        """Get most frequently detected threats."""
        recent_scans = self.scan_repo.get_recent_scans(limit=1000)
        threat_counts: Dict[str, int] = {}

        for scan in recent_scans:
            threats = scan.get("threats", [])
            if threats:
                if isinstance(threats, list):
                    threat_list = threats
                else:
                    import json

                    try:
                        threat_list = json.loads(threats)
                    except (json.JSONDecodeError, TypeError):
                        threat_list = []
                for threat in threat_list:
                    threat_name = threat.get("name", "Unknown")
                    threat_counts[threat_name] = threat_counts.get(threat_name, 0) + 1

        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        return [
            {"name": name, "count": count} for name, count in sorted_threats[:limit]
        ]

    def get_false_positive_ratio(self) -> float:
        """Estimate false positive ratio (requires manual tagging in production)."""
        # This is a placeholder for production use
        # In a real system, users would mark false positives
        return 0.0

    def get_detection_summary(self, report: ScanReport) -> Dict:
        """Summarize detection results from a scan report."""
        threat_categories: Dict[str, int] = {}
        threat_severities: Dict[str, int] = {}
        detection_methods: Dict[str, int] = {}

        for result in report.results:
            for threat in result.threats:
                category = threat.category or "Unknown"
                severity = threat.severity or "Unknown"

                threat_categories[category] = threat_categories.get(category, 0) + 1
                threat_severities[severity] = threat_severities.get(severity, 0) + 1

            for method in result.detection_methods:
                detection_methods[method] = detection_methods.get(method, 0) + 1

        return {
            "threat_categories": threat_categories,
            "threat_severities": threat_severities,
            "detection_methods": detection_methods,
            "total_threats": sum(threat_categories.values()),
            "most_common_category": (
                max(threat_categories, key=threat_categories.get)
                if threat_categories
                else None
            ),
        }

    def get_performance_metrics(self) -> Dict:
        """Get performance metrics for recent scans."""
        recent_scans = self.scan_repo.get_recent_scans(limit=100)

        if not recent_scans:
            return {
                "avg_scan_time_ms": 0,
                "total_scans": 0,
                "scans_processed": 0,
            }

        durations = [float(scan.get("duration", 0) or 0) for scan in recent_scans]
        count = len(durations)

        return {
            "total_scans": len(recent_scans),
            "scans_processed": count,
            "avg_scan_time_ms": round(sum(durations) / count * 1000) if count else 0,
        }
