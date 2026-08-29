from typing import Dict, List, Optional
from datetime import datetime, timedelta
from antivirus.repository.scan_repository import ScanRepository
from antivirus.repository.threat_repository import ThreatRepository
from antivirus.model.scan_report import ScanReport


class StatisticsService:
    """Threat statistics and analytics service."""

    def __init__(self):
        self.scan_repo = ScanRepository()
        self.threat_repo = ThreatRepository()

    def get_scan_statistics(self, hours: int = 24) -> Dict:
        """Get scan statistics for the last N hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_scans = self.scan_repo.get_recent_scans(limit=1000)

        total_scans = 0
        threat_scans = 0
        clean_scans = 0
        threat_types: Dict[str, int] = {}

        for scan in recent_scans:
            scan_time = scan.get("scan_time")
            if scan_time:
                try:
                    scan_datetime = datetime.fromisoformat(scan_time)
                    if scan_datetime < cutoff_time:
                        continue
                except (ValueError, TypeError):
                    pass

            total_scans += 1
            status = scan.get("status", "unknown")

            if status == "detected":
                threat_scans += 1
            elif status == "clean":
                clean_scans += 1

        return {
            "total_scans": total_scans,
            "threat_scans": threat_scans,
            "clean_scans": clean_scans,
            "detection_rate": (
                round((threat_scans / total_scans * 100), 2)
                if total_scans > 0
                else 0
            ),
            "time_period_hours": hours,
        }

    def get_threat_distribution(self) -> Dict[str, int]:
        """Get distribution of threats by category."""
        recent_scans = self.scan_repo.get_recent_scans(limit=1000)
        distribution: Dict[str, int] = {}

        for scan in recent_scans:
            threats = scan.get("threats", "")
            if threats:
                # Threats are stored as comma-separated list or JSON
                if threats.startswith("["):
                    # Handle JSON format if applicable
                    try:
                        import json

                        threat_list = json.loads(threats)
                        for threat in threat_list:
                            category = threat.get("category", "Unknown")
                            distribution[category] = distribution.get(category, 0) + 1
                    except (json.JSONDecodeError, TypeError):
                        pass
                else:
                    # Handle simple comma-separated format
                    threat_names = threats.split(",")
                    for threat_name in threat_names:
                        category = threat_name.strip().split(".")[0]
                        distribution[category] = distribution.get(category, 0) + 1

        return distribution

    def get_top_threats(self, limit: int = 10) -> List[Dict]:
        """Get most frequently detected threats."""
        recent_scans = self.scan_repo.get_recent_scans(limit=1000)
        threat_counts: Dict[str, int] = {}

        for scan in recent_scans:
            threats = scan.get("threats", "")
            if threats:
                try:
                    import json

                    threat_list = json.loads(threats)
                    for threat in threat_list:
                        threat_name = threat.get("name", "Unknown")
                        threat_counts[threat_name] = threat_counts.get(threat_name, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    pass

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

        total_time = 0
        count = 0

        for scan in recent_scans:
            # Placeholder: actual timing would need to be stored in scan_repository
            count += 1

        return {
            "total_scans": len(recent_scans),
            "scans_processed": count,
            "avg_scan_time_ms": round(total_time / count) if count > 0 else 0,
        }
