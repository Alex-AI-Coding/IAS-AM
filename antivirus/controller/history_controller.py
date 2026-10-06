from antivirus.repository.scan_repository import ScanRepository


class HistoryController:
    def __init__(self, repository=None):
        self.repository = repository or ScanRepository()

    def recent_scans(self, limit=100):
        return self.repository.get_recent_scans(limit=limit)

    def clear_history(self):
        return self.repository.clear_history()

    def clear_selected(self, record_ids):
        return self.repository.delete_scans(record_ids)
