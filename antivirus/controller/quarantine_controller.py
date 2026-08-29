from antivirus.services.quarantine_service import QuarantineService


class QuarantineController:
    def __init__(self, service=None):
        self.service = service or QuarantineService()

    def list_quarantined(self):
        return self.service.list_quarantined()

    def restore(self, record_id):
        return self.service.restore(record_id)

    def delete(self, record_id):
        return self.service.delete(record_id)

    def quarantine(self, source_path, threat_name, sha256=None):
        return self.service.quarantine(source_path, threat_name, sha256)
