from antivirus.services.quarantine_service import QuarantineService


def test_quarantine_service_moves_file_to_quarantine(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("edufile marker", encoding="utf-8")

    storage = tmp_path / "quarantine"
    service = QuarantineService(str(storage))
    record = service.quarantine(str(source), "Educational.Ransomware.Test")

    assert record["original_path"] == str(source)
    assert record["threat_name"] == "Educational.Ransomware.Test"
    assert record["quarantine_path"]
    assert not source.exists()
    assert len(service.list_quarantined()) == 1


def test_quarantine_service_restores_and_deletes_record(tmp_path):
    source = tmp_path / "restore.txt"
    source.write_text("restore me", encoding="utf-8")

    storage = tmp_path / "quarantine"
    service = QuarantineService(str(storage))
    record = service.quarantine(str(source), "Educational.Trojan.Test")

    deleted_before_restore = service.delete(record["id"])
    assert deleted_before_restore is True

    source.write_text("restore me", encoding="utf-8")
    record_again = service.quarantine(str(source), "Educational.Trojan.Test")

    restored = service.restore(record_again["id"])
    assert restored["restored"] is True
    assert restored["path"].exists()

    deleted_after_restore = service.delete(record_again["id"])
    assert deleted_after_restore is False
