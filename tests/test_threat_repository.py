from antivirus.repository.threat_repository import ThreatRepository


def test_threat_repository_tracks_hash_lookup(tmp_path):
    db_path = tmp_path / "threats.db"
    repository = ThreatRepository(str(db_path))

    repository.add_threat(
        name="Educational.Ransomware.Test",
        category="Ransomware",
        sha256="abc123",
        severity="High",
        description="Educational ransomware detector",
    )

    found = repository.find_by_hash("abc123")

    assert found is not None
    assert found["name"] == "Educational.Ransomware.Test"
    assert found["category"] == "Ransomware"
    assert found["severity"] == "High"


def test_threat_repository_returns_none_for_unknown_hash(tmp_path):
    db_path = tmp_path / "threats.db"
    repository = ThreatRepository(str(db_path))

    assert repository.find_by_hash("unknownhash") is None
