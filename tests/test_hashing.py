from antivirus.services.hash_service import HashService


def test_hash_service_calculates_sha256_for_text():
    service = HashService()
    digest = service.calculate_sha256_from_bytes(b"hello world")

    assert digest == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_hash_service_calculates_sha256_for_file(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"hello world")

    service = HashService()
    digest = service.calculate_sha256(str(sample))

    assert digest == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
