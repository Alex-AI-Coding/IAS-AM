"""Real encrypted round trips and failure injection; all content is harmless."""

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat

import pytest

from antivirus.model.scan_result import ScanResult
from antivirus.model.scan_status import ScanStatus
from antivirus.model.threat import Threat
from antivirus.services.quarantine_service import QuarantineError, QuarantineService
from antivirus.services.scanner import Scanner
from antivirus.services.vault_key import windows_protect

CONTENT = b"Harmless educational quarantine fixture. " * 2400


@pytest.fixture
def vault(tmp_path):
    return QuarantineService(tmp_path / "vault")


def detection(path, data=CONTENT, severity="High", category="Trojan"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return ScanResult(
        str(path),
        ScanStatus.DETECTED,
        [Threat("Educational.Fixture", category, severity, "Harmless fixture", "yara")],
        hashlib.sha256(data).hexdigest(),
    )


def payload(vault, item):
    return vault.payload_directory / (item.entry_id + ".qvault")


def database_change(vault, column, value, entry_id):
    assert column in {"threats", "original_path", "sha256", "state"}
    with sqlite3.connect(vault.repository.path) as connection:
        connection.execute(
            f"UPDATE quarantine SET {column}=? WHERE entry_id=?", (value, entry_id)
        )


def test_encrypted_isolation_restore_delete_and_persistence(vault, tmp_path):
    original = tmp_path / "flagged.txt"
    result = detection(original)
    held = vault.quarantine(result)
    assert held.state == "active" and not original.exists()
    assert CONTENT[:100] not in payload(vault, held).read_bytes()
    assert held.categories == "Trojan" and held.severity == "High"
    assert result.status == ScanStatus.DETECTED  # Original scan evidence is immutable.
    reopened = QuarantineService(vault.directory)
    restored = reopened.restore(held.entry_id)
    assert restored.state == "restored" and original.read_bytes() == CONTENT
    assert payload(vault, held).exists()  # Retained until explicit user deletion.
    deleted = reopened.delete(held.entry_id)
    assert deleted.state == "deleted" and not payload(vault, held).exists()
    assert original.read_bytes() == CONTENT
    assert QuarantineService(vault.directory).items()[0].state == "deleted"
    assert reopened.delete(held.entry_id).state == "deleted"


@pytest.mark.parametrize("data", [b"", b"x", b"a" * 65536, b"a" * 65537])
def test_round_trip_across_stream_boundaries(vault, tmp_path, data):
    original = tmp_path / "boundary.txt"
    item = vault.quarantine(detection(original, data))
    vault.restore(item.entry_id)
    assert original.read_bytes() == data


def test_equal_names_in_different_folders_have_independent_copies(vault, tmp_path):
    a = tmp_path / "a" / "same.txt"
    b = tmp_path / "b" / "same.txt"
    first = vault.quarantine(detection(a, b"first"))
    second = vault.quarantine(detection(b, b"second"))
    assert first.entry_id != second.entry_id
    vault.restore(first.entry_id)
    vault.restore(second.entry_id)
    assert a.read_bytes() == b"first" and b.read_bytes() == b"second"


def test_changed_file_after_scan_is_kept(vault, tmp_path):
    original = tmp_path / "changed.txt"
    result = detection(original)
    original.write_bytes(b"New content that must survive")
    with pytest.raises(QuarantineError, match="changed"):
        vault.quarantine(result)
    assert original.read_bytes() == b"New content that must survive"
    assert vault.items()[0].state == "incomplete"


def test_replaced_original_before_removal_is_kept(vault, tmp_path, monkeypatch):
    original = tmp_path / "changed.txt"
    result = detection(original)
    decrypt = vault._decrypt

    def replace_after_verification(*args, **kwargs):
        decrypt(*args, **kwargs)
        original.write_bytes(b"Replacement must survive")

    monkeypatch.setattr(vault, "_decrypt", replace_after_verification)
    item = vault.quarantine(result)
    assert item.state == "copy_retained"
    assert original.read_bytes() == b"Replacement must survive"
    monkeypatch.setattr(vault, "_decrypt", decrypt)
    with pytest.raises(QuarantineError, match="changed"):
        vault.retry_isolation(item.entry_id)
    assert original.read_bytes() == b"Replacement must survive"


def test_removal_failure_is_visible_and_can_be_retried(vault, tmp_path, monkeypatch):
    original = tmp_path / "locked.txt"
    result = detection(original)
    unlink = Path.unlink

    def cannot_unlink(path, *args, **kwargs):
        if path == original:
            raise PermissionError("File is locked")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(Path, "unlink", cannot_unlink)
        item = vault.quarantine(result)
    assert item.state == "copy_retained" and "locked" in item.error_message
    assert original.read_bytes() == CONTENT
    assert vault.retry_isolation(item.entry_id).state == "active"
    assert not original.exists()


def test_encryption_storage_failure_never_removes_original(
    vault, tmp_path, monkeypatch
):
    original = tmp_path / "disk-full.txt"
    result = detection(original)
    vault._key()
    exclusive = vault._exclusive_file

    def fail_output(path):
        if path.suffix == ".qvault":
            raise OSError("Disk full")
        return exclusive(path)

    monkeypatch.setattr(vault, "_exclusive_file", fail_output)
    with pytest.raises(OSError, match="Disk full"):
        vault.quarantine(result)
    assert original.read_bytes() == CONTENT
    assert vault.items()[0].state == "incomplete"


def test_catalogue_failure_before_removal_preserves_original(
    vault, tmp_path, monkeypatch
):
    original = tmp_path / "database-locked.txt"
    result = detection(original)
    update = vault.repository.update_state

    def fail_commit(entry_id, state, *args, **kwargs):
        if state == "copy_retained":
            raise sqlite3.OperationalError("Cannot commit")
        return update(entry_id, state, *args, **kwargs)

    monkeypatch.setattr(vault.repository, "update_state", fail_commit)
    with pytest.raises(sqlite3.OperationalError):
        vault.quarantine(result)
    assert original.read_bytes() == CONTENT
    assert payload(vault, vault.items()[0]).exists()


def test_catalogue_failure_after_removal_keeps_recoverable_copy(
    vault, tmp_path, monkeypatch
):
    original = tmp_path / "status-failure.txt"
    result = detection(original)
    update = vault.repository.update_state

    def fail_commit(entry_id, state, *args, **kwargs):
        if state == "active":
            raise sqlite3.OperationalError("Cannot commit")
        return update(entry_id, state, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(vault.repository, "update_state", fail_commit)
        with pytest.raises(QuarantineError, match="copy remains"):
            vault.quarantine(result)
    item = vault.items()[0]
    assert item.state == "copy_retained" and not original.exists()
    vault.restore(item.entry_id)
    assert original.read_bytes() == CONTENT


@pytest.mark.parametrize("offset", [0, 25, -1])
def test_damaged_payload_cannot_restore_and_leaves_no_plaintext(
    vault, tmp_path, offset
):
    original = tmp_path / "tamper.txt"
    item = vault.quarantine(detection(original))
    data = bytearray(payload(vault, item).read_bytes())
    data[offset] ^= 1
    payload(vault, item).write_bytes(data)
    with pytest.raises(QuarantineError):
        vault.restore(item.entry_id)
    assert not original.exists() and not list(tmp_path.glob(".premiere-restore-*"))
    assert payload(vault, item).exists() and vault.items()[0].state == "active"


def test_truncated_payload_is_not_restored(vault, tmp_path):
    original = tmp_path / "truncated.txt"
    item = vault.quarantine(detection(original))
    payload(vault, item).write_bytes(payload(vault, item).read_bytes()[:-20])
    with pytest.raises(QuarantineError, match="invalid size"):
        vault.restore(item.entry_id)
    assert not original.exists()


def test_corruption_between_verification_and_recovery_leaves_no_plaintext(
    vault, tmp_path, monkeypatch
):
    original = tmp_path / "second-pass.txt"
    item = vault.quarantine(detection(original))
    decrypt = vault._decrypt

    def corrupt_before_second_pass(entry, key, output=None):
        if output is not None:
            data = bytearray(payload(vault, entry).read_bytes())
            data[-1] ^= 1
            payload(vault, entry).write_bytes(data)
        return decrypt(entry, key, output)

    monkeypatch.setattr(vault, "_decrypt", corrupt_before_second_pass)
    with pytest.raises(QuarantineError, match="Integrity verification"):
        vault.restore(item.entry_id)
    assert not original.exists() and not list(tmp_path.glob(".premiere-restore-*"))
    assert payload(vault, item).exists()


@pytest.mark.parametrize(
    "column,value",
    [
        ("original_path", "untrusted-restoration.txt"),
        ("sha256", "a" * 64),
        (
            "threats",
            json.dumps(
                [
                    {
                        "name": "Fake",
                        "category": "Fake",
                        "severity": "Low",
                        "source": "unknown",
                        "description": "Changed evidence",
                    }
                ]
            ),
        ),
    ],
)
def test_evidence_is_bound_to_encrypted_content(vault, tmp_path, column, value):
    original = tmp_path / "evidence.txt"
    item = vault.quarantine(detection(original))
    database_change(vault, column, value, item.entry_id)
    with pytest.raises(QuarantineError, match="Integrity verification"):
        vault.restore(item.entry_id, tmp_path / "restored.txt")
    assert not (tmp_path / "restored.txt").exists() and not original.exists()


def test_missing_key_is_not_silently_replaced(vault, tmp_path):
    item = vault.quarantine(detection(tmp_path / "key-test.txt"))
    key = next(vault.directory.glob("vault-key.*"))
    key.unlink()
    with pytest.raises(QuarantineError, match="key is missing"):
        vault.restore(item.entry_id)
    assert not key.exists() and payload(vault, item).exists()


def test_restore_refuses_existing_file_and_supports_alternate_location(vault, tmp_path):
    original = tmp_path / "original.txt"
    item = vault.quarantine(detection(original))
    original.write_bytes(b"User's newer file")
    with pytest.raises(QuarantineError, match="already exists"):
        vault.restore(item.entry_id)
    alternate = tmp_path / "alternate.txt"
    vault.restore(item.entry_id, alternate)
    assert (
        original.read_bytes() == b"User's newer file"
        and alternate.read_bytes() == CONTENT
    )
    assert payload(vault, item).exists()


def test_restore_destination_created_during_publication_is_never_overwritten(
    vault, tmp_path, monkeypatch
):
    original = tmp_path / "race.txt"
    item = vault.quarantine(detection(original))
    link = os.link

    def competing_file(source, destination):
        Path(destination).write_bytes(b"Concurrent user file")
        return link(source, destination)

    monkeypatch.setattr(os, "link", competing_file)
    with pytest.raises(FileExistsError):
        vault.restore(item.entry_id)
    assert original.read_bytes() == b"Concurrent user file"
    assert not list(tmp_path.glob(".premiere-restore-*"))
    assert payload(vault, item).exists()


def test_restore_status_failure_preserves_both_copies(vault, tmp_path, monkeypatch):
    original = tmp_path / "restore-status.txt"
    item = vault.quarantine(detection(original))

    def fail_commit(*args, **kwargs):
        raise sqlite3.OperationalError("Cannot commit")

    monkeypatch.setattr(vault.repository, "update_state", fail_commit)
    with pytest.raises(QuarantineError, match="file was restored"):
        vault.restore(item.entry_id)
    assert original.read_bytes() == CONTENT and payload(vault, item).exists()
    assert not list(tmp_path.glob(".premiere-restore-*"))


def test_no_hardlink_support_fails_without_losing_backup(vault, tmp_path, monkeypatch):
    original = tmp_path / "unsupported.txt"
    item = vault.quarantine(detection(original))

    def unsupported(*args, **kwargs):
        raise OSError("Hard links not supported by this filesystem")

    monkeypatch.setattr(os, "link", unsupported)
    with pytest.raises(OSError, match="not supported"):
        vault.restore(item.entry_id)
    assert not original.exists() and payload(vault, item).exists()
    assert not list(tmp_path.glob(".premiere-restore-*"))


def test_delete_failed_unlink_retains_record_and_copy(vault, tmp_path, monkeypatch):
    item = vault.quarantine(detection(tmp_path / "delete.txt"))
    unlink = Path.unlink

    def cannot_unlink(path, *args, **kwargs):
        if path == payload(vault, item):
            raise PermissionError("File is locked")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", cannot_unlink)
    with pytest.raises(PermissionError):
        vault.delete(item.entry_id)
    assert payload(vault, item).exists() and vault.items()[0].state == "active"


def test_interrupted_preparation_never_removes_original_on_restart(vault, tmp_path):
    original = tmp_path / "interrupted.txt"
    result = detection(original)
    item = vault.quarantine(result)
    original.write_bytes(CONTENT)
    database_change(vault, "state", "pending", item.entry_id)
    reopened = QuarantineService(vault.directory)
    assert (
        reopened.items()[0].state == "incomplete" and original.read_bytes() == CONTENT
    )
    with pytest.raises(QuarantineError, match="verified held"):
        reopened.restore(item.entry_id)
    reopened.delete(item.entry_id)
    assert original.read_bytes() == CONTENT


def test_hardlinked_original_cannot_be_called_isolated(vault, tmp_path):
    original = tmp_path / "linked.txt"
    result = detection(original)
    os.link(original, tmp_path / "other-link.txt")
    with pytest.raises(QuarantineError, match="one filesystem link"):
        vault.quarantine(result)
    assert original.read_bytes() == CONTENT and not vault.items()


@pytest.mark.skipif(
    os.name == "nt", reason="Windows symlink creation requires account privileges"
)
def test_symlink_sources_destinations_and_vault_are_rejected(vault, tmp_path):
    original = tmp_path / "real.txt"
    result = detection(original)
    linked = tmp_path / "linked.txt"
    linked.symlink_to(original)
    result.file_path = str(linked)
    with pytest.raises(QuarantineError, match="Linked paths"):
        vault.quarantine(result)
    assert original.read_bytes() == CONTENT
    result.file_path = str(original)
    item = vault.quarantine(result)
    with pytest.raises(QuarantineError, match="Linked paths"):
        vault.restore(item.entry_id, linked)
    folder_link = tmp_path / "folder-link"
    folder_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(QuarantineError, match="Linked paths"):
        vault.restore(item.entry_id, folder_link / "new.txt")
    vault_link = tmp_path / "vault-link"
    vault_link.symlink_to(vault.directory, target_is_directory=True)
    with pytest.raises(QuarantineError, match="Linked paths"):
        QuarantineService(vault_link)
    assert payload(vault, item).exists()


@pytest.mark.parametrize(
    "identifier", ["../outside", "/tmp/outside", "a" * 31, "z" * 32]
)
def test_identifiers_cannot_escape_payload_directory(vault, identifier):
    for action in (vault.restore, vault.delete, vault.retry_isolation):
        with pytest.raises(QuarantineError, match="identifier"):
            action(identifier)


def test_clean_missing_hash_and_oversized_files_are_never_removed(vault, tmp_path):
    original = tmp_path / "not-eligible.txt"
    result = detection(original)
    clean = ScanResult(str(original), sha256=result.sha256)
    with pytest.raises(QuarantineError, match="detected files"):
        vault.quarantine(clean)
    result.sha256 = None
    with pytest.raises(QuarantineError, match="scan hash"):
        vault.quarantine(result)
    result.sha256 = hashlib.sha256(CONTENT).hexdigest()
    limited = QuarantineService(tmp_path / "tiny-vault", max_bytes=10)
    with pytest.raises(QuarantineError, match="limit"):
        limited.quarantine(result)
    assert original.read_bytes() == CONTENT


def test_malformed_catalogue_cannot_crash_evidence_rendering(vault, tmp_path):
    item = vault.quarantine(detection(tmp_path / "malformed.txt"))
    database_change(vault, "threats", '["not a threat object"]', item.entry_id)
    with pytest.raises(ValueError, match="invalid evidence"):
        vault.items()
    assert payload(vault, item).exists()


def test_severity_uses_highest_known_label_and_preserves_unknown(vault, tmp_path):
    result = detection(tmp_path / "severity.txt", severity="Low")
    result.threats.append(Threat("Educational.Second", "Spyware", "Critical"))
    item = vault.quarantine(result)
    assert item.severity == "Critical" and item.categories == "Trojan, Spyware"
    result = detection(
        tmp_path / "unknown.txt", severity="Unclassified", category="Unknown"
    )
    assert vault.quarantine(result).severity == "Unknown"


def test_vault_and_key_are_private_and_restored_file_not_executable(vault, tmp_path):
    original = tmp_path / "permissions.txt"
    result = detection(original)
    if os.name != "nt":
        original.chmod(0o700)
    item = vault.quarantine(result)
    if os.name == "nt":
        key = (vault.directory / "vault-key.dpapi").read_bytes()
        assert len(windows_protect(key, decrypt=True)) == 32 and len(key) > 32
    else:
        assert stat.S_IMODE(vault.directory.stat().st_mode) == 0o700
        for path in (
            vault.directory / "vault-key.bin",
            Path(vault.repository.path),
            payload(vault, item),
        ):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    vault.restore(item.entry_id)
    if os.name != "nt":
        assert stat.S_IMODE(original.stat().st_mode) == 0o600


def test_normal_scans_never_read_vault_payload_or_key(vault, tmp_path):
    outside = tmp_path / "normal.txt"
    outside.write_text("harmless", encoding="utf-8")
    (vault.payload_directory / "opaque.qvault").write_bytes(b"opaque")
    seen = []

    class CleanEngine:
        def analyze_file(self, path):
            seen.append(path)
            return ScanResult(path)

    scanner = Scanner(CleanEngine(), excluded_roots=[vault.directory])
    assert (
        scanner.scan_file(str(vault.directory / "vault-key.bin")).status
        == ScanStatus.SKIPPED
    )
    report = scanner.scan_directory(str(tmp_path))
    assert seen == [str(outside)]
    assert any(result.status == ScanStatus.SKIPPED for result in report.results)
    assert (
        scanner.scan_directory(str(vault.directory)).results[0].status
        == ScanStatus.SKIPPED
    )


@pytest.mark.skipif(
    os.name != "nt", reason="Requires the real Windows DPAPI implementation"
)
def test_windows_key_round_trip_and_corruption():
    key = os.urandom(32)
    protected = windows_protect(key)
    assert protected != key and windows_protect(protected, decrypt=True) == key
    with pytest.raises(OSError):
        windows_protect(b"invalid DPAPI blob", decrypt=True)
