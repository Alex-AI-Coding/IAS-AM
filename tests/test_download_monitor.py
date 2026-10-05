from antivirus.services.download_watcher import DownloadWatcherService


def test_new_download_is_scanned_once_only_after_it_is_stable(tmp_path):
    calls = []
    existing = tmp_path / "existing.txt"
    existing.write_text("old")
    watcher = DownloadWatcherService(tmp_path, calls.append, interval=3600)
    watcher.start()
    try:
        sample = tmp_path / "new.txt"
        sample.write_bytes(b"first")
        watcher.poll_once()
        assert calls == []
        sample.write_bytes(b"finished content")
        watcher.poll_once()
        assert calls == []
        watcher.poll_once()
        watcher.poll_once()
        assert calls == [str(sample)]
        assert sample.read_bytes() == b"finished content"
        assert existing.read_text() == "old"
        sample.write_bytes(b"a new revision")
        watcher.poll_once()
        watcher.poll_once()
        assert calls == [str(sample), str(sample)]
    finally:
        watcher.stop(timeout=1)
    assert not watcher.has_pending_work()


def test_browser_temporary_files_are_ignored_then_scanned_after_rename(tmp_path):
    calls = []
    watcher = DownloadWatcherService(tmp_path, calls.append, interval=3600)
    watcher.start()
    try:
        pending = tmp_path / "file.crdownload"
        pending.write_text("finished")
        watcher.poll_once()
        watcher.poll_once()
        assert not calls
        complete = tmp_path / "file.txt"
        pending.rename(complete)
        watcher.poll_once()
        watcher.poll_once()
        assert calls == [str(complete)]
    finally:
        watcher.stop(timeout=1)
