"""Opt-in polling watcher: stable files, read-only scans, no automatic quarantine."""

from __future__ import annotations

from pathlib import Path
from threading import Event, Thread


class DownloadWatcherService:
    TEMP_SUFFIXES = (".crdownload", ".part", ".tmp", ".download")

    def __init__(
        self, watch_path=None, scanner_callback=None, interval=2, error_callback=None
    ):
        self.watch_path = Path(watch_path or Path.home() / "Downloads")
        self.scanner_callback = scanner_callback
        self.error_callback = error_callback
        self.interval = interval
        self._stop = Event()
        self._thread = None
        self._observed = {}
        self._scanned = {}

    @property
    def is_running(self):
        return (
            self._thread is not None
            and self._thread.is_alive()
            and not self._stop.is_set()
        )

    def _snapshot(self):
        snapshot = {}
        for path in self.watch_path.iterdir():
            if len(snapshot) >= 5000:
                raise RuntimeError(
                    "Download monitoring supports up to 5,000 directory entries. Choose a smaller folder."
                )
            if path.suffix.lower() in self.TEMP_SUFFIXES or path.is_symlink():
                continue
            try:
                stat = path.stat()
                if path.is_file():
                    snapshot[path] = (stat.st_size, stat.st_mtime_ns, stat.st_ino)
            except OSError:
                continue
        return snapshot

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("The previous download monitor is still stopping.")
        if not self.watch_path.is_dir() or self.watch_path.is_symlink():
            raise ValueError(
                "A real Downloads folder is required. Choose a folder scan instead."
            )
        if not callable(self.scanner_callback):
            raise ValueError("A scan callback is required.")
        self._observed = self._snapshot()
        self._scanned = dict(self._observed)  # Existing files need an explicit scan.
        self._stop.clear()
        self._thread = Thread(target=self._run, name="download-monitor", daemon=True)
        self._thread.start()

    def poll_once(self):
        current = self._snapshot()
        for path, identity in current.items():
            if self._stop.is_set():
                break
            if (
                self._observed.get(path) == identity
                and self._scanned.get(path) != identity
            ):
                self.scanner_callback(str(path))
                self._scanned[path] = identity
        self._observed = current
        self._scanned = {
            p: identity for p, identity in self._scanned.items() if p in current
        }

    def _run(self):
        while not self._stop.wait(self.interval):
            try:
                self.poll_once()
            except Exception as exc:
                self._stop.set()
                if self.error_callback:
                    self.error_callback(str(exc))

    def stop(self, timeout=0):
        self._stop.set()
        if self._thread and timeout:
            self._thread.join(timeout=timeout)

    def has_pending_work(self):
        return bool(self._thread and self._thread.is_alive())
