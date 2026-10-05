import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

class DownloadHandler(FileSystemEventHandler):
    def __init__(self, scanner_callback, target_extensions=None):
        super().__init__()
        self.scanner_callback = scanner_callback
        self.target_extensions = target_extensions
        self.processing_cache = set()

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_file_event(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_file_event(event.src_path)

    def on_moved(self, event):
        """Catch files when browsers rename them from .crdownload/.part to their final extension."""
        if event.is_directory:
            return
        self._handle_file_event(event.dest_path)

    def _handle_file_event(self, filepath):
        if filepath.endswith(('.crdownload', '.part', '.tmp')):
            return

        ext = os.path.splitext(filepath)[1].lower()
        if self.target_extensions and ext not in self.target_extensions:
            return
        if filepath in self.processing_cache:
            return

        self.processing_cache.add(filepath)
        self._safely_trigger_scan(filepath)

    def _safely_trigger_scan(self, filepath, retries=3, delay=1.0):
        for attempt in range(retries):
            if not os.path.exists(filepath):
                self.processing_cache.discard(filepath)
                return
            try:
                with open(filepath, 'ab'):
                    break
            except IOError:
                time.sleep(delay)
        else:
            logger.warning(f"[Watchdog] File lock timeout for: {filepath}")
            self.processing_cache.discard(filepath)
            return

        logger.info(f"[Watchdog] Intercepted new download: {filepath}. Triggering scanner...")
        try:
            self.scanner_callback(filepath)
        except Exception as e:
            logger.error(f"[Watchdog] Error scanning intercepted download {filepath}: {e}")
        finally:
            self.processing_cache.discard(filepath)


class DownloadWatcherService:
    def __init__(self, watch_path=None, scanner_callback=None):
        self.watch_path = watch_path or os.path.join(os.path.expanduser("~"), "Downloads")
        self.event_handler = DownloadHandler(scanner_callback=scanner_callback)
        self.observer = Observer()
        self.is_running = False

    def start(self):
        if not os.path.exists(self.watch_path):
            os.makedirs(self.watch_path, exist_ok=True)
            
        self.observer.schedule(self.event_handler, path=self.watch_path, recursive=False)
        self.observer.start()
        self.is_running = True
        logger.info(f"[*] Download Watcher active. Monitoring directory: {self.watch_path}")

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            logger.info("[*] Download Watcher stopped.")