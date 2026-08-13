"""
FileCollector (A11) — Monitors sensitive directories for file creation, modification, deletion, and renaming.

Design:
  - Default watched paths: %APPDATA%, %TEMP%, Desktop, Documents.
  - Event-driven filesystem watching via ReadDirectoryChangesW (win32file / watchdog) or FileWatcher seam.
  - Asynchronous file hashing for small modified files (<10MB).
  - Emits TelemetryEventDTO with collector_type='file'.
"""
import hashlib
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "file"
MAX_HASH_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit


def _get_default_watched_paths() -> List[str]:
    paths: List[str] = []
    appdata = os.getenv("APPDATA")
    temp = os.getenv("TEMP")
    userprofile = os.getenv("USERPROFILE")

    if appdata:
        paths.append(appdata)
    if temp:
        paths.append(temp)
    if userprofile:
        paths.append(os.path.join(userprofile, "Desktop"))
        paths.append(os.path.join(userprofile, "Documents"))
    return [p for p in paths if os.path.exists(p)]


def _sha256_file(path: str) -> Optional[str]:
    try:
        if not os.path.isfile(path):
            return None
        if os.path.getsize(path) > MAX_HASH_FILE_SIZE:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class FileWatcher:
    """
    Wraps filesystem event monitoring.
    Uses watchdog if available, falling back to an internal seam for testing.
    """

    def __init__(self, watched_paths: List[str]) -> None:
        self.watched_paths = watched_paths

    def subscribe(
        self,
        on_file_event: Callable[[dict], None],
        stop_event: threading.Event,
    ) -> None:
        try:
            from watchdog.events import FileSystemEventHandler  # type: ignore[import]
            from watchdog.observers import Observer  # type: ignore[import]

            class WatchdogHandler(FileSystemEventHandler):
                def on_created(self, event):
                    if not event.is_directory:
                        on_file_event({"file_path": event.src_path, "change_type": "created"})

                def on_modified(self, event):
                    if not event.is_directory:
                        on_file_event({"file_path": event.src_path, "change_type": "modified"})

                def on_deleted(self, event):
                    if not event.is_directory:
                        on_file_event({"file_path": event.src_path, "change_type": "deleted"})

                def on_moved(self, event):
                    if not event.is_directory:
                        on_file_event({
                            "file_path": event.dest_path,
                            "old_path": event.src_path,
                            "change_type": "renamed",
                        })

            observer = Observer()
            handler = WatchdogHandler()
            for p in self.watched_paths:
                if os.path.exists(p):
                    observer.schedule(handler, p, recursive=False)
            observer.start()
            logger.info("FileCollector attached watchdog observers.")
            while not stop_event.is_set():
                stop_event.wait(timeout=1.0)
            observer.stop()
            observer.join()
        except Exception as exc:
            logger.debug(f"Watchdog unavailable ({exc}). Using mock/idle loop.")
            stop_event.wait()


class FileCollector(BaseCollector):
    """
    A11 — File Collector.
    Monitors sensitive directories for file creation, modification, deletion, and renaming.
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        watched_paths: Optional[List[str]] = None,
        watcher: Optional[FileWatcher] = None,
        max_hash_workers: int = 2,
    ) -> None:
        super().__init__(event_sink)
        self._watched_paths = watched_paths or _get_default_watched_paths()
        self._watcher = watcher or FileWatcher(self._watched_paths)
        self._executor = ThreadPoolExecutor(max_workers=max_hash_workers, thread_name_prefix="file-hash")
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start file monitoring thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="FileCollector-Thread",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("FileCollector started.")

    def stop(self) -> None:
        """Stop file monitoring thread. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._executor.shutdown(wait=False)
        self._running = False
        logger.info("FileCollector stopped.")

    def _run(self) -> None:
        try:
            self._watcher.subscribe(
                on_file_event=self._on_file_event,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            logger.error(f"FileCollector thread error: {exc}", exc_info=True)
        finally:
            self._running = False

    def _on_file_event(self, raw: dict) -> None:
        try:
            self._executor.submit(self._process_and_emit, raw)
        except Exception as exc:
            logger.error(f"Failed to submit file enrichment task: {exc}")

    def _process_and_emit(self, raw: dict) -> None:
        file_path = raw.get("file_path", "")
        change_type = raw.get("change_type", "modified")

        file_size = 0
        file_hash = None
        if change_type in ("created", "modified") and os.path.exists(file_path):
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                pass
            file_hash = _sha256_file(file_path)

        severity = EventSeverity.LOW.value
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr"):
            severity = EventSeverity.MEDIUM.value
        if "temp" in file_path.lower() and ext in (".exe", ".dll", ".ps1"):
            severity = EventSeverity.HIGH.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type=f"file_{change_type}",
            severity=severity,
            data={
                "file_path": file_path,
                "change_type": change_type,
                "file_size": file_size,
                "file_hash": file_hash,
                "process_that_touched_it": None,
            },
        )
        self._emit(event)
