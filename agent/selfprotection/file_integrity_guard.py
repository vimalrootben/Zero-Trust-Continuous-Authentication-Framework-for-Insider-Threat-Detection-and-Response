import logging
import threading
import time
from typing import List, Optional

logger = logging.getLogger(__name__)

class FileIntegrityGuard:
    """Monitors critical binary and config files for unauthorized alterations."""

    def __init__(self, protected_paths: Optional[List[str]] = None, check_interval: int = 15):
        self.protected_paths = protected_paths or []
        self.check_interval = check_interval
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("FileIntegrityGuard started.")

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info("FileIntegrityGuard stopped.")

    def _monitor_loop(self):
        while self._running:
            time.sleep(self.check_interval)
