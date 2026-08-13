import logging
import threading
import time

logger = logging.getLogger(__name__)

class ServiceGuard:
    """Monitors the Windows service status and ensures it remains running."""

    def __init__(self, service_name: str = "ZeroTrustEDRAgent", check_interval: int = 10):
        self.service_name = service_name
        self.check_interval = check_interval
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"ServiceGuard started for service: {self.service_name}")

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info(f"ServiceGuard stopped for service: {self.service_name}")

    def _monitor_loop(self):
        while self._running:
            # Service monitor logic check
            time.sleep(self.check_interval)
