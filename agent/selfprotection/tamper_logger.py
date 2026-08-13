import logging

logger = logging.getLogger(__name__)

class TamperLogger:
    """Logs tampering attempts and security violations locally and via audit logger."""

    def __init__(self):
        self._running = False

    def start(self):
        self._running = True
        logger.info("TamperLogger started.")

    def stop(self):
        self._running = False
        logger.info("TamperLogger stopped.")

    def log_tamper_attempt(self, event: str, details: dict):
        logger.warning(f"Tamper attempt detected! Event: {event}, Details: {details}")
