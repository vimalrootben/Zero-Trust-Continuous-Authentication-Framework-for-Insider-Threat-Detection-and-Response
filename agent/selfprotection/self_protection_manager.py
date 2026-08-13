import logging
from typing import Any
from .service_guard import ServiceGuard
from .file_integrity_guard import FileIntegrityGuard
from .tamper_logger import TamperLogger
from manager.audit.audit_logger import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()

class SelfProtectionManager:
    """Orchestrates self‑protection guards.

    Each guard runs in a lightweight thread (or async task) and monitors
    a specific aspect of the host. The manager starts/stops them based on
    the configuration toggles defined in ``AgentConfig``.
    """

    def __init__(self, config):
        self.config = config
        self.guards = []
        if getattr(config, "enable_service_guard", True):
            self.guards.append(ServiceGuard())
        if getattr(config, "enable_file_integrity_guard", True):
            self.guards.append(FileIntegrityGuard())
        if getattr(config, "enable_tamper_logger", True):
            self.guards.append(TamperLogger())

    def start(self) -> None:
        logger.info("Starting self‑protection manager with %d guards", len(self.guards))
        audit.log_self_protection_event(event="self_protection_start", details={"guard_count": len(self.guards)})
        for guard in self.guards:
            try:
                guard.start()
                logger.debug("Started guard: %s", guard.__class__.__name__)
            except Exception as exc:
                logger.exception("Failed to start guard %s: %s", guard.__class__.__name__, exc)

    def stop(self) -> None:
        logger.info("Stopping self‑protection manager")
        audit.log_self_protection_event(event="self_protection_stop", details={})
        for guard in self.guards:
            try:
                guard.stop()
                logger.debug("Stopped guard: %s", guard.__class__.__name__)
            except Exception as exc:
                logger.exception("Failed to stop guard %s: %s", guard.__class__.__name__, exc)
