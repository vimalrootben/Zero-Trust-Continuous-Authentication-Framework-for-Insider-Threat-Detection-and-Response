# Connectivity Monitor (Phase 7 – A-network)
"""
Provides a centralised online/offline state for the agent. Other components
(OfflineQueue, HeartbeatSender, WebSocketClient) should call ``report_success``
when a network interaction succeeds and ``report_failure`` when it fails. When
the failure count reaches ``failure_threshold`` the monitor flips to OFFLINE and
invokes any registered ``on_offline`` callbacks. When connectivity is restored
the monitor flips back to ONLINE and invokes ``on_online`` callbacks.
"""

import asyncio
import logging
from typing import Callable, List, Optional

from agent.communication.transport import SecureTransport, TransportError, AuthenticationError

logger = logging.getLogger(__name__)


class ConnectivityMonitor:
    """Centralised connectivity detector.

    Parameters
    ----------
    transport: SecureTransport
        The transport used by the agent to talk to the manager. It must expose
        an ``is_connected`` coroutine that returns ``True`` when the remote
        endpoint is reachable.
    failure_threshold: int, default 3
        Number of consecutive failures required before the monitor declares the
        agent OFFLINE.
    check_interval: float, default 5.0
        Seconds between passive connectivity checks performed in the background
        task.
    """

    def __init__(
        self,
        transport: SecureTransport,
        failure_threshold: int = 3,
        check_interval: float = 5.0,
    ) -> None:
        self.transport = transport
        self.failure_threshold = failure_threshold
        self.check_interval = check_interval
        self._online: bool = True
        self._failure_count: int = 0
        self._on_online: List[Callable[[], None]] = []
        self._on_offline: List[Callable[[], None]] = []
        self._monitor_task: Optional[asyncio.Task] = None
        # Start background monitor if an event loop is already running.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._monitor_task = None
        else:
            self._monitor_task = loop.create_task(self._monitor_loop())

    # ---------------------------------------------------------------------
    # Public API used by other components
    # ---------------------------------------------------------------------
    def is_online(self) -> bool:
        """Return the current connectivity state."""
        return self._online

    def register_on_reconnect(self, callback: Callable[[], None]) -> None:
        """Register a callback that is called **once** when the monitor goes
        from OFFLINE to ONLINE.
        """
        self._on_online.append(callback)

    def register_on_offline(self, callback: Callable[[], None]) -> None:
        """Register a callback that is called **once** when the monitor goes
        from ONLINE to OFFLINE.
        """
        self._on_offline.append(callback)

    def report_success(self) -> None:
        """Notify the monitor that a network operation succeeded.

        Resets the failure counter and, if the monitor was OFFLINE, flips back
        to ONLINE and fires the ``on_online`` callbacks.
        """
        if not self._online:
            logger.info("Connectivity restored – switching to ONLINE")
            self._online = True
            self._failure_count = 0
            for cb in self._on_online:
                try:
                    cb()
                except Exception as exc:  # pragma: no cover – defensive
                    logger.exception("on_online callback raised: %s", exc)
        else:
            self._failure_count = 0

    def report_failure(self) -> None:
        """Notify the monitor that a network operation failed.

        Increments the failure counter and, once the threshold is reached,
        flips to OFFLINE and fires the ``on_offline`` callbacks.
        """
        self._failure_count += 1
        if self._online and self._failure_count >= self.failure_threshold:
            logger.warning(
                "Connectivity lost – %d consecutive failures, switching to OFFLINE",
                self._failure_count,
            )
            self._online = False
            for cb in self._on_offline:
                try:
                    cb()
                except Exception as exc:  # pragma: no cover – defensive
                    logger.exception("on_offline callback raised: %s", exc)

    # ---------------------------------------------------------------------
    # Background monitoring – optional but useful for passive health checks
    # ---------------------------------------------------------------------
    async def _monitor_loop(self) -> None:
        """Periodically query ``transport.is_connected`` and update state.

        The loop runs until cancelled. Any exception from the transport is
        treated as a failure.
        """
        while True:
            try:
                # ``SecureTransport`` currently lacks ``is_connected``; we call
                # a stub method if it exists. Sub‑classes may implement it.
                is_up = await getattr(self.transport, "is_connected", lambda: asyncio.sleep(0))()
            except (TransportError, AuthenticationError) as exc:
                logger.debug("Connectivity probe failed: %s", exc)
                self.report_failure()
            except Exception as exc:  # pragma: no cover – unexpected errors
                logger.exception("Unexpected error in connectivity monitor: %s", exc)
                self.report_failure()
            else:
                if is_up:
                    self.report_success()
                else:
                    self.report_failure()
            await asyncio.sleep(self.check_interval)

    def stop(self) -> None:
        """Cancel the background monitor task if it exists."""
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                asyncio.get_event_loop().run_until_complete(self._monitor_task)
            except (asyncio.CancelledError, RuntimeError):
                pass
