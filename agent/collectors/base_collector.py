"""
BaseCollector — Abstract base class every A6-A12 collector must implement.

Design contract:
  - The collector is completely unaware of connectivity state.
  - It calls event_sink(TelemetryEventDTO) for every event it produces.
  - The caller (agent orchestrator) wires event_sink to either:
      * The OfflineQueue   (when the manager is unreachable), or
      * The telemetry batching buffer (when connected).
  - start() / stop() must be idempotent — calling stop() before start()
    must not raise. Calling start() twice must not spawn double subscriptions.
"""
from abc import ABC, abstractmethod
from typing import Callable

from agent.storage.models import TelemetryEventDTO


class BaseCollector(ABC):
    """Abstract base for all agent telemetry collectors."""

    def __init__(self, event_sink: Callable[[TelemetryEventDTO], None]) -> None:
        """
        Args:
            event_sink: Callable that receives each TelemetryEventDTO produced
                        by this collector. Never called with None.
        """
        self._event_sink = event_sink
        self._running = False

    @abstractmethod
    def start(self) -> None:
        """Begin monitoring. Must be idempotent (safe to call multiple times)."""

    @abstractmethod
    def stop(self) -> None:
        """Clean shutdown — release WMI subscriptions / stop threads. Idempotent."""

    @abstractmethod
    def collector_type(self) -> str:
        """
        Return the collector type string stored in telemetry_events.collector_type.
        Must exactly match the string the manager-side Rule Engine uses to route events.
        """

    def _emit(self, event: TelemetryEventDTO) -> None:
        """Safely call the event_sink, catching any exceptions to protect the collector loop."""
        try:
            self._event_sink(event)
        except Exception as e:
            import logging
            logging.getLogger(self.__class__.__name__).error(
                f"event_sink raised unexpectedly: {e}", exc_info=True
            )
