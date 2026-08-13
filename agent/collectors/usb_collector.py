"""
USBCollector (A10) — Real-time USB device insertion and removal telemetry.

Design:
  - Event-driven via WMI __InstanceCreationEvent / __InstanceDeletionEvent on Win32_DiskDrive or Win32_USBControllerDevice.
  - Exposes WMIUSBSubscriber seam for test injection.
  - Emits TelemetryEventDTO with collector_type='usb'.
"""
import logging
import threading
from typing import Callable, Optional

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "usb"


class WMIUSBSubscriber:
    """
    Wraps WMI USB device insertion/removal event subscriptions.
    """

    def subscribe(
        self,
        on_event: Callable[[dict], None],
        stop_event: threading.Event,
    ) -> None:
        try:
            import wmi  # type: ignore[import]
            c = wmi.WMI()
            creation_watcher = c.watch_for(
                notification_type="Creation",
                wmi_class="Win32_DiskDrive",
                delay_secs=2,
            )
            deletion_watcher = c.watch_for(
                notification_type="Deletion",
                wmi_class="Win32_DiskDrive",
                delay_secs=2,
            )
            logger.info("USBCollector attached to WMI Win32_DiskDrive watchers.")
            while not stop_event.is_set():
                try:
                    ev = creation_watcher(timeout_ms=500)
                    if ev and "USB" in getattr(ev, "InterfaceType", "").upper():
                        on_event(self._to_dict(ev, "connected"))
                except Exception:
                    pass
                try:
                    ev = deletion_watcher(timeout_ms=500)
                    if ev and "USB" in getattr(ev, "InterfaceType", "").upper():
                        on_event(self._to_dict(ev, "disconnected"))
                except Exception:
                    pass
        except Exception as exc:
            logger.debug(f"WMI USB watcher unavailable ({exc}). Using mock/idle loop.")
            stop_event.wait()

    @staticmethod
    def _to_dict(ev, event_type: str) -> dict:
        dev_id = getattr(ev, "DeviceID", "")
        desc = getattr(ev, "Caption", "") or getattr(ev, "Description", "")
        pnp_id = getattr(ev, "PNPDeviceID", "")

        vid, pid = "", ""
        if "VID_" in pnp_id:
            try:
                vid = pnp_id.split("VID_")[1].split("&")[0]
            except Exception:
                pass
        if "PID_" in pnp_id:
            try:
                pid = pnp_id.split("PID_")[1].split("&")[0]
            except Exception:
                pass

        return {
            "device_id": dev_id,
            "device_description": desc,
            "serial_number": getattr(ev, "SerialNumber", ""),
            "vendor_id": vid,
            "product_id": pid,
            "drive_letter": None,
            "event_type": event_type,
            "file_copy_activity": None,
        }


class USBCollector(BaseCollector):
    """
    A10 — USB Collector.
    Monitors insertion and removal of USB mass storage devices.
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        subscriber: Optional[WMIUSBSubscriber] = None,
    ) -> None:
        super().__init__(event_sink)
        self._subscriber = subscriber or WMIUSBSubscriber()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start USB monitoring thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="USBCollector-Thread",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("USBCollector started.")

    def stop(self) -> None:
        """Stop USB monitoring thread. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("USBCollector stopped.")

    def _run(self) -> None:
        try:
            self._subscriber.subscribe(
                on_event=self._on_usb_event,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            logger.error(f"USBCollector thread error: {exc}", exc_info=True)
        finally:
            self._running = False

    def _on_usb_event(self, raw: dict) -> None:
        event_type = raw.get("event_type", "connected")
        severity = EventSeverity.MEDIUM.value if event_type == "connected" else EventSeverity.LOW.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type=f"usb_{event_type}",
            severity=severity,
            data=raw,
        )
        self._emit(event)
