"""
RegistryCollector (A8) — Monitors security-relevant Windows Registry keys for changes.

Design:
  - Event-driven via RegNotifyChangeKeyValue (win32api / ctypes) on Windows.
  - Polling fallback (snapshotting winreg values) every N seconds when native notify is unavailable.
  - Exposes WinRegistryWatcher seam for test injection.
  - Emits TelemetryEventDTO with collector_type='registry'.
"""
import logging
import sys
import threading
from typing import Callable, Dict, List, Optional, Tuple

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "registry"

DEFAULT_MONITORED_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\System\CurrentControlSet\Services",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
]


class WinRegistryWatcher:
    """
    Wraps native Windows Registry notification or snapshot polling.
    """

    def __init__(self, monitored_keys: Optional[List[str]] = None) -> None:
        self.monitored_keys = monitored_keys or DEFAULT_MONITORED_KEYS

    def subscribe(
        self,
        on_change: Callable[[dict], None],
        stop_event: threading.Event,
        poll_interval: int = 15,
    ) -> None:
        """
        Polls or listens to registry changes until stop_event is set.
        """
        known_values: Dict[str, Dict[str, str]] = {}

        def snapshot_key(key_path: str) -> Dict[str, str]:
            res: Dict[str, str] = {}
            if not sys.platform.startswith("win"):
                return res
            try:
                import winreg  # type: ignore[import]
                root_str, subkey = self._split_key(key_path)
                root_hkey = getattr(winreg, root_str, None)
                if not root_hkey:
                    return res
                with winreg.OpenKey(root_hkey, subkey, 0, winreg.KEY_READ) as k:
                    idx = 0
                    while True:
                        try:
                            v_name, v_val, _ = winreg.EnumValue(k, idx)
                            res[v_name] = str(v_val)
                            idx += 1
                        except OSError:
                            break
            except Exception as e:
                logger.debug(f"Registry snapshot error on {key_path}: {e}")
            return res

        # Initial snapshot
        for kp in self.monitored_keys:
            known_values[kp] = snapshot_key(kp)

        while not stop_event.is_set():
            if stop_event.wait(timeout=poll_interval):
                break

            for kp in self.monitored_keys:
                current_vals = snapshot_key(kp)
                old_vals = known_values.get(kp, {})

                # Added or modified
                for val_name, val_str in current_vals.items():
                    if val_name not in old_vals:
                        on_change({
                            "key_path": kp,
                            "value_name": val_name,
                            "old_value": None,
                            "new_value": val_str,
                            "change_type": "created",
                        })
                    elif old_vals[val_name] != val_str:
                        on_change({
                            "key_path": kp,
                            "value_name": val_name,
                            "old_value": old_vals[val_name],
                            "new_value": val_str,
                            "change_type": "modified",
                        })

                # Deleted
                for val_name in old_vals:
                    if val_name not in current_vals:
                        on_change({
                            "key_path": kp,
                            "value_name": val_name,
                            "old_value": old_vals[val_name],
                            "new_value": None,
                            "change_type": "deleted",
                        })

                known_values[kp] = current_vals

    @staticmethod
    def _split_key(full_path: str) -> Tuple[str, str]:
        parts = full_path.split("\\", 1)
        root = parts[0].upper()
        hkey_map = {
            "HKLM": "HKEY_LOCAL_MACHINE",
            "HKCU": "HKEY_CURRENT_USER",
            "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
            "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
        }
        return hkey_map.get(root, "HKEY_LOCAL_MACHINE"), parts[1] if len(parts) > 1 else ""


class RegistryCollector(BaseCollector):
    """
    A8 — Registry Collector.
    Monitors changes in high-value Windows Registry locations (Run keys, Services, Winlogon).
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        monitored_keys: Optional[List[str]] = None,
        watcher: Optional[WinRegistryWatcher] = None,
        poll_interval: int = 15,
    ) -> None:
        super().__init__(event_sink)
        self._monitored_keys = monitored_keys or DEFAULT_MONITORED_KEYS
        self._watcher = watcher or WinRegistryWatcher(self._monitored_keys)
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start registry monitoring thread. Idempotent."""
        if self._running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="RegistryCollector-Thread",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("RegistryCollector started.")

    def stop(self) -> None:
        """Stop registry monitoring thread. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._running = False
        logger.info("RegistryCollector stopped.")

    def _run(self) -> None:
        try:
            self._watcher.subscribe(
                on_change=self._on_registry_change,
                stop_event=self._stop_event,
                poll_interval=self._poll_interval,
            )
        except Exception as exc:
            logger.error(f"RegistryCollector thread error: {exc}", exc_info=True)
        finally:
            self._running = False

    def _on_registry_change(self, raw: dict) -> None:
        key_path = raw.get("key_path", "")
        new_val = str(raw.get("new_value") or "").lower()

        severity = EventSeverity.MEDIUM.value
        if "run" in key_path.lower():
            severity = EventSeverity.HIGH.value
        if "cmd" in new_val or "powershell" in new_val or "temp" in new_val:
            severity = EventSeverity.CRITICAL.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type="registry_change",
            severity=severity,
            data={
                "key_path": key_path,
                "value_name": raw.get("value_name", ""),
                "old_value": raw.get("old_value"),
                "new_value": raw.get("new_value"),
                "change_type": raw.get("change_type", "modified"),
            },
        )
        self._emit(event)
