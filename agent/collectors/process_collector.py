"""
ProcessCollector (A6) — Real-time process start/stop telemetry via WMI event subscriptions.

Design:
  - Event-driven via WMI Win32_ProcessStartTrace / Win32_ProcessStopTrace.
    We do NOT poll (polling misses short-lived processes — a common evasion technique).
  - SHA-256 hashing is done asynchronously in a ThreadPoolExecutor to avoid
    blocking the WMI callback thread.
  - A hash cache keyed by (executable_path, mtime) prevents re-hashing unchanged
    executables on every launch.
  - A local allowlist cache tracks "previously seen and cleared" executables. 
    Events are STILL emitted for allowlisted processes — the allowlist only affects
    local severity weighting downstream; the manager always sees ground truth.
  - Authenticode signature check is done via PowerShell signtool subprocess (best-effort).
  - On non-Windows CI environments, the WMI layer is abstracted behind
    WMIProcessSubscriber so tests can inject a mock subscriber.

Usage:
    collector = ProcessCollector(event_sink=queue.enqueue)
    collector.start()
    # ... agent runs ...
    collector.stop()
"""
import hashlib
import logging
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Tuple

from agent.collectors.base_collector import BaseCollector
from agent.storage.models import EventSeverity, TelemetryEventDTO

logger = logging.getLogger(__name__)

COLLECTOR_TYPE = "process"

# --------------------------------------------------------------------------- #
# Hash cache                                                                    #
# --------------------------------------------------------------------------- #
# Key: (absolute_path, mtime_float)  →  sha256_hex
_HashCacheKey = Tuple[str, float]
_hash_cache: Dict[_HashCacheKey, str] = {}
_hash_cache_lock = threading.Lock()


def _sha256_file(path: str) -> Optional[str]:
    """Return SHA-256 hex digest of *path*, or None on any I/O error."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None

    cache_key: _HashCacheKey = (os.path.normcase(path), mtime)
    with _hash_cache_lock:
        if cache_key in _hash_cache:
            return _hash_cache[cache_key]

    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
    except (OSError, PermissionError):
        return None

    with _hash_cache_lock:
        _hash_cache[cache_key] = digest
    return digest


def _is_signed(path: str) -> Optional[bool]:
    """
    Return True if the executable has a valid Authenticode signature.
    Uses PowerShell Get-AuthenticodeSignature — best-effort, returns None on error.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        result = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                f"(Get-AuthenticodeSignature '{path}').Status -eq 'Valid'",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout.strip().lower()
        if output == "true":
            return True
        if output == "false":
            return False
        return None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# WMI subscriber abstraction (seam for test injection)                          #
# --------------------------------------------------------------------------- #

class WMIProcessSubscriber:
    """
    Wraps WMI process event subscriptions.
    Can be replaced with a mock in tests that don't run on Windows.
    """

    def subscribe(
        self,
        on_start: Callable[[dict], None],
        on_stop: Callable[[dict], None],
        stop_event: threading.Event,
    ) -> None:
        """
        Block until stop_event is set, calling on_start/on_stop for each
        Win32_ProcessStartTrace / Win32_ProcessStopTrace event.
        """
        try:
            import wmi  # type: ignore[import]
        except ImportError:
            logger.error(
                "WMI Python package not available. Install `wmi` on Windows. "
                "ProcessCollector will not collect events."
            )
            stop_event.wait()
            return

        c = wmi.WMI()
        start_watcher = c.Win32_ProcessStartTrace.watch_for()
        stop_watcher = c.Win32_ProcessStopTrace.watch_for()

        while not stop_event.is_set():
            try:
                ev = start_watcher(timeout_ms=500)
                if ev:
                    on_start(self._to_dict(ev))
            except Exception:
                pass
            try:
                ev = stop_watcher(timeout_ms=500)
                if ev:
                    on_stop(self._to_dict(ev))
            except Exception:
                pass

    @staticmethod
    def _to_dict(ev) -> dict:
        return {
            "ProcessName": getattr(ev, "ProcessName", ""),
            "ProcessId": getattr(ev, "ProcessId", 0),
            "ParentProcessId": getattr(ev, "ParentProcessId", 0),
        }


# --------------------------------------------------------------------------- #
# ProcessCollector                                                               #
# --------------------------------------------------------------------------- #

class ProcessCollector(BaseCollector):
    """
    A6 — Real-time process start/stop telemetry.
    Subscribes to WMI Win32_ProcessStartTrace / Win32_ProcessStopTrace.
    """

    COLLECTOR_TYPE = COLLECTOR_TYPE

    def __init__(
        self,
        event_sink: Callable[[TelemetryEventDTO], None],
        subscriber: Optional[WMIProcessSubscriber] = None,
        max_hash_workers: int = 4,
        allowlist: Optional[set] = None,
    ) -> None:
        super().__init__(event_sink)
        self._subscriber = subscriber or WMIProcessSubscriber()
        self._executor = ThreadPoolExecutor(max_workers=max_hash_workers, thread_name_prefix="proc-hash")
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Allowlist: set of normalised executable paths known to be benign
        self._allowlist: set = allowlist or set()

    def collector_type(self) -> str:
        return self.COLLECTOR_TYPE

    def start(self) -> None:
        """Start WMI subscription thread. Idempotent."""
        if self._running:
            logger.debug("ProcessCollector already running — ignoring duplicate start().")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="ProcessCollector-WMI",
            daemon=True,
        )
        self._running = True
        self._thread.start()
        logger.info("ProcessCollector started.")

    def stop(self) -> None:
        """Signal WMI loop to exit and wait for thread to join. Idempotent."""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._executor.shutdown(wait=False)
        self._running = False
        logger.info("ProcessCollector stopped.")

    # ------------------------------------------------------------------ #
    # Internal                                                             #
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        """Main loop running in the WMI subscription thread."""
        try:
            self._subscriber.subscribe(
                on_start=self._on_process_start,
                on_stop=self._on_process_stop,
                stop_event=self._stop_event,
            )
        except Exception as exc:
            logger.error(f"ProcessCollector WMI loop crashed: {exc}", exc_info=True)
        finally:
            self._running = False

    def _on_process_start(self, raw: dict) -> None:
        """Handle a raw Win32_ProcessStartTrace event dict."""
        try:
            self._executor.submit(self._build_and_emit_start, raw)
        except Exception as exc:
            logger.error(f"Failed to submit process-start enrichment: {exc}")

    def _build_and_emit_start(self, raw: dict) -> None:
        """
        Enrichment runs in thread pool to avoid blocking the WMI callback:
        - Resolve process details via psutil (pid, ppid, cmdline, exe, user)
        - Compute SHA-256 asynchronously
        - Check Authenticode signature
        """
        pid = raw.get("ProcessId", 0)
        process_name = raw.get("ProcessName", "")
        ppid = raw.get("ParentProcessId", 0)

        # Enrich via psutil
        exe_path = ""
        cmdline = ""
        user_sid = ""
        parent_name = ""
        integrity_level = ""

        try:
            import psutil  # type: ignore[import]
            proc = psutil.Process(pid)
            exe_path = proc.exe() or ""
            cmdline = " ".join(proc.cmdline())
            username = proc.username() or ""
            user_sid = username  # SID lookup is a future enhancement
            try:
                parent = psutil.Process(ppid)
                parent_name = parent.name()
            except Exception:
                pass
        except Exception:
            pass

        # Async hash (already in thread pool — call synchronously here)
        sha256 = _sha256_file(exe_path) if exe_path else None

        # Authenticode check (best-effort, time-boxed)
        signed = _is_signed(exe_path)

        # Determine if on allowlist
        norm_path = os.path.normcase(exe_path)
        in_allowlist = norm_path in self._allowlist if exe_path else False
        if in_allowlist:
            logger.debug(f"ProcessCollector: {process_name} (pid={pid}) is allowlisted.")

        severity = EventSeverity.LOW.value
        # Unsigned executables get medium severity
        if signed is False:
            severity = EventSeverity.MEDIUM.value
        # System32 cmd/powershell launched from unusual parent → medium
        if "powershell" in process_name.lower() and parent_name and "explorer" not in parent_name.lower():
            severity = EventSeverity.MEDIUM.value

        event = TelemetryEventDTO(
            collector_type=self.COLLECTOR_TYPE,
            event_type="process_start",
            severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={
                "process_name": process_name,
                "pid": pid,
                "ppid": ppid,
                "parent_process_name": parent_name,
                "command_line": cmdline,
                "executable_path": exe_path,
                "executable_sha256": sha256,
                "signed": signed,
                "user_sid": user_sid,
                "integrity_level": integrity_level,
                "in_allowlist": in_allowlist,
            },
        )
        self._emit(event)

    def _on_process_stop(self, raw: dict) -> None:
        """Handle a raw Win32_ProcessStopTrace event dict."""
        try:
            pid = raw.get("ProcessId", 0)
            process_name = raw.get("ProcessName", "")
            event = TelemetryEventDTO(
                collector_type=self.COLLECTOR_TYPE,
                event_type="process_stop",
                severity=EventSeverity.LOW.value,
                timestamp=datetime.now(timezone.utc).isoformat(),
                data={
                    "process_name": process_name,
                    "pid": pid,
                },
            )
            self._emit(event)
        except Exception as exc:
            logger.error(f"Error handling process_stop event: {exc}", exc_info=True)
