"""Small, stop-aware supervisor for the endpoint agent's long-running workers."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import threading
import random
from typing import Callable, Dict, Optional


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class WorkerStatus:
    worker_name: str
    current_state: str = "STOPPED"
    started_at: Optional[str] = None
    last_success_at: Optional[str] = None
    last_error_at: Optional[str] = None
    last_error: Optional[str] = None
    restart_count: int = 0


class BackgroundWorkerSupervisor:
    """Runs registered functions independently and prevents duplicate starts."""

    def __init__(self, stop_event, on_transition=None):
        self.stop_event = stop_event
        self.on_transition = on_transition
        self._workers: Dict[str, dict] = {}
        self._lock = threading.RLock()
        self._started = False

    def register(self, name: str, target: Callable[[], None], interval: float,
                 max_backoff: float = 60.0, close: Optional[Callable[[], None]] = None,
                 jitter_fraction: float = 0.0):
        with self._lock:
            if self._started or name in self._workers:
                raise RuntimeError(f"Worker already registered or supervisor started: {name}")
            self._workers[name] = {
                "target": target, "interval": max(0.05, float(interval)),
                "max_backoff": max(float(interval), float(max_backoff)), "close": close,
                "jitter_fraction": max(0.0, min(float(jitter_fraction), 0.5)),
                "status": WorkerStatus(name), "thread": None,
            }

    def _transition(self, item, state, error=None):
        status = item["status"]
        changed = status.current_state != state
        status.current_state = state
        if state == "STARTING":
            status.started_at = _now()
        elif state == "RUNNING":
            status.last_success_at = _now()
            status.last_error = None
        elif error is not None:
            status.last_error_at = _now()
            status.last_error = str(error)
        if changed and self.on_transition:
            self.on_transition(asdict(status))

    def _run(self, item):
        failures = 0
        self._transition(item, "STARTING")
        while not self.stop_event.is_set():
            try:
                item["target"]()
                failures = 0
                self._transition(item, "RUNNING")
                delay = item["interval"]
            except Exception as exc:
                failures += 1
                item["status"].restart_count += 1
                self._transition(item, "DEGRADED", exc)
                delay = min(item["max_backoff"], item["interval"] * (2 ** min(failures, 6)))
                if item["jitter_fraction"]:
                    delay = min(item["max_backoff"], delay * random.uniform(
                        1.0 - item["jitter_fraction"], 1.0 + item["jitter_fraction"]))
                if not self.stop_event.is_set():
                    self._transition(item, "RESTARTING", exc)
            self.stop_event.wait(delay)
        self._transition(item, "STOPPED")

    def start(self):
        with self._lock:
            if self._started:
                return False
            self._started = True
            for name, item in self._workers.items():
                thread = threading.Thread(target=self._run, args=(item,), name=f"zta-{name}", daemon=True)
                item["thread"] = thread
                thread.start()
            return True

    def stop(self, timeout=20):
        self.stop_event.set()
        with self._lock:
            for item in self._workers.values():
                if item["close"]:
                    try:
                        item["close"]()
                    except Exception as exc:
                        self._transition(item, "FAILED", exc)
            for item in self._workers.values():
                thread = item["thread"]
                if thread:
                    thread.join(timeout=timeout)
                    if thread.is_alive():
                        self._transition(item, "FAILED", "Worker did not stop before timeout")
            self._started = False

    def snapshot(self):
        with self._lock:
            return {name: asdict(item["status"]) for name, item in self._workers.items()}

    @property
    def started(self):
        return self._started
