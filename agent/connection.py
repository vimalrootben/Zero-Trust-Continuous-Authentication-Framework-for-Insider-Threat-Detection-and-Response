"""Explicit, durable Agent-to-Manager connection state transitions."""
from datetime import datetime, timezone
import threading


class InvalidConnectionTransition(RuntimeError):
    pass


class ConnectionStateMachine:
    STATES = {"STARTING", "CONNECTING", "ONLINE", "DEGRADED", "OFFLINE",
              "RECONNECTING", "SYNCING", "STOPPING", "STOPPED"}
    TRANSITIONS = {
        "STARTING": {"CONNECTING", "OFFLINE", "STOPPING"},
        "CONNECTING": {"ONLINE", "SYNCING", "OFFLINE", "DEGRADED", "STOPPING"},
        "ONLINE": {"DEGRADED", "OFFLINE", "SYNCING", "STOPPING"},
        "DEGRADED": {"ONLINE", "OFFLINE", "RECONNECTING", "SYNCING", "STOPPING"},
        "OFFLINE": {"RECONNECTING", "CONNECTING", "STOPPING"},
        "RECONNECTING": {"SYNCING", "ONLINE", "OFFLINE", "DEGRADED", "STOPPING"},
        "SYNCING": {"ONLINE", "OFFLINE", "DEGRADED", "STOPPING"},
        "STOPPING": {"STOPPED"},
        "STOPPED": set(),
    }

    def __init__(self, state_store=None, initial="STARTING"):
        self.store = state_store
        # A prior ONLINE value is not current network evidence after process restart.
        self._state = initial
        self._lock = threading.RLock()
        self.changed_at = datetime.now(timezone.utc).isoformat()

    @property
    def state(self):
        with self._lock:
            return self._state

    def transition(self, target, reason=None, force=False):
        if target not in self.STATES:
            raise InvalidConnectionTransition(f"Unknown connection state: {target}")
        with self._lock:
            previous = self._state
            if target == previous:
                return previous, target, False
            if not force and target not in self.TRANSITIONS[previous]:
                raise InvalidConnectionTransition(f"Invalid connection transition: {previous} -> {target}")
            self._state = target
            self.changed_at = datetime.now(timezone.utc).isoformat()
            if self.store:
                self.store.set("connection_state", target)
                self.store.set("connection_state_details", {
                    "previous": previous, "current": target, "changed_at": self.changed_at,
                    "reason": reason,
                })
            return previous, target, True
