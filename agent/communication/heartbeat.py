"""
HeartbeatSender — Collects system resource stats and sends periodic liveness reports.

Key design decisions from blueprint:
  - Heartbeats are NOT queued offline (only telemetry events are).
  - On consecutive failures, signals that the agent may be offline.
  - Does NOT crash the agent on heartbeat failure — logs and continues.
  - Uses psutil for cpu/memory/disk metrics.
"""
import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class ResourceStats:
    cpu_percent: float
    memory_percent: float
    disk_percent: float


class HeartbeatSender:
    def __init__(
        self,
        config,
        transport,
        agent_id: str,
        consecutive_failure_threshold: int = 3,
    ) -> None:
        self.config = config
        self.transport = transport
        self.agent_id = agent_id
        self.consecutive_failure_threshold = consecutive_failure_threshold
        self._consecutive_failures = 0
        self._possibly_offline = False

    def collect_resource_stats(self) -> ResourceStats:
        """
        Collect live system metrics using psutil.

        Returns:
            ResourceStats with cpu, memory, and disk usage percentages.
        """
        try:
            import psutil
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent
        except ImportError:
            # psutil not available in this environment (test/CI)
            cpu, mem, disk = 0.0, 0.0, 0.0
        except Exception as e:
            logger.warning(f"Failed to collect resource stats: {e}")
            cpu, mem, disk = 0.0, 0.0, 0.0

        return ResourceStats(cpu_percent=cpu, memory_percent=mem, disk_percent=disk)

    async def send_heartbeat(self) -> bool:
        """
        Collect stats and POST a heartbeat to the manager.

        Returns:
            True on success, False on any failure (caller handles offline logic).
        """
        from agent.communication.transport import TransportError, AuthenticationError

        stats = self.collect_resource_stats()
        payload = {
            "agent_id": self.agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cpu_usage": stats.cpu_percent,
            "memory_usage": stats.memory_percent,
            "disk_usage": stats.disk_percent,
            "status": "active",
        }

        try:
            response = await self.transport.post("/agent/heartbeat", json=payload)
            if response.status_code == 204:
                self._consecutive_failures = 0
                if self._possibly_offline:
                    logger.info("Agent connectivity restored — heartbeat acknowledged.")
                    self._possibly_offline = False
                logger.debug(
                    f"Heartbeat sent: cpu={stats.cpu_percent}%, "
                    f"mem={stats.memory_percent}%, disk={stats.disk_percent}%"
                )
                return True
            else:
                logger.warning(f"Heartbeat rejected: HTTP {response.status_code}")
                self._record_failure()
                return False

        except AuthenticationError as e:
            logger.critical(
                f"Agent certificate rejected by manager: {e}. "
                "This agent may have been decommissioned. Heartbeat stopped."
            )
            raise  # Re-raise: cert revocation is a critical, non-retryable failure

        except TransportError as e:
            logger.warning(f"Heartbeat transport error: {e}")
            self._record_failure()
            return False

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.consecutive_failure_threshold:
            if not self._possibly_offline:
                logger.warning(
                    f"Agent possibly offline: {self._consecutive_failures} consecutive "
                    f"heartbeat failures (threshold={self.consecutive_failure_threshold})."
                )
                self._possibly_offline = True

    @property
    def possibly_offline(self) -> bool:
        """True after N consecutive heartbeat failures — signals connectivity monitor."""
        return self._possibly_offline

    async def run_forever(self) -> None:
        """
        Continuous heartbeat loop: send every heartbeat_interval_seconds.

        On failure: logs and continues — does NOT crash the agent.
        Signals _possibly_offline after consecutive_failure_threshold misses.
        """
        interval = self.config.heartbeat_interval_seconds
        logger.info(f"HeartbeatSender started: interval={interval}s, agent_id={self.agent_id}")

        while True:
            try:
                await self.send_heartbeat()
            except Exception as e:
                # AuthenticationError intentionally bubbles out of run_forever
                # to the caller (main agent startup) which can handle it.
                if "certificate" in str(e).lower() or "AuthenticationError" in type(e).__name__:
                    raise
                logger.error(f"Unexpected heartbeat error: {e}", exc_info=True)
            await asyncio.sleep(interval)
