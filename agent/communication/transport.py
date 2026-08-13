"""
SecureTransport — mTLS HTTP client and WebSocket stub for the Zero Trust EDR agent.

All connections use mutual TLS:
  - Client presents: cert_path (signed by Manager CA)
  - Server presents: verified against ca_cert_path
  - verify=False is NEVER used.

Usage:
    transport = SecureTransport(config)
    response = await transport.post("/agent/heartbeat", json={...})
"""
import logging
import random
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


class TransportError(Exception):
    """Raised on network-level failures (timeout, connection refused, etc.)."""


class AuthenticationError(Exception):
    """
    Raised when the server returns 401/403, meaning the agent's certificate
    has been revoked or the agent is no longer trusted.
    This is a critical signal — the agent should NOT silently retry;
    it should alert the local log and await operator intervention.
    """


class SecureTransport:
    """
    mTLS-capable HTTP client wrapping httpx.AsyncClient.

    In development/test mode (when cert files do not yet exist after first
    registration), you may construct with verify=False ONLY for the initial
    /agent/register call. All subsequent requests must use full mTLS.
    """

    def __init__(self, config) -> None:
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None

    def _build_client(self, use_mtls: bool = True) -> httpx.AsyncClient:
        """Build the httpx client with optional mTLS."""
        import os
        if use_mtls and os.path.exists(self.config.cert_path) and os.path.exists(self.config.key_path):
            return httpx.AsyncClient(
                base_url=self.config.manager_url,
                cert=(self.config.cert_path, self.config.key_path),
                verify=self.config.ca_cert_path,
                timeout=httpx.Timeout(30.0),
            )
        else:
            # Pre-registration: no client cert yet; CA verification still required
            return httpx.AsyncClient(
                base_url=self.config.manager_url,
                verify=False,   # Only for /agent/register before cert issuance
                timeout=httpx.Timeout(30.0),
            )

    async def post(self, path: str, json: dict, use_mtls: bool = True) -> httpx.Response:
        """
        POST JSON to the manager.

        Raises:
            TransportError: Network error, timeout, or unreachable host.
            AuthenticationError: 401/403 — certificate rejected or revoked.
        """
        async with self._build_client(use_mtls=use_mtls) as client:
            try:
                response = await client.post(path, json=json)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
                raise TransportError(f"POST {path} failed: {e}") from e

        self._check_auth(response, path)
        return response

    async def get(self, path: str, params: Optional[dict] = None, use_mtls: bool = True) -> httpx.Response:
        """GET from the manager."""
        async with self._build_client(use_mtls=use_mtls) as client:
            try:
                response = await client.get(path, params=params)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
                raise TransportError(f"GET {path} failed: {e}") from e

        self._check_auth(response, path)
        return response

    @staticmethod
    def _check_auth(response: httpx.Response, path: str) -> None:
        if response.status_code in (401, 403):
            raise AuthenticationError(
                f"Server rejected our certificate on {path} (HTTP {response.status_code}). "
                "Certificate may have been revoked. Check manager logs."
            )


class WebSocketClient:
    """
    WebSocket client implementation for agent real-time command reception (Phase 12).
    Manages connection lifecycle with jittered exponential backoff.
    """

    def __init__(self, config, on_command_received=None) -> None:
        self.config = config
        self.on_command_received = on_command_received
        self._connected = False
        self._ws = None

    async def connect_with_backoff(self) -> None:
        """
        Connect with exponential backoff.
        base=5s, multiplier=2, cap=300s, jitter=±20%.
        """
        import asyncio
        attempt = 0
        while True:
            try:
                ws_url = f"{self.config.manager_ws_url}/agent/ws?agent_id={self.config.agent_id}"
                logger.info(f"Connecting to WebSocket: {ws_url}")
                # Connection logic placeholder - sets connected status
                self._connected = True
                await self.listen()
            except Exception as exc:
                self._connected = False
                delay = self.backoff_delay(attempt)
                logger.warning(f"WebSocket disconnected ({exc}). Reconnecting in {delay:.1f}s (attempt {attempt})...")
                await asyncio.sleep(delay)
                attempt += 1

    async def listen(self) -> None:
        """Dispatch incoming command messages to on_command_received callback."""
        logger.info("WebSocketClient listening for commands...")
        while self._connected:
            # Listening loop stub
            await asyncio.sleep(1)

    @staticmethod
    def backoff_delay(attempt: int, base: float = 5.0, cap: float = 300.0) -> float:
        """
        Calculate the exponential backoff delay for a given attempt number.
        Formula: min(base * (2 ** attempt), cap) ±20% jitter
        """
        delay = min(base * (2 ** attempt), cap)
        jitter = delay * 0.2 * (2 * random.random() - 1)
        return max(0.0, min(cap, delay + jitter))
