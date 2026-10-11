"""Async HTTP client for the Proxmox VE API.

Proxmox authenticates with an API token carried as
``Authorization: PVEAPIToken=<user>!<token-name>=<token-value>`` and returns
``{"data": ...}`` on success. The API is HTTPS on port 8006 with a self-signed
certificate by default (verify off).

All methods return the parsed ``data`` payload. API errors raise ``ProxmoxError``.
"""

from __future__ import annotations

from typing import Any

import httpx


class ProxmoxError(RuntimeError):
    """Raised when the Proxmox API returns an error or unexpected payload."""


class ProxmoxClient:
    """Authenticated async client for the Proxmox VE API."""

    def __init__(
        self,
        host: str,
        user: str,
        token_name: str,
        token_value: str,
        *,
        port: int = 8006,
        verify_tls: bool = False,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = f"https://{host}:{port}/api2/json"
        headers = {
            "Authorization": f"PVEAPIToken={user}!{token_name}={token_value}",
            "Content-Type": "application/json",
        }
        self._client = httpx.AsyncClient(
            headers=headers,
            verify=verify_tls,
            timeout=timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        endpoint: str,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> Any:
        """Call one Proxmox API endpoint and return the parsed ``data`` payload."""
        url = f"{self.base_url}{endpoint}"
        resp = await self._client.request(method, url, json=body)
        if resp.status_code >= 400:
            text = resp.text[:300]
            if resp.status_code == 596:
                raise ProxmoxError(
                    f'Proxmox returned 596 proxying to a node in "{endpoint}". '
                    f"Node name lookup is case-sensitive; verify the exact node name. "
                    f"Other 596 causes: proxy timeouts and cert issues."
                )
            raise ProxmoxError(f"Proxmox API error: {resp.status_code} - {text}")
        if not resp.text.strip():
            raise ProxmoxError("Empty response from Proxmox API")
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProxmoxError(f"Failed to parse Proxmox API response: {exc}") from exc
        return data.get("data")
