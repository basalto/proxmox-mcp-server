"""Tests for the Proxmox client with a mocked httpx transport."""

import httpx
import pytest

from proxmox_mcp.client import ProxmoxClient, ProxmoxError


def client_with(handler):
    return ProxmoxClient(
        "proxmox.example",
        "root@pam",
        "mcpserver",
        "secret",
        transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_request_sends_token_and_returns_data():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": [{"node": "server1"}]})

    c = client_with(handler)
    try:
        data = await c.request("/nodes")
    finally:
        await c.aclose()
    assert "proxmox.example:8006/api2/json/nodes" in seen["url"]
    assert seen["auth"] == "PVEAPIToken=root@pam!mcpserver=secret"
    assert data == [{"node": "server1"}]


@pytest.mark.asyncio
async def test_error_raises():
    def handler(request):
        return httpx.Response(401, text="permission denied")

    c = client_with(handler)
    try:
        with pytest.raises(ProxmoxError):
            await c.request("/nodes")
    finally:
        await c.aclose()


@pytest.mark.asyncio
async def test_empty_response_raises():
    def handler(request):
        return httpx.Response(200, text="")

    c = client_with(handler)
    try:
        with pytest.raises(ProxmoxError):
            await c.request("/nodes")
    finally:
        await c.aclose()
