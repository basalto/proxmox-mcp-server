"""Tests for config loading."""

from proxmox_mcp.config import Settings


def test_settings_defaults(monkeypatch):
    monkeypatch.delenv("PROXMOX_HOST", raising=False)
    monkeypatch.delenv("PROXMOX_TOKEN_VALUE", raising=False)
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    s = Settings(_env_file=None)
    assert s.proxmox_host == ""
    assert s.proxmox_user == "root@pam"
    assert s.proxmox_token_name == "mcpserver"
    assert s.proxmox_port == 8006
    assert s.allow_elevated is False
    assert s.verify_tls is False
    assert s.mcp_auth_token is None


def test_settings_env_aliases(monkeypatch):
    monkeypatch.setenv("PROXMOX_HOST", "proxmox.stdout.pt")
    monkeypatch.setenv("PROXMOX_TOKEN_VALUE", "tok")
    monkeypatch.setenv("PROXMOX_ALLOW_ELEVATED", "true")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "secret")
    s = Settings(_env_file=None)
    assert s.proxmox_host == "proxmox.stdout.pt"
    assert s.proxmox_token_value == "tok"
    assert s.allow_elevated is True
    assert s.mcp_auth_token == "secret"


def test_allowlist_parsing(monkeypatch):
    monkeypatch.setenv("PROXMOX_NODE_ALLOWLIST", "server1, server2")
    s = Settings(_env_file=None)
    assert s.node_allowlist == "server1, server2"
