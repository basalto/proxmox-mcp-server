"""Configuration management for the Proxmox MCP Server."""

from basalto_mcp import MCPBaseSettings
from pydantic import Field


class Settings(MCPBaseSettings):
    """Application settings loaded from environment variables and .env file.

    Inherits ``.env`` loading, case-insensitivity, and the optional
    ``mcp_auth_token`` (``MCP_AUTH_TOKEN``) from :class:`MCPBaseSettings`.
    """

    proxmox_host: str = Field(
        default="",
        description="Proxmox host (hostname or IP)",
        validation_alias="PROXMOX_HOST",
    )

    proxmox_user: str = Field(
        default="root@pam",
        description="Proxmox API token user (realm-qualified, e.g. root@pam)",
        validation_alias="PROXMOX_USER",
    )

    proxmox_token_name: str = Field(
        default="mcpserver",
        description="Proxmox API token name",
        validation_alias="PROXMOX_TOKEN_NAME",
    )

    proxmox_token_value: str = Field(
        default="",
        description="Proxmox API token secret",
        validation_alias="PROXMOX_TOKEN_VALUE",
    )

    proxmox_port: int = Field(
        default=8006,
        description="Proxmox API port",
        validation_alias="PROXMOX_PORT",
    )

    allow_elevated: bool = Field(
        default=False,
        description="Enable destructive/write tools (default: read-only)",
        validation_alias="PROXMOX_ALLOW_ELEVATED",
    )

    verify_tls: bool = Field(
        default=False,
        description="Verify the Proxmox TLS cert (self-signed by default, so off)",
        validation_alias="PROXMOX_VERIFY_TLS",
    )

    node_allowlist: str | None = Field(
        default=None,
        description="Comma-separated node names the server may touch (empty = unrestricted)",
        validation_alias="PROXMOX_NODE_ALLOWLIST",
    )

    vmid_allowlist: str | None = Field(
        default=None,
        description="Comma-separated VMIDs the server may touch (empty = unrestricted)",
        validation_alias="PROXMOX_VMID_ALLOWLIST",
    )

    request_timeout: float = Field(
        default=30.0,
        description="HTTP request timeout in seconds",
        validation_alias="PROXMOX_REQUEST_TIMEOUT",
    )

    log_level: str = Field(
        default="INFO",
        description="Log level (DEBUG, INFO, WARNING, ERROR)",
        validation_alias="PROXMOX_LOG_LEVEL",
    )
