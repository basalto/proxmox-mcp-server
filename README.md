# Proxmox MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server for the
Proxmox VE API — a FastMCP Python port of
[basalto/mcp-proxmox](https://github.com/basalto/mcp-proxmox). 67 `proxmox_*`
tools covering nodes, VMs/LXC, storage, cluster, snapshots, backups, disks,
networks, migration, cloud-init, RRD metrics, pools, HA, and firewall.

Read-only by default; destructive tools require `PROXMOX_ALLOW_ELEVATED=true`
and a Proxmox API token with the relevant privileges.

## Configuration

Env vars (see `.env.example`): `PROXMOX_HOST`, `PROXMOX_USER`, `PROXMOX_TOKEN_NAME`,
`PROXMOX_TOKEN_VALUE`, `PROXMOX_PORT`, `PROXMOX_ALLOW_ELEVATED`,
`PROXMOX_VERIFY_TLS`, `PROXMOX_NODE_ALLOWLIST`, `PROXMOX_VMID_ALLOWLIST`,
plus `MCP_AUTH_TOKEN` (optional MCP-layer bearer token) and
`FASTMCP_TRANSPORT`/`FASTMCP_HOST`/`FASTMCP_PORT`.

Auth uses the shared
[basalto-mcp](https://github.com/basalto/mcp-common) package
(`StaticTokenAuth`, `MCPBaseSettings`, `make_auth`, `serve`).

## Run

```bash
uv pip install -e ".[dev]"
FASTMCP_TRANSPORT=streamable-http proxmox-mcp-server   # or: python -m proxmox_mcp.main
```

## Test

```bash
uv run pytest
uv run ruff check src tests
uv run black --check src tests
```
