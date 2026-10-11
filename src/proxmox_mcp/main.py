"""Main entry point for the Proxmox MCP Server.

A FastMCP port of the basalto/mcp-proxmox Node server. 67 ``proxmox_*`` tools
covering nodes, VMs/LXC, storage, cluster, snapshots, backups, disks, networks,
migrations, cloud-init, RRD metrics, pools, HA, and firewall. Read-only by
default; destructive tools are gated behind ``PROXMOX_ALLOW_ELEVATED=true``.
"""

from __future__ import annotations

import importlib.metadata
import re
import secrets
import string
from typing import Any

from basalto_mcp import make_auth, serve
from fastmcp import FastMCP

from .client import ProxmoxClient, ProxmoxError
from .config import Settings

settings = Settings()

mcp = FastMCP("Proxmox MCP Server", auth=make_auth(settings, client_id="proxmox-mcp-server"))

_NODE_ALLOWLIST = {
    s.strip() for s in (settings.node_allowlist or "").split(",") if s.strip()
} or None
_VMID_ALLOWLIST = {
    s.strip() for s in (settings.vmid_allowlist or "").split(",") if s.strip()
} or None


async def _client() -> ProxmoxClient:
    if not settings.proxmox_host:
        raise ProxmoxError("PROXMOX_HOST is not configured. Set it in .env.")
    if not settings.proxmox_token_value:
        raise ProxmoxError("PROXMOX_TOKEN_VALUE is not configured. Set it in .env.")
    return ProxmoxClient(
        settings.proxmox_host,
        settings.proxmox_user,
        settings.proxmox_token_name,
        settings.proxmox_token_value,
        port=settings.proxmox_port,
        verify_tls=settings.verify_tls,
        timeout=settings.request_timeout,
    )


def _require_elevated() -> None:
    if not settings.allow_elevated:
        raise ProxmoxError("requires elevated permissions (set PROXMOX_ALLOW_ELEVATED=true)")


# ---------------------------------------------------------------------------
# Input validation (ported 1:1 from the Node server)
# ---------------------------------------------------------------------------


def validate_node(node: Any) -> str:
    if not node or not isinstance(node, str):
        raise ProxmoxError("Node name is required and must be a string")
    if not re.fullmatch(r"[a-zA-Z0-9\-_]+", node):
        raise ProxmoxError(
            "Invalid node name format. Only alphanumeric, hyphens, and underscores allowed"
        )
    if len(node) > 64:
        raise ProxmoxError("Node name too long (max 64 characters)")
    if _NODE_ALLOWLIST and node not in _NODE_ALLOWLIST:
        raise ProxmoxError(f'Node "{node}" is not in PROXMOX_NODE_ALLOWLIST')
    return node


def validate_vmid(vmid: Any) -> str:
    if not vmid:
        raise ProxmoxError("VM ID is required")
    try:
        id_ = int(vmid)
    except (TypeError, ValueError):
        raise ProxmoxError("Invalid VM ID. Must be a number between 100 and 999999999") from None
    if id_ < 100 or id_ > 999999999:
        raise ProxmoxError("Invalid VM ID. Must be a number between 100 and 999999999")
    id_str = str(id_)
    if _VMID_ALLOWLIST and id_str not in _VMID_ALLOWLIST:
        raise ProxmoxError(f"VMID {id_str} is not in PROXMOX_VMID_ALLOWLIST")
    return id_str


def validate_guest_type(type_: Any, fallback: str = "qemu") -> str:
    value = fallback if type_ in (None, "") else type_
    if value not in ("qemu", "lxc"):
        raise ProxmoxError("Invalid guest type. Must be 'qemu' or 'lxc'")
    return value


def validate_storage(storage: Any) -> str:
    if not storage or not isinstance(storage, str):
        raise ProxmoxError("Storage name is required and must be a string")
    if not re.fullmatch(r"[a-zA-Z0-9\-_.]+", storage):
        raise ProxmoxError(
            "Invalid storage name format. Only alphanumeric, hyphens, underscores, and dots allowed"
        )
    if len(storage) > 64:
        raise ProxmoxError("Storage name too long (max 64 characters)")
    return storage


def validate_snapshot(snapname: Any) -> str:
    if not snapname or not isinstance(snapname, str):
        raise ProxmoxError("Snapshot name is required and must be a string")
    if not re.fullmatch(r"[a-zA-Z0-9\-_]+", snapname):
        raise ProxmoxError(
            "Invalid snapshot name format. Only alphanumeric, hyphens, and underscores allowed"
        )
    if len(snapname) > 40:
        raise ProxmoxError("Snapshot name too long (max 40 characters)")
    return snapname


def validate_disk(disk: Any) -> str:
    if not disk or not isinstance(disk, str):
        raise ProxmoxError("Disk name is required and must be a string")
    if disk in ("rootfs", "efidisk0", "tpmstate0"):
        return disk
    m = re.fullmatch(r"(scsi|virtio|sata|ide|mp|unused)(\d+)", disk)
    if not m:
        raise ProxmoxError(
            "Invalid disk name format. Expected: scsi0-30, virtio0-15, sata0-5, "
            "ide0-3, efidisk0, tpmstate0, rootfs, mp0-255, or unusedN"
        )
    prefix, num_str = m.group(1), m.group(2)
    num = int(num_str)
    max_by_prefix = {"scsi": 30, "virtio": 15, "sata": 5, "ide": 3, "mp": 255, "unused": None}
    max_ = max_by_prefix[prefix]
    if max_ is not None and num > max_:
        raise ProxmoxError(f"Disk number out of range for {prefix} (max: {prefix}{max_})")
    return disk


def validate_network(net: Any) -> str:
    if not net or not isinstance(net, str):
        raise ProxmoxError("Network interface name is required and must be a string")
    m = re.fullmatch(r"net(\d{1,2})", net)
    if not m:
        raise ProxmoxError("Invalid network interface name. Expected: net0-31")
    num = int(m.group(1))
    if num > 31:
        raise ProxmoxError("Network interface number out of range (max: net31)")
    return f"net{num}"


def validate_bridge(bridge: Any) -> str:
    if not bridge or not isinstance(bridge, str):
        raise ProxmoxError("Bridge name is required and must be a string")
    if not re.fullmatch(r"[a-zA-Z0-9._-]+", bridge):
        raise ProxmoxError(
            "Invalid bridge name format. Only alphanumeric, periods, hyphens, and underscores allowed"
        )
    if len(bridge) > 32:
        raise ProxmoxError("Bridge name too long (max 32 characters)")
    return bridge


def validate_mountpoint(mp: Any) -> str:
    if not mp or not isinstance(mp, str):
        raise ProxmoxError("Mount point name is required and must be a string")
    if mp == "rootfs":
        return mp
    m = re.fullmatch(r"mp(\d{1,3})", mp)
    if not m:
        raise ProxmoxError("Invalid mount point name. Expected: mp0-255 or rootfs")
    num = int(m.group(1))
    if num > 255:
        raise ProxmoxError("Mount point number out of range (max: mp255)")
    return f"mp{num}"


def validate_command(command: Any) -> str:
    if not command or not isinstance(command, str):
        raise ProxmoxError("Command is required and must be a string")
    if re.search(r"[;&|`$(){}[\]<>\\]", command):
        raise ProxmoxError("Command contains potentially dangerous characters")
    if len(command) > 1000:
        raise ProxmoxError("Command exceeds maximum allowed length (1000 characters)")
    return command


def validate_upid(upid: Any) -> str:
    if not upid or not isinstance(upid, str):
        raise ProxmoxError("UPID is required and must be a string")
    if not re.fullmatch(
        r"UPID:[^:]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:[^:]+:[^:]*:[^:]+:", upid
    ):
        raise ProxmoxError("Invalid UPID format")
    if len(upid) > 256:
        raise ProxmoxError("UPID too long (max 256 characters)")
    return upid


def _secure_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(16))


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@mcp.tool()
async def health_check() -> dict[str, str]:
    """Health check to verify the server is running and can reach Proxmox.

    Returns:
        Status information plus Proxmox connectivity.
    """
    try:
        client = await _client()
    except ProxmoxError as exc:
        return {"status": "unhealthy", "error": str(exc)}
    try:
        await client.request("/nodes")
        reachable = "ok"
    except ProxmoxError as exc:
        reachable = f"error: {exc}"
    finally:
        await client.aclose()
    return {
        "status": "healthy" if reachable == "ok" else "unhealthy",
        "proxmox_reachable": reachable,
        "proxmox_host": settings.proxmox_host,
        "version": importlib.metadata.version("proxmox-mcp-server"),
    }


# ---------------------------------------------------------------------------
# Nodes / cluster / storage (read-only)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_get_nodes() -> dict[str, Any]:
    """List all Proxmox cluster nodes with their status and resources.

    Returns:
        ``nodes``: each node's name, status, uptime, cpu, mem, maxmem.
    """
    client = await _client()
    try:
        return {"nodes": await client.request("/nodes")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_node_status(node: str) -> dict[str, Any]:
    """Get detailed status information for a specific Proxmox node.

    Args:
        node: Node name (e.g. server1, server2).

    Returns:
        The node status payload (uptime, loadavg, cpu, memory, rootfs).
    """
    _require_elevated()
    client = await _client()
    try:
        return {
            "node": node,
            "status": await client.request(f"/nodes/{validate_node(node)}/status"),
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_vms(node: str = "", type: str = "all") -> dict[str, Any]:
    """List all virtual machines across the cluster with their status.

    Args:
        node: optional filter by specific node.
        type: VM type filter ('qemu', 'lxc', or 'all').

    Returns:
        ``vms``: each guest's vmid, name, type, node, status, cpu, mem, uptime.
    """
    safe_node = validate_node(node) if node else None
    want_qemu = type in ("all", "qemu")
    want_lxc = type in ("all", "lxc")
    client = await _client()
    try:
        vms: list[dict[str, Any]] = []
        try:
            resources = await client.request("/cluster/resources?type=vm")
            vms = [r for r in (resources or []) if r.get("type") in ("qemu", "lxc")]
        except ProxmoxError:
            node_names = (
                [safe_node]
                if safe_node
                else [n["node"] for n in (await client.request("/nodes") or [])]
            )
            for n in node_names:
                if want_qemu:
                    vms.extend(
                        {**vm, "type": "qemu", "node": n}
                        for vm in (await client.request(f"/nodes/{n}/qemu") or [])
                    )
                if want_lxc:
                    vms.extend(
                        {**vm, "type": "lxc", "node": n}
                        for vm in (await client.request(f"/nodes/{n}/lxc") or [])
                    )
        vms = [
            vm
            for vm in vms
            if (not safe_node or vm.get("node") == safe_node)
            and (vm.get("type") == "qemu" and want_qemu or vm.get("type") == "lxc" and want_lxc)
        ]
        vms.sort(key=lambda v: int(v.get("vmid", 0)))
        return {"count": len(vms), "vms": vms}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_vm_status(node: str, vmid: str, type: str = "qemu") -> dict[str, Any]:
    """Get detailed status information for a specific VM or container.

    Args:
        node: Node name where the guest is located.
        vmid: VM/container ID.
        type: guest type ('qemu' or 'lxc').

    Returns:
        The guest's current status payload.
    """
    client = await _client()
    try:
        n, v, t = validate_node(node), validate_vmid(vmid), validate_guest_type(type)
        return await client.request(f"/nodes/{n}/{t}/{v}/status/current")
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_storage(node: str = "") -> dict[str, Any]:
    """List all storage pools and their usage across the cluster.

    Args:
        node: optional filter by specific node.

    Returns:
        ``storages``: each pool's storage, node, type, content, total, used.
    """
    client = await _client()
    try:
        storages: list[dict[str, Any]] = []
        if node:
            n = validate_node(node)
            storages = [
                {**s, "node": n} for s in (await client.request(f"/nodes/{n}/storage") or [])
            ]
        else:
            for nd in await client.request("/nodes") or []:
                storages.extend(
                    {**s, "node": nd["node"]}
                    for s in (await client.request(f"/nodes/{nd['node']}/storage") or [])
                )
        return {"count": len(storages), "storages": storages}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_cluster_status() -> dict[str, Any]:
    """Get overall cluster status including nodes and resource usage.

    Returns:
        Node list plus (when elevated) the cluster status payload.
    """
    client = await _client()
    try:
        nodes = await client.request("/nodes") or []
        result: dict[str, Any] = {"nodes": nodes}
        if settings.allow_elevated:
            try:
                result["cluster_status"] = await client.request("/cluster/status")
            except ProxmoxError:
                pass
        return result
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_list_templates(node: str, storage: str = "local") -> dict[str, Any]:
    """List available LXC container templates on a storage.

    Args:
        node: Node name.
        storage: Storage name.

    Returns:
        ``templates``: each template's volid and size.
    """
    client = await _client()
    try:
        n, s = validate_node(node), validate_storage(storage)
        return {"templates": await client.request(f"/nodes/{n}/storage/{s}/content?content=vztmpl")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_next_vmid() -> dict[str, Any]:
    """Get the next available VM/Container ID number.

    Returns:
        The next free vmid.
    """
    client = await _client()
    try:
        return {"next_vmid": await client.request("/cluster/nextid")}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Guest lifecycle (elevated)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_start_lxc(node: str, vmid: str) -> dict[str, Any]:
    """Start an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.

    Returns:
        The task UPID for the start operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/lxc/{v}/status/start", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_start_vm(node: str, vmid: str) -> dict[str, Any]:
    """Start a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.

    Returns:
        The task UPID for the start operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/status/start", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_stop_lxc(node: str, vmid: str) -> dict[str, Any]:
    """Stop an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.

    Returns:
        The task UPID for the stop operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/lxc/{v}/status/stop", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_stop_vm(node: str, vmid: str) -> dict[str, Any]:
    """Stop a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.

    Returns:
        The task UPID for the stop operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/status/stop", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_delete_lxc(node: str, vmid: str) -> dict[str, Any]:
    """Delete an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID to delete.

    Returns:
        The task UPID for the delete operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/lxc/{v}", "DELETE")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_delete_vm(node: str, vmid: str) -> dict[str, Any]:
    """Delete a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID to delete.

    Returns:
        The task UPID for the delete operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}", "DELETE")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_reboot_lxc(node: str, vmid: str) -> dict[str, Any]:
    """Reboot an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.

    Returns:
        The task UPID for the reboot operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/lxc/{v}/status/reboot", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_reboot_vm(node: str, vmid: str) -> dict[str, Any]:
    """Reboot a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.

    Returns:
        The task UPID for the reboot operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/status/reboot", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_shutdown_lxc(node: str, vmid: str) -> dict[str, Any]:
    """Gracefully shutdown an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.

    Returns:
        The task UPID for the shutdown operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/lxc/{v}/status/shutdown", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_shutdown_vm(node: str, vmid: str) -> dict[str, Any]:
    """Gracefully shutdown a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.

    Returns:
        The task UPID for the shutdown operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/status/shutdown", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_pause_vm(node: str, vmid: str) -> dict[str, Any]:
    """Pause (suspend) a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.

    Returns:
        The task UPID for the suspend operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/status/suspend", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_resume_vm(node: str, vmid: str) -> dict[str, Any]:
    """Resume a paused QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.

    Returns:
        The task UPID for the resume operation.
    """
    _require_elevated()
    client = await _client()
    try:
        n, v = validate_node(node), validate_vmid(vmid)
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/status/resume", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_create_lxc(
    node: str,
    vmid: str,
    ostemplate: str,
    hostname: str = "",
    password: str = "",
    memory: int = 512,
    storage: str = "local-lvm",
    rootfs: str = "8",
) -> dict[str, Any]:
    """Create a new LXC container (requires elevated permissions).

    Args:
        node: Node name where the container will be created.
        vmid: Container ID (unique, or use proxmox_get_next_vmid).
        ostemplate: OS template (e.g. local:vztmpl/debian-12-standard_12.2-1_amd64.tar.gz).
        hostname: Container hostname.
        password: Root password (auto-generated if omitted).
        memory: RAM in MB.
        storage: Storage location.
        rootfs: Root filesystem size in GB.

    Returns:
        The task UPID plus the (possibly generated) password.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    gen_password = password or _secure_password()
    body = {
        "vmid": v,
        "ostemplate": ostemplate,
        "hostname": hostname or f"ct{v}",
        "password": gen_password,
        "memory": memory,
        "storage": storage,
        "rootfs": f"{storage}:{rootfs}",
    }
    client = await _client()
    try:
        upid = await client.request(f"/nodes/{n}/lxc", "POST", body)
    finally:
        await client.aclose()
    return {"upid": upid, "vmid": v, "password": gen_password, "password_generated": not password}


@mcp.tool()
async def proxmox_create_vm(
    node: str,
    vmid: str,
    name: str = "",
    memory: int = 512,
    cores: int = 1,
    sockets: int = 1,
    disk_size: str = "8G",
    storage: str = "local-lvm",
    iso: str = "",
    ostype: str = "l26",
    net0: str = "virtio,bridge=vmbr0",
) -> dict[str, Any]:
    """Create a new QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM will be created.
        vmid: VM ID (unique, or use proxmox_get_next_vmid).
        name: VM name.
        memory: RAM in MB.
        cores: Number of CPU cores.
        sockets: Number of CPU sockets.
        disk_size: Disk size (e.g. "8G", "10G").
        storage: Storage location for the disk.
        iso: ISO image (optional, e.g. "local:iso/alpine.iso").
        ostype: OS type (l26=Linux, win10, etc.).
        net0: Network interface config.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    size_match = re.match(r"^(\d+(?:\.\d+)?)", str(disk_size))
    if not size_match:
        raise ProxmoxError(f'Invalid disk size "{disk_size}". Expected e.g. "8G".')
    body = {
        "vmid": v,
        "name": name or f"vm{v}",
        "memory": memory,
        "cores": cores,
        "sockets": sockets,
        "ostype": ostype,
        "net0": net0,
        "scsi0": f"{storage}:{size_match.group(1)}",
    }
    if iso:
        body["ide2"] = f"{iso},media=cdrom"
        body["boot"] = "order=ide2;scsi0"
    client = await _client()
    try:
        upid = await client.request(f"/nodes/{n}/qemu", "POST", body)
    finally:
        await client.aclose()
    return {"upid": upid, "vmid": v}


@mcp.tool()
async def proxmox_clone_lxc(node: str, vmid: str, newid: str, hostname: str = "") -> dict[str, Any]:
    """Clone an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID to clone from.
        newid: New container ID.
        hostname: Hostname for the cloned container.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, nid = validate_node(node), validate_vmid(vmid), validate_vmid(newid)
    body = {"newid": nid}
    if hostname:
        body["hostname"] = hostname
    client = await _client()
    try:
        return {"upid": await client.request(f"/nodes/{n}/lxc/{v}/clone", "POST", body)}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_clone_vm(node: str, vmid: str, newid: str, name: str = "") -> dict[str, Any]:
    """Clone a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID to clone from.
        newid: New VM ID.
        name: Name for the cloned VM.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, nid = validate_node(node), validate_vmid(vmid), validate_vmid(newid)
    body = {"newid": nid}
    if name:
        body["name"] = name
    client = await _client()
    try:
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/clone", "POST", body)}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_resize_lxc(
    node: str, vmid: str, memory: int = 0, cores: int = 0
) -> dict[str, Any]:
    """Resize an LXC container CPU/memory (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        memory: Memory in MB (optional).
        cores: Number of CPU cores (optional).

    Returns:
        The API result.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    body: dict[str, Any] = {}
    if memory:
        body["memory"] = memory
    if cores:
        body["cores"] = cores
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/lxc/{v}/config", "PUT", body)}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_resize_vm(
    node: str, vmid: str, memory: int = 0, cores: int = 0
) -> dict[str, Any]:
    """Resize a QEMU VM CPU/memory (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        memory: Memory in MB (optional).
        cores: Number of CPU cores (optional).

    Returns:
        The API result.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    body: dict[str, Any] = {}
    if memory:
        body["memory"] = memory
    if cores:
        body["cores"] = cores
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/qemu/{v}/config", "PUT", body)}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Snapshots (elevated)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_create_snapshot_lxc(node: str, vmid: str, snapname: str) -> dict[str, Any]:
    """Create a snapshot of an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        snapname: Snapshot name.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_snapshot(snapname)
    client = await _client()
    try:
        return {
            "upid": await client.request(f"/nodes/{n}/lxc/{v}/snapshot", "POST", {"snapname": s})
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_create_snapshot_vm(node: str, vmid: str, snapname: str) -> dict[str, Any]:
    """Create a snapshot of a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        snapname: Snapshot name.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_snapshot(snapname)
    client = await _client()
    try:
        return {
            "upid": await client.request(f"/nodes/{n}/qemu/{v}/snapshot", "POST", {"snapname": s})
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_list_snapshots_lxc(node: str, vmid: str) -> dict[str, Any]:
    """List all snapshots of an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.

    Returns:
        ``snapshots``: the snapshot list.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    client = await _client()
    try:
        return {"snapshots": await client.request(f"/nodes/{n}/lxc/{v}/snapshot")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_list_snapshots_vm(node: str, vmid: str) -> dict[str, Any]:
    """List all snapshots of a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.

    Returns:
        ``snapshots``: the snapshot list.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    client = await _client()
    try:
        return {"snapshots": await client.request(f"/nodes/{n}/qemu/{v}/snapshot")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_rollback_snapshot_lxc(node: str, vmid: str, snapname: str) -> dict[str, Any]:
    """Rollback an LXC container to a snapshot (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        snapname: Snapshot name to roll back to.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_snapshot(snapname)
    client = await _client()
    try:
        return {
            "upid": await client.request(f"/nodes/{n}/lxc/{v}/snapshot/{s}/rollback", "POST", {})
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_rollback_snapshot_vm(node: str, vmid: str, snapname: str) -> dict[str, Any]:
    """Rollback a QEMU virtual machine to a snapshot (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        snapname: Snapshot name to roll back to.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_snapshot(snapname)
    client = await _client()
    try:
        return {
            "upid": await client.request(f"/nodes/{n}/qemu/{v}/snapshot/{s}/rollback", "POST", {})
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_delete_snapshot_lxc(node: str, vmid: str, snapname: str) -> dict[str, Any]:
    """Delete a snapshot of an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        snapname: Snapshot name to delete.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_snapshot(snapname)
    client = await _client()
    try:
        return {"upid": await client.request(f"/nodes/{n}/lxc/{v}/snapshot/{s}", "DELETE")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_delete_snapshot_vm(node: str, vmid: str, snapname: str) -> dict[str, Any]:
    """Delete a snapshot of a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        snapname: Snapshot name to delete.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_snapshot(snapname)
    client = await _client()
    try:
        return {"upid": await client.request(f"/nodes/{n}/qemu/{v}/snapshot/{s}", "DELETE")}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Backups (elevated)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_create_backup_lxc(
    node: str, vmid: str, storage: str = "local", mode: str = "snapshot", compress: str = "zstd"
) -> dict[str, Any]:
    """Create a backup of an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        storage: Storage location for the backup.
        mode: Backup mode ('snapshot', 'suspend', or 'stop').
        compress: Compression algorithm ('none', 'lzo', 'gzip', or 'zstd').

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_storage(storage)
    client = await _client()
    try:
        return {
            "upid": await client.request(
                f"/nodes/{n}/vzdump",
                "POST",
                {"vmid": v, "storage": s, "mode": mode, "compress": compress},
            )
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_create_backup_vm(
    node: str, vmid: str, storage: str = "local", mode: str = "snapshot", compress: str = "zstd"
) -> dict[str, Any]:
    """Create a backup of a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        storage: Storage location for the backup.
        mode: Backup mode ('snapshot', 'suspend', or 'stop').
        compress: Compression algorithm ('none', 'lzo', 'gzip', or 'zstd').

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, s = validate_node(node), validate_vmid(vmid), validate_storage(storage)
    client = await _client()
    try:
        return {
            "upid": await client.request(
                f"/nodes/{n}/vzdump",
                "POST",
                {"vmid": v, "storage": s, "mode": mode, "compress": compress},
            )
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_list_backups(node: str, storage: str = "local") -> dict[str, Any]:
    """List all backups on a storage (requires elevated permissions).

    Args:
        node: Node name.
        storage: Storage name.

    Returns:
        ``backups``: each backup's volid, size, ctime.
    """
    _require_elevated()
    n, s = validate_node(node), validate_storage(storage)
    client = await _client()
    try:
        return {"backups": await client.request(f"/nodes/{n}/storage/{s}/content?content=backup")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_restore_backup_lxc(
    node: str, vmid: str, archive: str, storage: str = ""
) -> dict[str, Any]:
    """Restore an LXC container from backup (requires elevated permissions).

    Args:
        node: Node name where the container will be restored.
        vmid: New container ID.
        archive: Backup archive path (e.g. local:backup/vzdump-lxc-100-....tar.zst).
        storage: Storage location (optional).

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    body: dict[str, Any] = {"vmid": v, "ostemplate": archive, "restore": 1}
    if storage:
        body["storage"] = validate_storage(storage)
    client = await _client()
    try:
        return {"upid": await client.request(f"/nodes/{n}/lxc", "POST", body)}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_restore_backup_vm(
    node: str, vmid: str, archive: str, storage: str = ""
) -> dict[str, Any]:
    """Restore a QEMU virtual machine from backup (requires elevated permissions).

    Args:
        node: Node name where the VM will be restored.
        vmid: New VM ID.
        archive: Backup archive path (e.g. local:backup/vzdump-qemu-100-....vma.zst).
        storage: Storage location (optional).

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    body: dict[str, Any] = {"vmid": v, "archive": archive}
    if storage:
        body["storage"] = validate_storage(storage)
    client = await _client()
    try:
        return {"upid": await client.request(f"/nodes/{n}/qemu", "POST", body)}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_delete_backup(node: str, storage: str, volume: str) -> dict[str, Any]:
    """Delete a backup file from storage (requires elevated permissions).

    Args:
        node: Node name.
        storage: Storage name.
        volume: Backup volume ID (e.g. local:backup/vzdump-lxc-100-....tar.zst).

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, s = validate_node(node), validate_storage(storage)
    client = await _client()
    try:
        return {"upid": await client.request(f"/nodes/{n}/storage/{s}/content/{volume}", "DELETE")}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Disks (elevated)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_add_disk_vm(
    node: str, vmid: str, disk: str, storage: str, size: str
) -> dict[str, Any]:
    """Add a new disk to a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        disk: Disk name (scsi1, virtio1, sata1, ide1).
        storage: Storage name.
        size: Disk size in GB.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, d, s = (
        validate_node(node),
        validate_vmid(vmid),
        validate_disk(disk),
        validate_storage(storage),
    )
    client = await _client()
    try:
        return {
            "result": await client.request(f"/nodes/{n}/qemu/{v}/config", "PUT", {d: f"{s}:{size}"})
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_add_mountpoint_lxc(
    node: str, vmid: str, mp: str, storage: str, size: str
) -> dict[str, Any]:
    """Add a mount point to an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        mp: Mount point name (mp0, mp1, ...).
        storage: Storage name.
        size: Mount point size in GB.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, m, s = (
        validate_node(node),
        validate_vmid(vmid),
        validate_mountpoint(mp),
        validate_storage(storage),
    )
    client = await _client()
    try:
        return {
            "result": await client.request(f"/nodes/{n}/lxc/{v}/config", "PUT", {m: f"{s}:{size}"})
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_resize_disk_vm(node: str, vmid: str, disk: str, size: str) -> dict[str, Any]:
    """Resize a QEMU VM disk (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        disk: Disk name (scsi0, virtio0, sata0, ide0).
        size: New size (+10G for relative, or 50G absolute).

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, d = validate_node(node), validate_vmid(vmid), validate_disk(disk)
    client = await _client()
    try:
        return {
            "upid": await client.request(
                f"/nodes/{n}/qemu/{v}/resize", "PUT", {"disk": d, "size": size}
            )
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_resize_disk_lxc(node: str, vmid: str, disk: str, size: str) -> dict[str, Any]:
    """Resize an LXC container disk or mount point (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        disk: Disk name (rootfs, mp0, mp1, ...).
        size: New size (+10G for relative, or 50G absolute).

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, d = validate_node(node), validate_vmid(vmid), validate_disk(disk)
    client = await _client()
    try:
        return {
            "upid": await client.request(
                f"/nodes/{n}/lxc/{v}/resize", "PUT", {"disk": d, "size": size}
            )
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_remove_disk_vm(node: str, vmid: str, disk: str) -> dict[str, Any]:
    """Remove a disk from a QEMU virtual machine (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        disk: Disk name to remove.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, d = validate_node(node), validate_vmid(vmid), validate_disk(disk)
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/qemu/{v}/config", "PUT", {"delete": d})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_remove_mountpoint_lxc(node: str, vmid: str, mp: str) -> dict[str, Any]:
    """Remove a mount point from an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        mp: Mount point name to remove.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, m = validate_node(node), validate_vmid(vmid), validate_mountpoint(mp)
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/lxc/{v}/config", "PUT", {"delete": m})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_move_disk_vm(
    node: str, vmid: str, disk: str, storage: str, delete: bool = True
) -> dict[str, Any]:
    """Move a QEMU VM disk to different storage (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        disk: Disk name to move.
        storage: Target storage name.
        delete: Delete source disk after move.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, d, s = (
        validate_node(node),
        validate_vmid(vmid),
        validate_disk(disk),
        validate_storage(storage),
    )
    client = await _client()
    try:
        return {
            "upid": await client.request(
                f"/nodes/{n}/qemu/{v}/move_disk",
                "POST",
                {"disk": d, "storage": s, "delete": 1 if delete else 0},
            )
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_move_disk_lxc(
    node: str, vmid: str, disk: str, storage: str, delete: bool = True
) -> dict[str, Any]:
    """Move an LXC container volume to different storage (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        disk: Volume name to move (rootfs, mp0, mp1, ...).
        storage: Target storage name.
        delete: Delete source volume after move.

    Returns:
        The task UPID.
    """
    _require_elevated()
    n, v, d, s = (
        validate_node(node),
        validate_vmid(vmid),
        validate_disk(disk),
        validate_storage(storage),
    )
    client = await _client()
    try:
        return {
            "upid": await client.request(
                f"/nodes/{n}/lxc/{v}/move_volume",
                "POST",
                {"volume": d, "storage": s, "delete": 1 if delete else 0},
            )
        }
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Networks (elevated)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_add_network_vm(
    node: str,
    vmid: str,
    net: str,
    bridge: str,
    model: str = "virtio",
    macaddr: str = "",
    vlan: int = 0,
    firewall: bool = False,
) -> dict[str, Any]:
    """Add a network interface to a QEMU VM (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        net: Interface name (net0, net1, ...).
        bridge: Bridge name (vmbr0, ...).
        model: Network model (virtio, e1000, rtl8139, vmxnet3).
        macaddr: MAC address (XX:XX:XX:XX:XX:XX).
        vlan: VLAN tag (1-4094).
        firewall: Enable firewall on the interface.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, nt, b = (
        validate_node(node),
        validate_vmid(vmid),
        validate_network(net),
        validate_bridge(bridge),
    )
    cfg = f"{model},bridge={b}"
    if macaddr:
        cfg += f",macaddr={macaddr}"
    if vlan:
        cfg += f",tag={vlan}"
    if firewall:
        cfg += ",firewall=1"
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/qemu/{v}/config", "PUT", {nt: cfg})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_add_network_lxc(
    node: str,
    vmid: str,
    net: str,
    bridge: str,
    ip: str = "",
    gw: str = "",
    firewall: bool = False,
) -> dict[str, Any]:
    """Add a network interface to an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        net: Interface name (net0, net1, ...).
        bridge: Bridge name (vmbr0, ...).
        ip: IP address (dhcp, 192.168.1.100/24, auto).
        gw: Gateway IP.
        firewall: Enable firewall on the interface.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, nt, b = (
        validate_node(node),
        validate_vmid(vmid),
        validate_network(net),
        validate_bridge(bridge),
    )
    net_num = nt.replace("net", "")
    cfg = f"name=eth{net_num},bridge={b}"
    if ip:
        cfg += f",ip={ip}"
    if gw:
        cfg += f",gw={gw}"
    if firewall:
        cfg += ",firewall=1"
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/lxc/{v}/config", "PUT", {nt: cfg})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_update_network_vm(
    node: str,
    vmid: str,
    net: str,
    bridge: str = "",
    model: str = "virtio",
    macaddr: str = "",
    vlan: int = 0,
    firewall: bool = False,
) -> dict[str, Any]:
    """Update a VM network interface (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        net: Interface name to update.
        bridge: Bridge name.
        model: Network model.
        macaddr: MAC address.
        vlan: VLAN tag.
        firewall: Enable firewall on the interface.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, nt = validate_node(node), validate_vmid(vmid), validate_network(net)
    if bridge:
        validate_bridge(bridge)
    cfg = f"{model},bridge={bridge}"
    if macaddr:
        cfg += f",macaddr={macaddr}"
    if vlan:
        cfg += f",tag={vlan}"
    if firewall:
        cfg += ",firewall=1"
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/qemu/{v}/config", "PUT", {nt: cfg})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_update_network_lxc(
    node: str,
    vmid: str,
    net: str,
    bridge: str = "",
    ip: str = "",
    gw: str = "",
    firewall: bool = False,
) -> dict[str, Any]:
    """Update an LXC network interface (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        net: Interface name to update.
        bridge: Bridge name.
        ip: IP address.
        gw: Gateway IP.
        firewall: Enable firewall on the interface.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, nt = validate_node(node), validate_vmid(vmid), validate_network(net)
    if bridge:
        validate_bridge(bridge)
    net_num = nt.replace("net", "")
    cfg = f"name=eth{net_num},bridge={bridge}"
    if ip:
        cfg += f",ip={ip}"
    if gw:
        cfg += f",gw={gw}"
    if firewall:
        cfg += ",firewall=1"
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/lxc/{v}/config", "PUT", {nt: cfg})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_remove_network_vm(node: str, vmid: str, net: str) -> dict[str, Any]:
    """Remove a network interface from a QEMU VM (requires elevated permissions).

    Args:
        node: Node name where the VM is located.
        vmid: VM ID.
        net: Interface name to remove.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, nt = validate_node(node), validate_vmid(vmid), validate_network(net)
    client = await _client()
    try:
        return {
            "result": await client.request(f"/nodes/{n}/qemu/{v}/config", "PUT", {"delete": nt})
        }
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_remove_network_lxc(node: str, vmid: str, net: str) -> dict[str, Any]:
    """Remove a network interface from an LXC container (requires elevated permissions).

    Args:
        node: Node name where the container is located.
        vmid: Container ID.
        net: Interface name to remove.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, nt = validate_node(node), validate_vmid(vmid), validate_network(net)
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/lxc/{v}/config", "PUT", {"delete": nt})}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Tasks / config / identity (read-only)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_get_task_status(
    node: str, upid: str, wait: bool = False, timeout: int = 60
) -> dict[str, Any]:
    """Get the status of a Proxmox task by UPID. Optionally wait for completion.

    Args:
        node: Node the task is running on.
        upid: Task UPID (returned by mutating operations).
        wait: Poll until the task finishes.
        timeout: Max seconds to wait when wait=true (max 600).

    Returns:
        The task status payload.
    """
    n, u = validate_node(node), validate_upid(upid)
    import asyncio

    timeout = max(1, min(timeout, 600))
    client = await _client()
    try:
        path = f"/nodes/{n}/tasks/{u}/status"
        status = await client.request(path)
        if wait:
            import time

            start = time.monotonic()
            while (
                status and status.get("exitstatus") is None and (time.monotonic() - start) < timeout
            ):
                await asyncio.sleep(2)
                status = await client.request(path)
        return {"status": status}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_vm_config(node: str, vmid: str, type: str = "qemu") -> dict[str, Any]:
    """Get the full configuration of a VM or LXC container.

    Args:
        node: Node where the guest is located.
        vmid: VM/container ID.
        type: guest type ('qemu' or 'lxc').

    Returns:
        The guest configuration (cores, memory, disks, network, cloud-init).
    """
    n, v, t = validate_node(node), validate_vmid(vmid), validate_guest_type(type)
    client = await _client()
    try:
        return {"config": await client.request(f"/nodes/{n}/{t}/{v}/config")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_whoami(path: str = "") -> dict[str, Any]:
    """Show the identity the server authenticates as and its API permissions.

    Args:
        path: optional ACL path to check permissions for (e.g. /vms/100).

    Returns:
        The permissions payload (and the token identity).
    """
    client = await _client()
    try:
        endpoint = f"/access/permissions?path={path}" if path else "/access/permissions"
        permissions = await client.request(endpoint)
        userid = f"{settings.proxmox_user}!{settings.proxmox_token_name}"
        return {"userid": userid, "permissions": permissions}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_guest_ips(node: str, vmid: str) -> dict[str, Any]:
    """Discover a running VM's IP addresses via the QEMU guest agent (qemu only).

    Args:
        node: Node where the VM is located.
        vmid: VM ID.

    Returns:
        The guest-agent network interfaces payload.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    client = await _client()
    try:
        return await client.request(f"/nodes/{n}/qemu/{v}/agent/network-get-interfaces")
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_rrd_data(
    node: str, vmid: str = "", type: str = "qemu", timeframe: str = "day"
) -> dict[str, Any]:
    """Get historical performance metrics (CPU, memory, disk, network) for a guest or node.

    Args:
        node: Node name.
        vmid: optional VM/container ID (omit for node-level metrics).
        type: guest type (when vmid is given).
        timeframe: time window ('hour', 'day', 'week', 'month', 'year').

    Returns:
        ``rrddata``: the time-series samples.
    """
    n = validate_node(node)
    if timeframe not in ("hour", "day", "week", "month", "year"):
        timeframe = "day"
    client = await _client()
    try:
        if vmid:
            v, t = validate_vmid(vmid), validate_guest_type(type)
            endpoint = f"/nodes/{n}/{t}/{v}/rrddata?timeframe={timeframe}"
        else:
            endpoint = f"/nodes/{n}/rrddata?timeframe={timeframe}"
        return {"rrddata": await client.request(endpoint)}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_pools(poolid: str = "") -> dict[str, Any]:
    """List resource pools and their members.

    Args:
        poolid: optional specific pool to show members of.

    Returns:
        ``pools``: the pool list (or one pool's members).
    """
    client = await _client()
    try:
        if poolid:
            return {"pool": await client.request(f"/pools/{poolid}")}
        return {"pools": await client.request("/pools")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_ha_resources() -> dict[str, Any]:
    """List High Availability resources and their configured state.

    Returns:
        ``ha_resources``: the HA resource list.
    """
    client = await _client()
    try:
        return {"ha_resources": await client.request("/cluster/ha/resources")}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_get_firewall_rules(
    level: str = "cluster", node: str = "", vmid: str = "", type: str = "qemu"
) -> dict[str, Any]:
    """List firewall rules at the cluster level, a node, or a specific guest.

    Args:
        level: which ruleset to read ('cluster', 'node', or 'guest').
        node: Node name (required for level=node or level=guest).
        vmid: VM/container ID (required for level=guest).
        type: guest type (for level=guest).

    Returns:
        ``firewall_rules``: the ruleset.
    """
    client = await _client()
    try:
        if level == "node":
            n = validate_node(node)
            endpoint = f"/nodes/{n}/firewall/rules"
        elif level == "guest":
            n, v, t = validate_node(node), validate_vmid(vmid), validate_guest_type(type)
            endpoint = f"/nodes/{n}/{t}/{v}/firewall/rules"
        else:
            endpoint = "/cluster/firewall/rules"
        return {"firewall_rules": await client.request(endpoint)}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Advanced (elevated): migrate / template / cloud-init
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_migrate_vm(
    node: str, vmid: str, target: str, type: str = "qemu", online: bool = False, wait: bool = False
) -> dict[str, Any]:
    """Migrate a VM or LXC container to another node (requires elevated permissions).

    Args:
        node: Current node hosting the guest.
        vmid: VM/container ID.
        target: Destination node.
        type: guest type ('qemu' or 'lxc').
        online: live-migrate a running VM (QEMU) / restart migration (LXC).
        wait: wait for the migration task to finish.

    Returns:
        The task UPID (or final status if wait=true).
    """
    _require_elevated()
    n, v, t = validate_node(node), validate_vmid(vmid), validate_guest_type(type)
    target_n = validate_node(target)
    body: dict[str, Any] = {"target": target_n}
    if online:
        body["online"] = 1
    client = await _client()
    try:
        upid = await client.request(f"/nodes/{n}/{t}/{v}/migrate", "POST", body)
        if wait and isinstance(upid, str) and upid.startswith("UPID:"):
            import asyncio
            import time

            path = f"/nodes/{n}/tasks/{upid}/status"
            status = await client.request(path)
            start = time.monotonic()
            while status and status.get("exitstatus") is None and (time.monotonic() - start) < 600:
                await asyncio.sleep(2)
                status = await client.request(path)
            return {"upid": upid, "status": status}
        return {"upid": upid}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_convert_to_template(node: str, vmid: str, type: str = "qemu") -> dict[str, Any]:
    """Convert a VM or LXC container into a template (irreversible; requires elevated permissions).

    Args:
        node: Node where the guest is located.
        vmid: VM/container ID.
        type: guest type ('qemu' or 'lxc').

    Returns:
        The API result.
    """
    _require_elevated()
    n, v, t = validate_node(node), validate_vmid(vmid), validate_guest_type(type)
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/{t}/{v}/template", "POST", {})}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_set_cloudinit(
    node: str,
    vmid: str,
    ciuser: str = "",
    cipassword: str = "",
    sshkeys: str = "",
    ipconfig0: str = "",
    nameserver: str = "",
    searchdomain: str = "",
) -> dict[str, Any]:
    """Set cloud-init options on a QEMU VM (requires elevated permissions).

    Args:
        node: Node where the VM is located.
        vmid: VM ID.
        ciuser: default cloud-init user.
        cipassword: password for the cloud-init user.
        sshkeys: public SSH keys (newline separated).
        ipconfig0: IP config for net0 (ip=192.168.1.50/24,gw=... or ip=dhcp).
        nameserver: DNS nameserver(s).
        searchdomain: DNS search domain.

    Returns:
        The API result.
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    body: dict[str, Any] = {}
    for key, val in (
        ("ciuser", ciuser),
        ("cipassword", cipassword),
        ("sshkeys", sshkeys),
        ("ipconfig0", ipconfig0),
        ("nameserver", nameserver),
        ("searchdomain", searchdomain),
    ):
        if val:
            body[key] = val
    client = await _client()
    try:
        return {"result": await client.request(f"/nodes/{n}/qemu/{v}/config", "PUT", body)}
    finally:
        await client.aclose()


@mcp.tool()
async def proxmox_execute_vm_command(
    node: str, vmid: str, command: str, type: str = "qemu", wait: bool = True
) -> dict[str, Any]:
    """Execute a shell command on a VM via the QEMU guest agent (requires elevated permissions).

    Args:
        node: Node where the VM is located.
        vmid: VM ID.
        command: shell command to execute.
        type: guest type ('qemu' only — LXC has no API exec endpoint).
        wait: poll the guest agent for stdout/exit code (default true).

    Returns:
        The PID (and, when wait=true, stdout/stderr/exit code).
    """
    _require_elevated()
    n, v = validate_node(node), validate_vmid(vmid)
    if validate_guest_type(type) != "qemu":
        raise ProxmoxError(
            "Command execution is only supported for QEMU VMs via the guest agent. "
            "For containers use SSH or `pct exec` on the host."
        )
    cmd = validate_command(command)
    import asyncio
    import time

    client = await _client()
    try:
        argv = cmd.split()
        result = await client.request(f"/nodes/{n}/qemu/{v}/agent/exec", "POST", {"command": argv})
        pid = (result or {}).get("pid") if isinstance(result, dict) else None
        if not wait or pid is None:
            return {"vmid": v, "command": cmd, "pid": pid, "exited": False}
        status_path = f"/nodes/{n}/qemu/{v}/agent/exec-status?pid={pid}"
        status = await client.request(status_path) or {}
        start = time.monotonic()
        while not status.get("exited") and (time.monotonic() - start) < 30:
            await asyncio.sleep(1)
            status = await client.request(status_path) or {}
        return {
            "vmid": v,
            "command": cmd,
            "pid": pid,
            "exited": bool(status.get("exited")),
            "exitcode": status.get("exitcode"),
            "stdout": status.get("out-data", ""),
            "stderr": status.get("err-data", ""),
            "signal": status.get("signal"),
        }
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Terraform generation (read-only, pure computation)
# ---------------------------------------------------------------------------


@mcp.tool()
async def proxmox_generate_terraform(
    node: str = "", vmid: str = "", type: str = "all", include_provider: bool = True
) -> dict[str, Any]:
    """Generate Terraform HCL (bpg/proxmox provider) with import blocks for existing guests.

    Args:
        node: optional node filter.
        vmid: optional single VM/container ID.
        type: guest type filter ('qemu', 'lxc', or 'all').
        include_provider: include the terraform/provider scaffolding block.

    Returns:
        ``hcl``: the generated Terraform HCL, and ``resources``: the imported guests.
    """
    client = await _client()
    try:
        guests: list[dict[str, Any]] = []
        if vmid:
            v = validate_vmid(vmid)
            n = validate_node(node)
            t = validate_guest_type(type, "qemu")
            cfg = await client.request(f"/nodes/{n}/{t}/{v}/config") or {}
            guests = [{"node": n, "vmid": v, "type": t, "config": cfg}]
        else:
            safe_node = validate_node(node) if node else None
            nodes = (
                [{"node": safe_node}]
                if safe_node
                else [{"node": nd["node"]} for nd in (await client.request("/nodes") or [])]
            )
            for nd in nodes:
                n = nd["node"]
                if type in ("all", "qemu"):
                    for vm in await client.request(f"/nodes/{n}/qemu") or []:
                        cfg = await client.request(f"/nodes/{n}/qemu/{vm['vmid']}/config") or {}
                        guests.append(
                            {"node": n, "vmid": str(vm["vmid"]), "type": "qemu", "config": cfg}
                        )
                if type in ("all", "lxc"):
                    for ct in await client.request(f"/nodes/{n}/lxc") or []:
                        cfg = await client.request(f"/nodes/{n}/lxc/{ct['vmid']}/config") or {}
                        guests.append(
                            {"node": n, "vmid": str(ct["vmid"]), "type": "lxc", "config": cfg}
                        )

        lines: list[str] = []
        if include_provider:
            lines += [
                "terraform {",
                "  required_providers {",
                "    proxmox = {",
                '      source = "bpg/proxmox"',
                "    }",
                "  }",
                "}",
                "",
            ]
        for g in guests:
            if g["type"] == "qemu":
                rtype = "proxmox_virtual_environment_vm"
            else:
                rtype = "proxmox_virtual_environment_container"
            name = (g["config"].get("name") or f"vm{g['vmid']}").replace("-", "_").replace(".", "_")
            rid = f"{rtype}.{name}"
            lines += [
                "import {",
                f"  to = {rid}",
                f'  id = "{g["node"]}/{g["vmid"]}"',
                "}",
                "",
            ]
        return {"hcl": "\n".join(lines), "resources": [g["type"] for g in guests]}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point for the MCP server."""
    serve(mcp, default_port=3001)


if __name__ == "__main__":
    main()
