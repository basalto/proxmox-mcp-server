"""Tests for the input-validation helpers."""

import pytest

from proxmox_mcp.client import ProxmoxError
from proxmox_mcp.main import (
    validate_bridge,
    validate_command,
    validate_disk,
    validate_guest_type,
    validate_network,
    validate_node,
    validate_snapshot,
    validate_storage,
    validate_upid,
    validate_vmid,
)


def test_validate_node_ok():
    assert validate_node("server1") == "server1"
    assert validate_node("k3s-1") == "k3s-1"


def test_validate_node_rejects_bad_chars():
    with pytest.raises(ProxmoxError):
        validate_node("server/1")


def test_validate_vmid():
    assert validate_vmid("105") == "105"
    assert validate_vmid(105) == "105"
    with pytest.raises(ProxmoxError):
        validate_vmid("99")  # below 100
    with pytest.raises(ProxmoxError):
        validate_vmid("abc")


def test_validate_guest_type():
    assert validate_guest_type("qemu") == "qemu"
    assert validate_guest_type("lxc") == "lxc"
    assert validate_guest_type(None, "qemu") == "qemu"
    with pytest.raises(ProxmoxError):
        validate_guest_type("bogus")


def test_validate_storage():
    assert validate_storage("local-lvm") == "local-lvm"
    with pytest.raises(ProxmoxError):
        validate_storage("bad/name")


def test_validate_snapshot():
    assert validate_snapshot("pre-upgrade") == "pre-upgrade"
    with pytest.raises(ProxmoxError):
        validate_snapshot("bad name")


def test_validate_disk():
    assert validate_disk("scsi0") == "scsi0"
    assert validate_disk("rootfs") == "rootfs"
    with pytest.raises(ProxmoxError):
        validate_disk("scsi99")  # out of range


def test_validate_network():
    assert validate_network("net0") == "net0"
    assert validate_network("net31") == "net31"
    with pytest.raises(ProxmoxError):
        validate_network("net32")


def test_validate_bridge():
    assert validate_bridge("vmbr0") == "vmbr0"
    with pytest.raises(ProxmoxError):
        validate_bridge("bad bridge")


def test_validate_command_rejects_metachars():
    assert validate_command("ls -la") == "ls -la"
    with pytest.raises(ProxmoxError):
        validate_command("ls; rm -rf /")


def test_validate_upid():
    upid = "UPID:pve1:0000ABCD:12345678:5F3A1B2C:vzdump:100:root@pam:"
    assert validate_upid(upid) == upid
    with pytest.raises(ProxmoxError):
        validate_upid("not-a-upid")
