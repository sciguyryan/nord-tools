"""Refusal paths must never leak a privileged namespace descriptor."""

from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_cleanup_executor import _real_kernel
from nord_tools_internal.nordvpn_namespace_ownership import OwnershipError
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError


def test_refused_namespace_retirement_releases_open_descriptor():
    kernel = _real_kernel()
    with (
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.open", return_value=73),
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.close") as close,
        patch(
            "nord_tools_internal.nordvpn_cleanup_executor.OwnedNamespace.verify", side_effect=OwnershipError("changed")
        ),
    ):
        with pytest.raises(ProvisioningUncertainError, match="recorded owner binding"):
            kernel.delete_namespace("nt-abcdefgh", {"device": 1, "inode": 2})
        close.assert_called_once_with(73)


def test_successful_namespace_retirement_closes_descriptor_once():
    kernel = _real_kernel()
    with (
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.open", return_value=73),
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.close") as close,
        patch("nord_tools_internal.nordvpn_cleanup_executor.OwnedNamespace.verify"),
        patch("nord_tools_internal.nordvpn_namespace_ownership.require_trusted_netns_directory"),
        patch("nord_tools_internal.nordvpn_namespace_ownership._command", side_effect=["", ""]),
    ):
        kernel.delete_namespace("nt-abcdefgh", {"device": 1, "inode": 2})
        close.assert_called_once_with(73)


def test_namespace_replacement_before_retirement_refuses_and_closes_descriptor():
    """A replacement observed at the final ownership check must not be deleted."""
    kernel = _real_kernel()
    with (
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.open", return_value=73),
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.close") as close,
        patch("nord_tools_internal.nordvpn_namespace_ownership.require_trusted_netns_directory"),
        patch(
            "nord_tools_internal.nordvpn_namespace_ownership.OwnedNamespace.verify",
            side_effect=[None, OwnershipError("replaced")],
        ),
        patch("nord_tools_internal.nordvpn_namespace_ownership._command") as command,
        pytest.raises(ProvisioningUncertainError, match="recorded owner binding"),
    ):
        kernel.delete_namespace("nt-abcdefgh", {"device": 1, "inode": 2})
    command.assert_not_called()
    close.assert_called_once_with(73)


def test_reused_interface_index_refuses_before_netlink_mutation():
    """An observed index now belonging to another name cannot be retired."""
    kernel = _real_kernel()
    with (
        patch("socket.if_indextoname", return_value="foreign-link"),
        patch("socket.if_nametoindex", return_value=42),
        patch("nord_tools_internal.nordvpn_link_netlink.delete_link_by_index") as delete,
        pytest.raises(ProvisioningUncertainError, match="changed identity"),
    ):
        kernel.delete_host_interface("nt-host-link", 42)
    delete.assert_not_called()


@pytest.mark.parametrize("name", ["../foreign", "nt-abcdefgh/other", "nt-ABCDEFGH", "", "nt-abc", None])
def test_invalid_namespace_name_is_refused_before_open(name):
    kernel = _real_kernel()
    with (
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.open") as opening,
        pytest.raises(ProvisioningUncertainError, match="name is invalid"),
    ):
        kernel.delete_namespace(name, {"device": 1, "inode": 2})
    opening.assert_not_called()


@pytest.mark.parametrize("binding", [{}, {"device": True, "inode": 2}, {"device": -1, "inode": 2}])
def test_invalid_namespace_binding_is_refused_before_open(binding):
    kernel = _real_kernel()
    with (
        patch("nord_tools_internal.nordvpn_cleanup_executor.os.open") as opening,
        pytest.raises(ProvisioningUncertainError, match="binding is invalid"),
    ):
        kernel.delete_namespace("nt-abcdefgh", binding)
    opening.assert_not_called()
