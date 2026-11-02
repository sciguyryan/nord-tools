"""Host-interface identity checks and indexed netlink mutation boundary."""

from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_cleanup_executor import _real_kernel
from nord_tools_internal.nordvpn_link_netlink import LinkMutationError
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError


@pytest.mark.parametrize("name,index", [("nt-host", 0), ("nt-host", -1), ("../other", 4), ("nt-host", True)])
def test_invalid_identity_never_reaches_kernel(name, index):
    with patch("nord_tools_internal.nordvpn_link_netlink.delete_link_by_index") as delete:
        with pytest.raises(ProvisioningUncertainError):
            _real_kernel().delete_host_interface(name, index)
        delete.assert_not_called()


@pytest.mark.parametrize("actual_name,actual_index", [("unrelated", 5), ("nt-host", 9)])
def test_changed_identity_never_reaches_kernel(actual_name, actual_index):
    with (
        patch("socket.if_indextoname", return_value=actual_name),
        patch("socket.if_nametoindex", return_value=actual_index),
        patch("nord_tools_internal.nordvpn_link_netlink.delete_link_by_index") as delete,
    ):
        with pytest.raises(ProvisioningUncertainError, match="changed identity"):
            _real_kernel().delete_host_interface("nt-host", 5)
        delete.assert_not_called()


def test_matching_identity_uses_indexed_netlink():
    with (
        patch("socket.if_indextoname", return_value="nt-host"),
        patch("socket.if_nametoindex", return_value=5),
        patch("nord_tools_internal.nordvpn_link_netlink.delete_link_by_index") as delete,
    ):
        _real_kernel().delete_host_interface("nt-host", 5)
        delete.assert_called_once_with(5)


def test_kernel_refusal_is_uncertain():
    with (
        patch("socket.if_indextoname", return_value="nt-host"),
        patch("socket.if_nametoindex", return_value=5),
        patch(
            "nord_tools_internal.nordvpn_link_netlink.delete_link_by_index", side_effect=LinkMutationError("refused")
        ),
        pytest.raises(ProvisioningUncertainError, match="could not be deleted"),
    ):
        _real_kernel().delete_host_interface("nt-host", 5)
