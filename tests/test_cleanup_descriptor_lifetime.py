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
