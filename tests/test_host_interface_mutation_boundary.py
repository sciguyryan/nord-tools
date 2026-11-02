"""Host-interface identity checks at the production cleanup command boundary."""

from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_cleanup_executor import _real_kernel
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError


@pytest.mark.parametrize("name,index", [("nt-host", 0), ("nt-host", -1), ("../other", 4), ("nt-host", True)])
def test_invalid_identity_never_reaches_ip(name, index):
    with patch("subprocess.run") as command:
        with pytest.raises(ProvisioningUncertainError):
            _real_kernel().delete_host_interface(name, index)
        command.assert_not_called()


def test_reused_index_never_reaches_ip():
    with (
        patch("socket.if_indextoname", return_value="unrelated"),
        patch("socket.if_nametoindex", return_value=5),
        patch("subprocess.run") as command,
    ):
        with pytest.raises(ProvisioningUncertainError, match="changed identity"):
            _real_kernel().delete_host_interface("nt-host", 5)
        command.assert_not_called()


def test_renamed_link_never_reaches_ip():
    with (
        patch("socket.if_indextoname", return_value="nt-host"),
        patch("socket.if_nametoindex", return_value=9),
        patch("subprocess.run") as command,
    ):
        with pytest.raises(ProvisioningUncertainError, match="changed identity"):
            _real_kernel().delete_host_interface("nt-host", 5)
        command.assert_not_called()


def test_matching_identity_allows_indexed_command():
    with (
        patch("socket.if_indextoname", return_value="nt-host"),
        patch("socket.if_nametoindex", return_value=5),
        patch("subprocess.run") as command,
    ):
        command.return_value.returncode = 0
        _real_kernel().delete_host_interface("nt-host", 5)
        command.assert_called_once()
        assert command.call_args.args[0] == ["ip", "link", "del", "dev", "5"]
