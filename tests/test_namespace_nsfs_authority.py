"""Linux nsfs attestation is required before trusting a held namespace handle."""

from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_namespace_ownership import (
    OwnedNamespace,
    OwnershipError,
    _require_network_namespace,
)


def test_nsfs_attestation_accepts_network_namespace():
    with patch("nord_tools_internal.nordvpn_namespace_ownership.fcntl.ioctl", return_value=0x40000000) as ioctl:
        _require_network_namespace(19)
    ioctl.assert_called_once_with(19, 0xB703)


@pytest.mark.parametrize("kind", [0, 0x20000000, -1])
def test_nsfs_attestation_rejects_other_namespace_types(kind):
    with (
        patch("nord_tools_internal.nordvpn_namespace_ownership.fcntl.ioctl", return_value=kind),
        pytest.raises(OwnershipError, match="does not identify a network namespace"),
    ):
        _require_network_namespace(19)


def test_nsfs_attestation_refuses_ioctl_failure():
    with (
        patch("nord_tools_internal.nordvpn_namespace_ownership.fcntl.ioctl", side_effect=OSError("not nsfs")),
        pytest.raises(OwnershipError, match="not a verifiable kernel namespace"),
    ):
        _require_network_namespace(19)


def test_namespace_verification_refuses_impostor_before_kernel_discovery():
    from types import SimpleNamespace

    entry = SimpleNamespace(st_mode=0o100600, st_dev=3, st_ino=4)
    owned = OwnedNamespace("nt-abcdefgh", 19, 3, 4)
    with (
        patch("nord_tools_internal.nordvpn_namespace_ownership.os.fstat", return_value=entry),
        patch("nord_tools_internal.nordvpn_namespace_ownership.os.stat", return_value=entry),
        patch("nord_tools_internal.nordvpn_namespace_ownership.fcntl.ioctl", return_value=0x20000000),
        patch("nord_tools_internal.nordvpn_namespace_ownership._namespace_names") as discovery,
    ):
        with pytest.raises(OwnershipError, match="does not identify a network namespace"):
            owned.verify()
        discovery.assert_not_called()
