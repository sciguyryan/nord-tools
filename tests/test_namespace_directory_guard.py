"""Directory authority preconditions must refuse ambiguous or hostile paths."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_namespace_directory_guard import (
    NamespaceDirectoryError,
    require_trusted_netns_directory,
)
from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace, OwnershipError


def _info(mode=0o40755, uid=0, dev=1, ino=2):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_dev=dev, st_ino=ino)


@pytest.mark.parametrize(
    "opened,named",
    [
        (_info(mode=0o40777), _info()),
        (_info(uid=1000), _info()),
        (_info(), _info(ino=3)),
        (_info(), _info(mode=0o120777)),
    ],
)
def test_unsafe_directory_is_rejected_and_descriptor_closed(opened, named):
    with (
        patch("nord_tools_internal.nordvpn_namespace_directory_guard.os.open", return_value=7),
        patch("nord_tools_internal.nordvpn_namespace_directory_guard.os.fstat", return_value=opened),
        patch("nord_tools_internal.nordvpn_namespace_directory_guard.os.stat", return_value=named),
        patch("nord_tools_internal.nordvpn_namespace_directory_guard.os.close") as close,
    ):
        with pytest.raises(NamespaceDirectoryError):
            require_trusted_netns_directory(Path("/run/netns"))
        close.assert_called_once_with(7)


def test_missing_directory_is_rejected():
    with (
        patch("nord_tools_internal.nordvpn_namespace_directory_guard.os.open", side_effect=FileNotFoundError),
        pytest.raises(NamespaceDirectoryError),
    ):
        require_trusted_netns_directory()


def test_retirement_refuses_untrusted_directory_before_commands():
    owned = OwnedNamespace("nt-abcdefgh", 8, 1, 2)
    with (
        patch(
            "nord_tools_internal.nordvpn_namespace_ownership.require_trusted_netns_directory",
            side_effect=NamespaceDirectoryError("unsafe"),
        ),
        patch("nord_tools_internal.nordvpn_namespace_ownership._command") as command,
    ):
        with pytest.raises(OwnershipError, match="not trusted"):
            owned.retire()
        command.assert_not_called()
