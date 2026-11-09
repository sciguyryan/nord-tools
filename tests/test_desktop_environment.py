"""Desktop environment forwarding is explicit, minimal and endpoint-verified."""

from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from nord_tools_internal import nordvpn_desktop_environment as desktop
from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError


def account():
    return SimpleNamespace(pw_dir="/home/example", pw_name="example")


def source(**overrides):
    values = {
        "LANG": "en_GB.UTF-8",
        "DISPLAY": ":0",
        "WAYLAND_DISPLAY": "wayland-1",
        "XAUTHORITY": "/run/user/1000/xauth_test",
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
        "XDG_SESSION_TYPE": "wayland",
        "XDG_CURRENT_DESKTOP": "KDE",
        "LD_PRELOAD": "/tmp/untrusted.so",
    }
    values.update(overrides)
    return values


def test_non_desktop_environment_is_minimal():
    with patch.object(desktop.pwd, "getpwuid", return_value=account()):
        environment = desktop.application_environment(1000, source=source())
    assert environment == {
        "HOME": "/home/example",
        "USER": "example",
        "LOGNAME": "example",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "en_GB.UTF-8",
    }


def test_desktop_environment_forwards_verified_wayland_x11_and_dbus():
    runtime = Path("/run/user/1000")
    with (
        patch.object(desktop.pwd, "getpwuid", return_value=account()),
        patch.object(desktop, "_owned_runtime_directory", return_value=runtime),
        patch.object(desktop, "_owned_socket") as socket_check,
        patch.object(desktop, "_xauthority", return_value="/run/user/1000/xauth_test"),
    ):
        environment = desktop.application_environment(1000, desktop_session=True, source=source())
    assert environment["WAYLAND_DISPLAY"] == "wayland-1"
    assert environment["DISPLAY"] == ":0"
    assert environment["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1000/bus"
    assert environment["XDG_CURRENT_DESKTOP"] == "KDE"
    assert "LD_PRELOAD" not in environment
    assert [call.args[0] for call in socket_check.call_args_list] == [
        runtime / "bus",
        runtime / "wayland-1",
        Path("/tmp/.X11-unix/X0"),
    ]


@pytest.mark.parametrize(
    ("changed", "message"),
    [
        ({"DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/other"}, "D-Bus address"),
        ({"WAYLAND_DISPLAY": "../wayland-1"}, "WAYLAND_DISPLAY"),
        ({"DISPLAY": "example.org:0"}, "local X11"),
        ({"XDG_SESSION_TYPE": "tty"}, "wayland or x11"),
    ],
)
def test_desktop_environment_rejects_untrusted_session_values(changed, message):
    runtime = Path("/run/user/1000")
    with (
        patch.object(desktop.pwd, "getpwuid", return_value=account()),
        patch.object(desktop, "_owned_runtime_directory", return_value=runtime),
        patch.object(desktop, "_owned_socket"),
        patch.object(desktop, "_xauthority", return_value="/run/user/1000/xauth_test"),
        pytest.raises(ConsumerReferenceError, match=message),
    ):
        desktop.application_environment(1000, desktop_session=True, source=source(**changed))


def test_runtime_directory_requires_target_ownership_and_safe_mode():
    observed = SimpleNamespace(st_mode=stat.S_IFDIR | 0o722, st_uid=1000)
    with (
        patch.object(Path, "lstat", return_value=observed),
        pytest.raises(ConsumerReferenceError, match="permissions"),
    ):
        desktop._owned_runtime_directory(1000, source())


def test_desktop_endpoint_must_be_target_owned_socket():
    observed = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000)
    with (
        patch.object(desktop, "_lstat", return_value=observed),
        pytest.raises(ConsumerReferenceError, match="not a socket"),
    ):
        desktop._owned_socket(Path("/run/user/1000/bus"), 1000, "desktop D-Bus socket")
