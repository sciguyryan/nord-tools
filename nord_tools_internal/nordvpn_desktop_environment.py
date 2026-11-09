"""Validated environment construction for registered desktop applications.

Desktop mode is explicit. It forwards a small set of session values after
checking the target user's runtime directory, display sockets, D-Bus socket
and Xauthority file. Privileged caller variables outside the allowlist never
reach the application.
"""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import re
import stat
from typing import Mapping

from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError


_DISPLAY = re.compile(r":(?P<number>[0-9]+)(?:\.[0-9]+)?\Z")
_WAYLAND_DISPLAY = re.compile(r"wayland-[A-Za-z0-9_.-]+\Z")
_OPTIONAL_DESKTOP_KEYS = (
    "DESKTOP_SESSION",
    "DESKTOP_STARTUP_ID",
    "KDE_FULL_SESSION",
    "KDE_SESSION_VERSION",
    "XDG_ACTIVATION_TOKEN",
    "XDG_CURRENT_DESKTOP",
    "XDG_SESSION_DESKTOP",
)


def _safe_value(name: str, value: str, *, maximum: int = 4096) -> str:
    if not value or len(value) > maximum or any(ord(character) < 32 for character in value):
        raise ConsumerReferenceError(f"desktop environment {name} is empty, too long or contains controls")
    return value


def _lstat(path: Path, *, description: str) -> os.stat_result:
    try:
        result = path.lstat()
    except OSError as exc:
        raise ConsumerReferenceError(f"cannot inspect {description}: {exc}") from exc
    if stat.S_ISLNK(result.st_mode):
        raise ConsumerReferenceError(f"{description} must not be a symbolic link")
    return result


def _owned_runtime_directory(uid: int, source: Mapping[str, str]) -> Path:
    expected = Path("/run/user") / str(uid)
    supplied = source.get("XDG_RUNTIME_DIR")
    if supplied != str(expected):
        raise ConsumerReferenceError(f"desktop XDG_RUNTIME_DIR must be {expected}")
    observed = _lstat(expected, description="desktop runtime directory")
    if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != uid or observed.st_mode & 0o022:
        raise ConsumerReferenceError("desktop runtime directory ownership or permissions are unsafe")
    return expected


def _owned_socket(path: Path, uid: int, description: str) -> None:
    observed = _lstat(path, description=description)
    if not stat.S_ISSOCK(observed.st_mode) or observed.st_uid != uid:
        raise ConsumerReferenceError(f"{description} is not a socket owned by the target user")


def _xauthority(source: Mapping[str, str], uid: int) -> str:
    value = _safe_value("XAUTHORITY", source.get("XAUTHORITY", ""))
    path = Path(value)
    if not path.is_absolute():
        raise ConsumerReferenceError("desktop XAUTHORITY must be an absolute path")
    observed = _lstat(path, description="desktop Xauthority file")
    if not stat.S_ISREG(observed.st_mode) or observed.st_uid != uid or observed.st_mode & 0o022:
        raise ConsumerReferenceError("desktop Xauthority file ownership, type or permissions are unsafe")
    return value


def _base_environment(uid: int, source: Mapping[str, str]) -> dict[str, str]:
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise ConsumerReferenceError("application launch target uid does not exist") from exc
    environment = {
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": _safe_value("LANG", source.get("LANG", "C.UTF-8")),
    }
    for name, value in source.items():
        if value and (name == "LANGUAGE" or name.startswith("LC_")):
            environment[name] = _safe_value(name, value)
    return environment


def application_environment(
    uid: int,
    *,
    desktop_session: bool = False,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a minimal child environment, with validated desktop state on request."""
    source = os.environ if source is None else source
    environment = _base_environment(uid, source)
    if not desktop_session:
        return environment

    runtime = _owned_runtime_directory(uid, source)
    session_type = _safe_value("XDG_SESSION_TYPE", source.get("XDG_SESSION_TYPE", ""))
    if session_type not in {"wayland", "x11"}:
        raise ConsumerReferenceError("desktop XDG_SESSION_TYPE must be wayland or x11")
    environment["XDG_RUNTIME_DIR"] = str(runtime)
    environment["XDG_SESSION_TYPE"] = session_type

    bus_address = _safe_value("DBUS_SESSION_BUS_ADDRESS", source.get("DBUS_SESSION_BUS_ADDRESS", ""))
    expected_bus = f"unix:path={runtime / 'bus'}"
    if bus_address != expected_bus:
        raise ConsumerReferenceError("desktop D-Bus address must name the target user's runtime bus")
    _owned_socket(runtime / "bus", uid, "desktop D-Bus socket")
    environment["DBUS_SESSION_BUS_ADDRESS"] = bus_address

    wayland = source.get("WAYLAND_DISPLAY")
    if wayland:
        wayland = _safe_value("WAYLAND_DISPLAY", wayland)
        if _WAYLAND_DISPLAY.fullmatch(wayland) is None:
            raise ConsumerReferenceError("desktop WAYLAND_DISPLAY must be a runtime-directory socket name")
        _owned_socket(runtime / wayland, uid, "desktop Wayland socket")
        environment["WAYLAND_DISPLAY"] = wayland
    elif session_type == "wayland":
        raise ConsumerReferenceError("Wayland desktop launch requires WAYLAND_DISPLAY")

    display = source.get("DISPLAY")
    if display:
        display = _safe_value("DISPLAY", display)
        match = _DISPLAY.fullmatch(display)
        if match is None:
            raise ConsumerReferenceError("desktop DISPLAY must name a local X11 display")
        _owned_socket(Path("/tmp/.X11-unix") / f"X{match.group('number')}", uid, "desktop X11 socket")
        environment["DISPLAY"] = display
        environment["XAUTHORITY"] = _xauthority(source, uid)
    elif session_type == "x11":
        raise ConsumerReferenceError("X11 desktop launch requires DISPLAY")

    for name in _OPTIONAL_DESKTOP_KEYS:
        value = source.get(name)
        if value:
            environment[name] = _safe_value(name, value)
    return environment
