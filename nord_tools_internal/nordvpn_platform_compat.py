"""Conservative production-network platform compatibility preflight.

Production provisioning depends on specific Linux command output contracts.
Recognised version strings are necessary but not sufficient: this module also
checks the read-only JSON and field-selection behaviours consumed by the
production readback code. Unknown versions remain unsupported until their
behaviour has passed the privileged acceptance matrix.
"""

from __future__ import annotations

import json
from pathlib import Path
import platform
import re
import stat
import subprocess
from typing import Callable


class PlatformCompatibilityError(RuntimeError):
    """The host cannot establish the accepted network-tooling contract."""


SUPPORTED_KERNEL = re.compile(r"7\.2\.\d+-arch\d+-\d+\Z")
SUPPORTED_VERSIONS = {
    "iproute2": "7.3.0",
    "nftables": "1.1.7",
    "wireguard_tools": "1.0.20260223",
}
_VERSION_PATTERNS = {
    "iproute2": re.compile(r"\biproute2-(\d+(?:\.\d+){1,2})\b"),
    "nftables": re.compile(r"\bnftables v(\d+(?:\.\d+){1,2})\b"),
    "wireguard_tools": re.compile(r"\bwireguard-tools v(\d+(?:\.\d+){1,2})\b"),
}
_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")


def _run(arguments: list[str], runner: Callable = subprocess.run) -> str:
    try:
        result = runner(arguments, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PlatformCompatibilityError(f"platform command unavailable: {arguments[0]}") from exc
    if result.returncode:
        raise PlatformCompatibilityError(f"platform command failed: {arguments[0]}")
    return (result.stdout or "") + (result.stderr or "")


def _version(name: str, arguments: list[str], runner: Callable) -> str:
    output = _run(arguments, runner)
    match = _VERSION_PATTERNS[name].search(output)
    if match is None:
        raise PlatformCompatibilityError(f"unrecognised {name} version output")
    version = match.group(1)
    if version != SUPPORTED_VERSIONS[name]:
        raise PlatformCompatibilityError(
            f"unsupported {name} version {version}; accepted version is {SUPPORTED_VERSIONS[name]}"
        )
    return version


def _json(arguments: list[str], runner: Callable) -> object:
    try:
        return json.loads(_run(arguments, runner))
    except (TypeError, ValueError) as exc:
        raise PlatformCompatibilityError(f"invalid JSON from platform command: {arguments[0]}") from exc


def verify_supported_network_platform(
    *,
    system: Callable[[], str] = platform.system,
    release: Callable[[], str] = platform.release,
    runner: Callable = subprocess.run,
    resolver_root: Path = Path("/etc/netns"),
    resolver_owner: tuple[int, int] = (0, 0),
) -> dict:
    """Verify the accepted Linux and network-tool contract without mutation."""
    if system() != "Linux":
        raise PlatformCompatibilityError("production network provisioning is supported on Linux only")
    kernel = release()
    if not isinstance(kernel, str) or SUPPORTED_KERNEL.fullmatch(kernel) is None:
        raise PlatformCompatibilityError(
            f"unsupported kernel release {kernel!r}; accepted profile is Linux 7.2.x-arch1"
        )
    versions = {
        "iproute2": _version("iproute2", ["ip", "-Version"], runner),
        "nftables": _version("nftables", ["nft", "--version"], runner),
        "wireguard_tools": _version("wireguard_tools", ["wg", "--version"], runner),
    }

    links = _json(["ip", "-j", "link", "show", "dev", "lo"], runner)
    if (
        not isinstance(links, list)
        or len(links) != 1
        or not isinstance(links[0], dict)
        or links[0].get("ifname") != "lo"
        or type(links[0].get("ifindex")) is not int
    ):
        raise PlatformCompatibilityError("iproute2 link JSON does not match the accepted schema")
    for family in ("-4", "-6"):
        routes = _json(["ip", "-j", family, "route", "show", "table", "main"], runner)
        if not isinstance(routes, list) or any(not isinstance(item, dict) for item in routes):
            raise PlatformCompatibilityError(f"iproute2 {family} route JSON does not match the accepted schema")

    ruleset = _json(["nft", "-j", "list", "ruleset"], runner)
    if (
        not isinstance(ruleset, dict)
        or set(ruleset) != {"nftables"}
        or not isinstance(ruleset["nftables"], list)
        or any(not isinstance(item, dict) for item in ruleset["nftables"])
    ):
        raise PlatformCompatibilityError("nftables JSON does not match the accepted schema")

    interfaces = _run(["wg", "show", "all", "interfaces"], runner).split()
    if any(_INTERFACE.fullmatch(name) is None for name in interfaces):
        raise PlatformCompatibilityError("WireGuard interface readback is malformed")

    try:
        resolver = resolver_root.lstat()
    except OSError as exc:
        raise PlatformCompatibilityError("namespace resolver root is unavailable") from exc
    if (
        not stat.S_ISDIR(resolver.st_mode)
        or (resolver.st_uid, resolver.st_gid) != resolver_owner
        or resolver.st_mode & 0o022
        or resolver_root.is_symlink()
    ):
        raise PlatformCompatibilityError("namespace resolver root is not trusted")

    return {
        "version": 1,
        "mode": "supported_network_platform",
        "platform": "Linux",
        "kernel": kernel,
        "tools": versions,
        "capabilities": [
            "iproute2_link_and_dual_stack_route_json",
            "nftables_ruleset_json",
            "wireguard_safe_interface_readback",
            "trusted_namespace_resolver_root",
        ],
        "network_changes_applied": False,
    }
