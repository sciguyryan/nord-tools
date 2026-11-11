"""Read-only preflight for supported production operating modes."""

from __future__ import annotations

import os
import shutil
import sys
from typing import Callable

from nord_tools_internal.nordvpn_platform_compat import verify_supported_network_platform
from nord_tools_internal.nordvpn_registry import RegistryError


MIN_PYTHON = (3, 10)
SUPPORTED_MODES = frozenset({"namespace", "host-default"})
_DEPENDENCIES = {
    "namespace": ("ip", "nft", "wg"),
    "host-default": ("ip", "nft", "wg", "systemctl", "resolvectl"),
}


def verify_execution_runtime(
    mode: str,
    *,
    effective_uid: Callable[[], int] = os.geteuid,
    python_version: tuple[int, ...] | None = None,
    executable: Callable[[str], str | None] = shutil.which,
) -> dict:
    """Check the stable runtime prerequisites without querying live network state."""
    if mode not in SUPPORTED_MODES:
        raise RegistryError(f"unsupported operational preflight mode: {mode}")
    version = tuple(sys.version_info[:3] if python_version is None else python_version)
    if version < MIN_PYTHON:
        raise RegistryError(f"production operation requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer")
    if effective_uid() != 0:
        raise RegistryError("production network operation requires Linux root")
    missing = [name for name in _DEPENDENCIES[mode] if executable(name) is None]
    if missing:
        raise RegistryError("production operation is missing required commands: " + ", ".join(missing))
    return {
        "effective_uid": 0,
        "python": ".".join(str(part) for part in version),
        "dependencies": list(_DEPENDENCIES[mode]),
    }


def verify_operational_preflight(
    mode: str,
    *,
    host_plan=None,
    effective_uid: Callable[[], int] = os.geteuid,
    python_version: tuple[int, ...] | None = None,
    executable: Callable[[str], str | None] = shutil.which,
    platform_inspector: Callable[[], dict] = verify_supported_network_platform,
    host_inspector: Callable | None = None,
    include_host_inventory: bool = True,
) -> dict:
    """Verify dependencies, platform and privilege without granting mutation authority."""
    runtime = verify_execution_runtime(
        mode,
        effective_uid=effective_uid,
        python_version=python_version,
        executable=executable,
    )

    platform_report = platform_inspector()
    host_report = None
    if mode == "host-default":
        if host_plan is None:
            raise RegistryError("host-default preflight requires a validated host protection plan")
        if include_host_inventory:
            if host_inspector is None:
                from nord_tools_internal.nordvpn_host_executor import inspect_host_compatibility

                host_inspector = inspect_host_compatibility
            host_report = host_inspector(host_plan)

    return {
        "version": 1,
        "mode": "operational_preflight",
        "operational_mode": mode,
        "supported": True,
        **runtime,
        "platform": platform_report,
        "host": host_report,
        "host_inventory_checked": host_report is not None,
        "network_changes_applied": False,
        "mutation_authorised": False,
        "limitations": (
            "This read-only result is current observation, not reusable mutation authority. "
            "Each executor still rechecks operation-specific ownership and host state."
        ),
    }
