"""Journal-gated disposable WireGuard configuration acceptance boundary.

This executes and verifies a short-lived test session, not persistent VPN
provisioning. Completed intent means the callback returned after namespace
retirement; it does not confer durable kernel resource ownership.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_namespace_ownership import disposable_namespace
from nord_tools_internal.nordvpn_provision_execution import execute_recorded_creation
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification
from nord_tools_internal.nordvpn_wireguard_session import configure_disposable_wireguard


def execute_disposable_session(
    store_path: str | Path,
    journal: object,
    allocation_id: str,
    specification: TunnelSpecification,
    key_fd: int,
    verify_peer: Callable[[TunnelSpecification], bool],
) -> str:
    """Record intent before creating a disposable namespace and configuring it.

    The verifier runs while descriptor-bound authority remains live. Namespace
    retirement occurs before the recorded operation can complete. An exception
    or uncertain retirement leaves the intent unresolved for manual review.
    """
    if not isinstance(specification, TunnelSpecification) or not callable(verify_peer):
        raise RegistryError("validated specification and peer verifier required")
    validated = validate_journal(journal)
    matches = [
        resource for resource in validated["allocations"]["resources"] if resource["allocation_id"] == allocation_id
    ]
    if len(matches) != 1 or matches[0]["kind"] != "interface" or matches[0]["identifier"] != specification.interface:
        raise RegistryError("allocation does not identify the requested WireGuard interface")

    def operation() -> str:
        with disposable_namespace(specification.namespace) as owned:
            configure_disposable_wireguard(specification, owned, key_fd)
            owned.verify()
            if verify_peer(specification) is not True:
                raise RuntimeError("disposable WireGuard peer verification failed")
            owned.verify()
        return specification.namespace

    return execute_recorded_creation(
        store_path, validated, allocation_id, operation, lambda result: result == specification.namespace
    )
