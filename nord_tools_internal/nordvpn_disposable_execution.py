"""Journal-gated disposable WireGuard configuration acceptance boundary.

This executes and verifies a short-lived test session, not persistent VPN
provisioning. Completed intent means the callback returned after namespace
retirement; it does not confer durable kernel resource ownership.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy
from nord_tools_internal.nordvpn_isolation_install import install_disposable_isolation
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
    *,
    isolation_policy: NamespaceIsolationPolicy | None = None,
) -> str:
    """Record intent before creating a disposable namespace and configuring it.

    The verifier runs while descriptor-bound authority remains live. Namespace
    retirement occurs before the recorded operation can complete. An exception
    or uncertain retirement leaves the intent unresolved for manual review.
    """
    if not isinstance(specification, TunnelSpecification) or not callable(verify_peer):
        raise RegistryError("validated specification and peer verifier required")
    if isolation_policy is not None:
        if not isinstance(isolation_policy, NamespaceIsolationPolicy):
            raise RegistryError("validated namespace isolation policy required")
        if (
            isolation_policy.tunnel_interface != specification.interface
            or isolation_policy.endpoint_address != specification.endpoint_address
            or isolation_policy.endpoint_port != specification.endpoint_port
        ):
            raise RegistryError("isolation policy does not match WireGuard specification")
    validated = validate_journal(journal)
    matches = [
        resource for resource in validated["allocations"]["resources"] if resource["allocation_id"] == allocation_id
    ]
    if len(matches) != 1 or matches[0]["kind"] != "interface" or matches[0]["identifier"] != specification.interface:
        raise RegistryError("allocation does not identify the requested WireGuard interface")

    def operation() -> str:
        with disposable_namespace(specification.namespace) as owned:
            if isolation_policy is not None:
                install_disposable_isolation(owned, isolation_policy)
                owned.verify()
            configure_disposable_wireguard(specification, owned, key_fd)
            owned.verify()
            if verify_peer(specification) is not True:
                raise RuntimeError("disposable WireGuard peer verification failed")
            owned.verify()
        return specification.namespace

    return execute_recorded_creation(
        store_path, validated, allocation_id, operation, lambda result: result == specification.namespace
    )


def execute_isolated_disposable_session(
    store_path: str | Path,
    journal: object,
    allocation_id: str,
    specification: TunnelSpecification,
    key_fd: int,
    verify_peer: Callable[[TunnelSpecification], bool],
    isolation_policy: NamespaceIsolationPolicy,
) -> str:
    """Require firewall installation before configuring a disposable WireGuard peer.

    This is an experimental pre-traffic ordering boundary, not proof of DNS
    confinement, complete leak prevention or safe underlay route selection.
    """
    if not isinstance(isolation_policy, NamespaceIsolationPolicy):
        raise RegistryError("validated namespace isolation policy required")
    return execute_disposable_session(
        store_path, journal, allocation_id, specification, key_fd, verify_peer, isolation_policy=isolation_policy
    )
