"""Authorised boot restoration of persistent desired-state VPN profiles.

This module wires the accepted foundations into one transactional,
boot-scoped path: a fresh read-only ownership preflight confirms what belongs to
Nord Tools, verified convergence is left untouched, and only profiles whose
desired resources are entirely absent in this boot session are provisioned
again through durable creation intents, creation-time owner records and the
existing privileged namespace, isolation, routing and WireGuard primitives.

Three boundaries stay strict. Resources that are present but not verifiable are
never touched: their fate belongs to the confirmed cleanup increment and to the
interruption-recovery work that follows it. Journal retirement is applied only
to allocations whose fresh observation is completely absent, so no kernel
resource is ever deleted by bookkeeping alone. Transient intent is structurally
unreachable: the startup configuration pins persistent paths only.

Every kernel mutation is bracketed by durable intent and verification. A failed
attempt records its allocations as failed, rolls back only the namespace this
run created, and leaves its own intent uncertain for operator review; the run
stops entirely so that later profiles, converged profiles and everything
unrelated remain exactly as observed. A fresh boot restores the profile again.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
from typing import Callable

from nord_tools_internal.nordvpn_allocation_profiles import expand_allocation_profiles, kernel_profile_for_allocation
from nord_tools_internal.nordvpn_discovery import discover
from nord_tools_internal.nordvpn_dns_confinement import (
    verify_dns_routes,
    verify_dns_peer_allowed_ips,
    verify_resolver_file,
)
from nord_tools_internal.nordvpn_resolver_install import install_namespace_resolver, remove_namespace_resolver
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy
from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy
from nord_tools_internal.nordvpn_generation_handover import read_handover, selected_allocation
from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_isolation_install import install_disposable_isolation
from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock as _execution_lock
from nord_tools_internal.nordvpn_lifecycle import record_transition, validate_journal, write_journal
from nord_tools_internal.nordvpn_lifecycle_store import update_journal
from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace, create_owned_namespace
from nord_tools_internal.nordvpn_operation_intent import validate_intents
from nord_tools_internal.nordvpn_ownership_verify import (
    initialise_bindings,
    preflight_ownership,
    record_binding,
)
from nord_tools_internal.nordvpn_operation_store import initialise_intents
from nord_tools_internal.nordvpn_provision_execution import (
    ProvisioningUncertainError,
    execute_recorded_creation,
)
from nord_tools_internal.nordvpn_cleanup_executor import CleanupKernel
from nord_tools_internal.nordvpn_production_contract import validate_executor_creation_contract
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_state_reconcile import derive_actual_state, reconcile_desired
from nord_tools_internal.nordvpn_sharing_contract import OwnershipGroup, resolve_ownership_groups
from nord_tools_internal.nordvpn_recovery_executor import plan_recovery
from nord_tools_internal.nordvpn_startup import (
    initialise_startup_runs,
    read_boot_id,
    record_startup_run,
    validate_startup_config,
)
from nord_tools_internal.nordvpn_underlay_install import (
    install_namespace_underlay,
    install_tunnel_routing,
    verify_tunnel_route_readback,
    namespace_interface_index,
)
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification
from nord_tools_internal.nordvpn_wireguard_session import configure_disposable_wireguard


RESTORATION_MODE = "startup_restoration_report"
# Findings asserting the resource is kernel-absent: replaced resources can be
# restored, anything else requires reviews or confirms live presence.
_ABSENT_FINDINGS = frozenset({"resource_missing", "scope_missing"})


@dataclass(frozen=True)
class RestoreKernel:
    """The injected privileged surface; tests substitute their own kernel."""

    observe: Callable[[], dict]
    create_namespace: Callable[[str], OwnedNamespace]
    prepare_underlay: Callable[..., int]
    install_isolation: Callable[[OwnedNamespace, NamespaceIsolationPolicy], object]
    route_tunnel: Callable[..., None]
    configure_wireguard: Callable[[TunnelSpecification, OwnedNamespace, int], None]
    interface_index: Callable[[str, str], int]
    public_key_from_fd: Callable[[int], str]
    verify_wireguard: Callable[..., bool]
    remove_host_interface: Callable[[str, int], None]
    install_resolver: Callable[..., object] | None = None
    verify_dns: Callable[..., None] | None = None
    remove_resolver: Callable[[object], None] | None = None


def _real_kernel() -> RestoreKernel:
    """Build the production kernel surface from the established primitives."""

    def observe() -> dict:
        return discover()

    def create_namespace(name: str) -> OwnedNamespace:
        return create_owned_namespace(name)

    def prepare_underlay(
        namespace: str, ns_interface: str, host_interface: str, ns_address: str, host_address: str
    ) -> int:
        return install_namespace_underlay(namespace, ns_interface, host_interface, ns_address, host_address)

    def install_isolation(owned: OwnedNamespace, policy: NamespaceIsolationPolicy) -> object:
        return install_disposable_isolation(owned, policy)

    def route_tunnel(
        namespace: str, tunnel_interface: str, underlay_interface: str, endpoint: str, tunnel_address: str, gateway: str
    ) -> None:
        install_tunnel_routing(namespace, tunnel_interface, underlay_interface, endpoint, tunnel_address, gateway)
        verify_tunnel_route_readback(namespace, tunnel_interface, underlay_interface, endpoint)

    def configure_wireguard(specification: TunnelSpecification, owned: OwnedNamespace, key_fd: int) -> None:
        configure_disposable_wireguard(specification, owned, key_fd)

    def interface_index(namespace: str, interface: str) -> int:
        return namespace_interface_index(namespace, interface)

    def public_key_from_fd(fd: int) -> str:
        from nord_tools_internal.nordvpn_wireguard_credentials import private_key_from_fd

        with private_key_from_fd(fd) as key:
            try:
                result = subprocess.run(["wg", "pubkey"], input=key, capture_output=True, timeout=15, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ProvisioningUncertainError("the WireGuard public key could not be derived") from exc
        if result.returncode:
            raise ProvisioningUncertainError("the WireGuard public key derivation failed")
        return result.stdout.decode("ascii").strip()

    def verify_wireguard(
        namespace: str,
        interface: str,
        expected_public_key: str,
        peer_public_key: str,
        specification: TunnelSpecification | None = None,
    ) -> bool:
        try:
            key = subprocess.run(
                ["ip", "netns", "exec", namespace, "wg", "show", interface, "public-key"],
                capture_output=True,
                timeout=15,
                check=False,
            )
            peers = subprocess.run(
                ["ip", "netns", "exec", namespace, "wg", "show", interface, "peers"],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if key.returncode or peers.returncode:
            return False
        if key.stdout != f"{expected_public_key}\n".encode("ascii") or peers.stdout != f"{peer_public_key}\n".encode(
            "ascii"
        ):
            return False
        if specification is None:
            return True
        # Query only non-secret WireGuard fields. `wg show ... dump` includes
        # private-key material and must not be used for diagnostic readback.
        expected_endpoint = (
            f"[{specification.endpoint_address}]:{specification.endpoint_port}"
            if ":" in specification.endpoint_address
            else f"{specification.endpoint_address}:{specification.endpoint_port}"
        )
        expected = (
            ("endpoints", f"{peer_public_key}\t{expected_endpoint}\n"),
            ("allowed-ips", f"{peer_public_key}\t{' '.join(specification.peer_allowed_ips)}\n"),
            ("persistent-keepalive", f"{peer_public_key}\t{specification.persistent_keepalive_seconds or 'off'}\n"),
        )
        for field, value in expected:
            try:
                result = subprocess.run(
                    ["ip", "netns", "exec", namespace, "wg", "show", interface, field],
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            if result.returncode or result.stdout != value.encode("ascii"):
                return False
        return True

    def remove_host_interface(name: str, ifindex: int) -> None:
        # Use the same identity-checked, indexed mutation as confirmed cleanup.
        # Never delete by name alone after a failed provisioning attempt.
        from nord_tools_internal.nordvpn_cleanup_executor import _real_kernel as cleanup_kernel

        cleanup_kernel().delete_host_interface(name, ifindex)

    return RestoreKernel(
        observe=observe,
        create_namespace=create_namespace,
        prepare_underlay=prepare_underlay,
        install_isolation=install_isolation,
        route_tunnel=route_tunnel,
        configure_wireguard=configure_wireguard,
        interface_index=interface_index,
        public_key_from_fd=public_key_from_fd,
        verify_wireguard=verify_wireguard,
        remove_host_interface=remove_host_interface,
        install_resolver=install_namespace_resolver,
        verify_dns=lambda name, interface, policy: (
            verify_dns_routes(name, interface, policy),
            verify_dns_peer_allowed_ips(name, interface, policy),
            verify_resolver_file(name, policy),
        ),
        remove_resolver=remove_namespace_resolver,
    )


def _read_document(path: str | Path) -> dict:
    try:
        with open(path, encoding="utf-8") as source:
            document = json.load(source)
    except (OSError, ValueError, UnicodeError) as exc:
        raise RegistryError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise RegistryError(f"{path} must contain a JSON object")
    return document


def _empty_journal() -> dict:
    return {"version": 1, "allocations": {"version": 2, "resources": []}, "events": []}


def _ensure_store_component(value: str) -> Path:
    target = Path(value).absolute()
    for component in (target, *target.parents):
        if component.is_symlink():
            raise RegistryError(f"refusing symlinked store path: {target}")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return target


def _ensure_stores(config: dict) -> dict:
    """Create absent journal, bindings, intent and run-record stores exclusively.

    A first boot may legitimately start with nothing recorded yet. The stores
    are created in the same locked, exclusive fashion as every other project
    store; existing stores are never replaced or rewritten.
    """
    journal_path = _ensure_store_component(config["journal"])
    if not journal_path.exists():
        write_journal(journal_path, _empty_journal())
    journal = validate_journal(_read_document(journal_path))
    bindings_path = _ensure_store_component(config["bindings"])
    if not bindings_path.exists():
        initialise_bindings(bindings_path)
    intent_path = _ensure_store_component(config["intent"])
    if not intent_path.exists():
        initialise_intents(intent_path, journal)
    validate_intents(_read_document(intent_path), journal)
    if not Path(config["run_record"]).exists():
        initialise_startup_runs(config["run_record"])
    return journal


def _advance(journal_path: str | Path, token: str, state: str) -> dict:
    """Append one validated lifecycle transition and return the new journal."""
    return update_journal(journal_path, lambda document: record_transition(document, token, state))


def _append_allocations(journal_path: str | Path, resources: list[dict]) -> dict:
    """Persist new allocation identities before any intent or mutation exists."""
    return update_journal(
        journal_path,
        lambda document: {
            **document,
            "allocations": {
                "version": 2,
                "resources": [*document["allocations"]["resources"], *resources],
            },
        },
    )


def _retire_sequence(current: str | None) -> tuple[str, ...]:
    """The canonical transition chain from any lifecycle state to retirement."""
    reaches = {
        None: ("reserved", "creating", "failed", "retiring"),
        "reserved": ("creating", "failed", "retiring"),
        "creating": ("failed", "retiring"),
        "active": ("retiring",),
        "degraded": ("retiring",),
        "failed": ("retiring",),
        "retiring": (),
        "retired": None,
    }
    if current not in reaches:
        raise RegistryError(f"unknown lifecycle state {current!r} for retirement")
    sequence = reaches[current]
    if sequence is None:
        return ()
    return sequence + ("retired",)


def _fresh_names(observation: dict, journal: dict) -> dict[str, str]:
    """Draw unique per-boot resource names; no draw reuses an observed name."""
    claimed: set[str] = set()
    for name in observation.get("namespaces", []):
        claimed.add(name)
    for details in observation.get("namespace_details", []):
        for link in details.get("interfaces", []):
            claimed.add(link["name"])
    for link in observation.get("host_interfaces", []):
        claimed.add(link["name"])
    for resource in journal["allocations"]["resources"]:
        claimed.add(resource["identifier"])
    drawn: dict[str, str] = {}
    for prefix in ("nt-", "ntwg", "ntul", "nthl"):
        while True:
            name = f"{prefix}{secrets.token_hex(4)}"
            if name in claimed or name in drawn.values():
                continue
            claimed.add(name)
            drawn[prefix] = name
            break
    return drawn


def _validated_plan(plan: dict, namespace: str, interface: str) -> dict:
    """Rebuild and validate the provider specification under final names."""
    specification = TunnelSpecification(
        namespace,
        interface,
        plan["peer_public_key"],
        plan["endpoint_address"],
        plan["endpoint_port"],
        plan["tunnel_address"],
        tuple(plan["peer_allowed_ips"]),
    )
    return {**plan, "specification": specification}


def _host_index(observation: dict, interface: str) -> int:
    for link in observation.get("host_interfaces", []):
        if link.get("name") == interface:
            value = link.get("index")
            if type(value) is not int or value < 1:
                raise RegistryError("invalid observed host interface identity")
            return value
    raise ProvisioningUncertainError(f"the created host interface {interface} is not observable")


def _prevalidate_plans(config: dict, desired: dict) -> dict:
    """Fail closed, before any mutation, on unusable plans or credentials."""
    tunnels = config["tunnels"]
    credentials = config["credentials"]
    effective, providers = expand_allocation_profiles(desired)
    unknown = [
        name for name in tunnels if name not in desired["vpn_profiles"] and name not in effective["vpn_profiles"]
    ]
    if unknown:
        raise RegistryError(f"provider tunnel plans name profiles out of saved policy: {', '.join(unknown)}")
    for name, plan in sorted(tunnels.items()):
        if credentials.get(name, credentials.get(providers.get(name))) is None:
            raise RegistryError(f"the tunnel plan for {name} has no pinned credential input")
        try:
            _validated_plan(plan, "nt-validation0123", "ntwg0123abcd")
            ipaddress.ip_interface(plan["underlay"]["namespace_address"])
            ipaddress.ip_interface(plan["underlay"]["host_address"])
            endpoint = ipaddress.ip_address(plan["endpoint_address"])
            if endpoint.version != ipaddress.ip_interface(plan["tunnel_address"]).version:
                raise RegistryError(f"the tunnel address family must match the peer endpoint family for {name}")
        except (ValueError, TypeError) as exc:
            raise RegistryError(f"invalid provider plan for {name}: {exc}") from exc
    return tunnels


def _restore_boot_policy(config: dict) -> dict:
    desired = validate_policy(_read_document(config["policy"]))
    _prevalidate_plans(config, desired)
    return desired


def _apply_generation_selections(config: dict, policy: dict) -> tuple[dict, dict[str, str]]:
    """Project active durable selections into boot restoration desired state."""
    if not config.get("handovers"):
        return policy, {}
    profiles = {name: dict(value) for name, value in policy["vpn_profiles"].items()}
    applications = {name: dict(value) for name, value in policy["applications"].items()}
    defaults = dict(policy["defaults"])
    providers: dict[str, str] = {}
    groups = {group.allocation_key: group for group in resolve_ownership_groups(policy)}
    selected_shared: set[str] = set()
    for configured_key, path in sorted(config["handovers"].items()):
        allocation = selected_allocation(read_handover(path), policy=policy)
        if configured_key not in {allocation.allocation_key, allocation.profile}:
            raise RegistryError("handover store does not match its configured allocation key")
        group = groups.get(allocation.allocation_key)
        if (
            group is None
            and allocation.allocation_key == f"profile:{allocation.profile}"
            and allocation.profile in policy["vpn_profiles"]
            and policy["vpn_profiles"][allocation.profile]["sharing"] == "shared"
        ):
            group = OwnershipGroup(
                allocation.allocation_key,
                allocation.profile,
                "shared",
                tuple(
                    name
                    for name, application in policy["applications"].items()
                    if application["vpn"] == allocation.profile
                ),
            )
        if group is None or group.profile != allocation.profile:
            raise RegistryError("handover allocation is not present in the boot policy")
        normal_profile = kernel_profile_for_allocation(group.allocation_key, group.profile, group.sharing)
        if allocation.kernel_profile == normal_profile:
            continue
        if allocation.kernel_profile in profiles:
            raise RegistryError("generation kernel profile collides with boot policy")
        definition = dict(profiles[group.profile])
        if group.sharing == "shared":
            if group.profile in selected_shared:
                raise RegistryError("multiple generation selections target one shared profile")
            selected_shared.add(group.profile)
            profiles.pop(group.profile)
            if defaults["vpn"] == group.profile:
                defaults["vpn"] = allocation.kernel_profile
        else:
            definition["sharing"] = "shared"
        profiles[allocation.kernel_profile] = definition
        providers[allocation.kernel_profile] = group.profile
        for application in group.consumers:
            applications[application]["vpn"] = allocation.kernel_profile
    return validate_policy(
        {
            "version": 1,
            "defaults": defaults,
            "vpn_profiles": profiles,
            "applications": applications,
        }
    ), providers


def _creation_order(candidates: list[str], dependencies: dict[str, list[str]] | None) -> list[str]:
    """Order candidates so every prerequisite candidate is attempted first."""
    if not dependencies:
        return list(candidates)
    order: list[str] = []
    pending = {name: {dep for dep in dependencies.get(name, []) if dep in candidates} for name in candidates}
    while pending:
        ready = sorted(name for name, waiting in pending.items() if not waiting)
        if not ready:
            raise RegistryError("provider profiles form a dependency cycle")
        for name in ready:
            del pending[name]
        for waiting in pending.values():
            waiting.difference_update(ready)
        order.extend(ready)
    return order


def _dependency_refusal(
    name: str,
    dependencies: dict[str, list[str]] | None,
    eligibility: dict[str, str | None],
    restored: list[str],
    decisions: dict[str, dict],
) -> str | None:
    """A dependent is refused when any prerequisite cannot already be trusted."""
    if not dependencies:
        return None
    for prerequisite in dependencies.get(name, ()):
        if prerequisite in decisions and decisions[prerequisite]["action"] == "converged":
            continue
        if prerequisite in restored and eligibility.get(prerequisite) is None:
            continue
        reason = eligibility.get(prerequisite) or decisions.get(prerequisite, {}).get("reason")
        return reason or "a prerequisite profile cannot be restored this boot"
    return None


def _restore_profile(
    profile: str,
    configuration: dict,
    plan: dict,
    credential_path: str,
    config: dict,
    stale_tokens: list[str],
    namespace_journal: dict,
    observation: dict,
    helpers: RestoreKernel,
) -> None:
    """Restore one profile's namespace, underlay and pinned WireGuard tunnel.

    The whole profile is one durable transaction on the namespace allocation:
    the pending intent is recorded first, every kernel step is bracketed by
    verification, owner bindings are written while descriptor-bound authority
    still exists, and lifecycle states reach ``active`` only after fresh
    verification. Any exception rolls back the namespace this run created and
    re-raises, leaving uncertain intent evidence behind for review.
    """
    journal_path = config["journal"]
    bindings_path = config["bindings"]
    intent_path = config["intent"]
    states = {event["allocation_id"]: event["state"] for event in namespace_journal["events"]}
    for token in sorted(stale_tokens):
        for state in _retire_sequence(states.get(token)):
            journal = _advance(journal_path, token, state)
    names = _fresh_names(observation, namespace_journal)
    namespace, interface, underlay_ns, underlay_host = (
        names["nt-"],
        names["ntwg"],
        names["ntul"],
        names["nthl"],
    )
    plan = _validated_plan(plan, namespace, interface)
    specification = plan["specification"]
    resources = [
        allocate_identity("namespace", namespace, profile),
        allocate_identity("interface", interface, profile),
        allocate_identity("interface", underlay_ns, profile),
        allocate_identity("interface", underlay_host, profile),
    ]
    ns_token, wg_token, ul_ns_token, ul_host_token = (resource["allocation_id"] for resource in resources)
    tokens = [ns_token, wg_token, ul_ns_token, ul_host_token]
    validate_executor_creation_contract(
        profile,
        specification,
        resources,
        underlay_ns,
        underlay_host,
        namespace_journal["allocations"],
    )
    # The initial observation selected names, but must not be treated as
    # authority to create them later. Refuse names newly occupied in the kernel.
    fresh = helpers.observe()
    occupied = set(fresh.get("namespaces", []))
    occupied.update(link["name"] for link in fresh.get("host_interfaces", []))
    for details in fresh.get("namespace_details", []):
        occupied.update(link["name"] for link in details.get("interfaces", []))
    if occupied.intersection((namespace, interface, underlay_ns, underlay_host)):
        raise ProvisioningUncertainError("a proposed production resource name became occupied before creation")
    journal = _append_allocations(journal_path, resources)
    for token in tokens:
        journal = _advance(journal_path, token, "reserved")
        journal = _advance(journal_path, token, "creating")

    def operation() -> dict:
        cleanup: list[Callable[[], None]] = []
        owned = None
        try:
            owned = helpers.create_namespace(namespace)
            # Reversed rollback order: retire first, then release the descriptor.
            cleanup.append(lambda: owned.release())
            cleanup.append(lambda: owned.retire())
            record_binding(
                bindings_path,
                validate_journal(_read_document(journal_path)),
                ns_token,
                {"device": owned.device, "inode": owned.inode},
                configuration=configuration,
            )
            ns_ifindex = helpers.prepare_underlay(
                namespace,
                underlay_ns,
                underlay_host,
                plan["underlay"]["namespace_address"],
                plan["underlay"]["host_address"],
            )
            # Capture the creation-time host index. A subsequent name reuse
            # must not turn rollback into deletion of an unrelated interface.
            host_ifindex = _host_index(helpers.observe(), underlay_host)
            cleanup.append(lambda: helpers.remove_host_interface(underlay_host, host_ifindex))
            gateway = str(ipaddress.ip_interface(plan["underlay"]["host_address"]).ip)
            with open(credential_path, "rb") as credential:
                public_key = helpers.public_key_from_fd(credential.fileno())
            isolation = NamespaceIsolationPolicy(
                tunnel_interface=interface,
                underlay_interface=underlay_ns,
                endpoint_address=plan["endpoint_address"],
                endpoint_port=plan["endpoint_port"],
            )
            helpers.install_isolation(owned, isolation)
            record_binding(
                bindings_path,
                validate_journal(_read_document(journal_path)),
                ul_ns_token,
                {"scope": namespace, "ifindex": ns_ifindex},
                configuration=configuration,
            )
            record_binding(
                bindings_path,
                validate_journal(_read_document(journal_path)),
                ul_host_token,
                {"scope": "host", "ifindex": _host_index(helpers.observe(), underlay_host)},
                configuration=configuration,
            )
            # The route targets the WireGuard device, which must exist before
            # iproute2 can install a route through it. Keep isolation in place
            # before creating or raising the device so failure remains closed.
            key_fd = os.open(credential_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                helpers.configure_wireguard(specification, owned, key_fd)
            finally:
                os.close(key_fd)
            helpers.route_tunnel(
                namespace,
                interface,
                underlay_ns,
                plan["endpoint_address"],
                plan["tunnel_address"],
                gateway,
            )
            if (
                helpers.verify_wireguard(namespace, interface, public_key, plan["peer_public_key"], specification)
                is not True
            ):
                raise ProvisioningUncertainError("the restored WireGuard peer does not match the pinned provider plan")
            # Only publish a namespace resolver after the firewall, both default
            # routes and the pinned WireGuard peer have been verified. An
            # unverified DNS destination must never become active.
            if "dns_servers" in plan:
                if helpers.install_resolver is None or helpers.verify_dns is None or helpers.remove_resolver is None:
                    raise ProvisioningUncertainError("production DNS kernel helpers are unavailable")
                dns_policy = NamespaceResolverPolicy(tuple(plan["dns_servers"]))
                verify_dns_routes_before_install = helpers.verify_dns
                # Route confinement is verified again after the resolver file
                # has been installed, before publishing active lifecycle state.
                installation = helpers.install_resolver(namespace, dns_policy)
                cleanup.append(lambda: helpers.remove_resolver(installation))
                verify_dns_routes_before_install(namespace, interface, dns_policy)
            record_binding(
                bindings_path,
                validate_journal(_read_document(journal_path)),
                wg_token,
                {"scope": namespace, "ifindex": helpers.interface_index(namespace, interface)},
                configuration=configuration,
            )
            for token in tokens:
                _advance(journal_path, token, "active")
            owned.release()
            return {"namespace": namespace, "profile": profile}
        except BaseException as failure:
            # Roll back only what this attempt created, best effort, and record
            # the failed lifecycle evidence rather than an invented success.
            rollback_failures = []
            for step in reversed(cleanup):
                try:
                    step()
                except Exception as exc:
                    rollback_failures.append(type(exc).__name__)
            # Rollback callbacks succeeding does not prove that their effects
            # survived in the kernel. Re-observe both resource scopes before
            # treating the best-effort rollback as complete. Never delete an
            # unexpected occupant of a reused name during this assessment.
            try:
                after_rollback = helpers.observe()
                remaining_namespaces = set(after_rollback.get("namespaces", ()))
                remaining_host_links = {link["name"] for link in after_rollback.get("host_interfaces", ())}
                if namespace in remaining_namespaces:
                    rollback_failures.append("namespace_still_present")
                if underlay_host in remaining_host_links:
                    rollback_failures.append("host_interface_still_present")
            except Exception:
                rollback_failures.append("rollback_observation_unavailable")
            # An incomplete rollback is never silently represented as clean.
            # The durable creation intent remains uncertain for recovery.
            if rollback_failures:
                failure.add_note(
                    "rollback could not complete safely ("
                    + ", ".join(rollback_failures)
                    + "); the creation intent remains uncertain and requires recovery review"
                )
            try:
                for token in tokens:
                    try:
                        _advance(journal_path, token, "failed")
                    except RegistryError:
                        pass
            except Exception:
                pass
            raise

    def verify(result: dict) -> bool:
        fresh = helpers.observe()
        if result["namespace"] not in fresh.get("namespaces", []):
            return False
        details = [entry for entry in fresh.get("namespace_details", []) if entry.get("name") == result["namespace"]]
        if len(details) != 1:
            return False
        observed = {link["name"] for link in details[0].get("interfaces", [])}
        if interface not in observed or underlay_ns not in observed:
            return False
        return underlay_host in [link["name"] for link in fresh.get("host_interfaces", [])]

    execute_recorded_creation(intent_path, journal, ns_token, operation, verify)


def _eligibility(decision: dict, actual_profile: dict | None, desired: bool) -> str | None:
    """Decide whether this profile may be restored this boot; None means eligible.

    Only two situations restore: desired profiles without any resources at all,
    and desired profiles whose every resource is freshly observed as absent from
    the kernel. Anything else stays a plan: dependency propagation, verified-but
    -undesired resources, configuration drift and unverified observations are
    the cleanup and recovery increments' business, not this importer's.
    """
    if not desired:
        return "not desired; resources belong to the confirmed cleanup work"
    action = decision["action"]
    blockers = (actual_profile or {}).get("blockers", [])
    if action == "converged":
        return "already converged"
    if action in ("configuration_changed", "configuration_unverified"):
        return f"the recorded configuration differs from desired intent ({action})"
    if action == "retire_pending":
        return "verified-but-undesired resources belong to the confirmed cleanup work"
    if action == "blocked":
        if not blockers:
            return "the profile is blocked through a prerequisite"
        if all(blocker["finding"] in _ABSENT_FINDINGS for blocker in blockers):
            return None
        return "resources are present but not verifiable; operator review is required"
    # create_pending: no owned resources exist yet; restore through the pinned plan.
    return None


def restore_boot_state(
    config: object,
    *,
    kernel: RestoreKernel | None = None,
    cleanup_kernel: "CleanupKernel | None" = None,
    boot_id: str | None = None,
    recorded_at: str | None = None,
) -> dict:
    """Restore absent desired profiles' resources exactly once per run.

    Returns a deterministic report and appends one startup run record.
    Convergence is re-derived fresh at the end of the run, so the report never
    reflects a stale classification. Failures propagate to the caller as
    exceptions after the durable intent, journal and owner-record evidence has
    been recorded, because an attempted change must never be reported as clean.
    """
    validated = validate_startup_config(config)
    if not validated["intent"]:
        raise RegistryError("restoration requires durable operation intents in the startup configuration")
    if validated["tunnels"] and not validated["credentials"]:
        raise RegistryError("restoration requires one pinned credential input per tunnel plan")
    helpers = kernel or _real_kernel()
    boot_identity = boot_id or read_boot_id()
    restart_at = recorded_at or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    if not Path(validated["policy"]).exists():
        raise RegistryError(f"the saved persistent policy does not exist: {validated['policy']}")
    with _execution_lock(validated["journal"]):
        _ensure_stores(validated)
        logical_policy = _restore_boot_policy(validated)
        original_policy, generation_providers = _apply_generation_selections(validated, logical_policy)
        desired, provider_profiles = expand_allocation_profiles(original_policy)
        provider_profiles.update(generation_providers)
        # Each isolated consumer receives a distinct durable profile identity.
        # The pinned provider specification and credential remain sourced from
        # the original profile, never inferred from the synthetic name.
        tunnels = {
            identity: validated["tunnels"].get(identity, validated["tunnels"].get(source))
            for identity, source in provider_profiles.items()
            if identity in validated["tunnels"] or source in validated["tunnels"]
        }
        # A profile plan cannot be blindly reused for multiple isolated
        # allocations: identical host-side underlay networks make routing
        # ambiguous. Operators must pin separate addressing per allocation.
        underlay_owners: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for identity, plan in sorted(tunnels.items()):
            network = ipaddress.ip_interface(plan["underlay"]["host_address"]).network
            for previous, occupied in underlay_owners:
                if network.overlaps(occupied):
                    raise RegistryError(
                        f"allocation profiles {previous} and {identity} overlap in host underlay networks; "
                        "pin a distinct tunnel plan for each isolated allocation"
                    )
            underlay_owners.append((identity, network))
        credentials = {
            identity: validated["credentials"].get(identity, validated["credentials"].get(source))
            for identity, source in provider_profiles.items()
            if identity in validated["credentials"] or source in validated["credentials"]
        }
        # Boot recovery next: it completes only certified bookkeeping and
        # identity-verified rollback of half-built creations, and aborts the
        # entire boot when uncertain evidence needs operator review.
        recovery = plan_recovery(
            validated["journal"],
            validated["bindings"],
            validated["intent"],
            boot=True,
            execute=True,
            kernel=cleanup_kernel,
            recorded_at=restart_at,
            already_locked=True,
        )
        bindings = _read_document(validated["bindings"])
        intents = _read_document(validated["intent"])
        observation = helpers.observe()
        namespace_journal = validate_journal(_read_document(validated["journal"]))
        preflight = preflight_ownership(namespace_journal, bindings, observation, intents)
        actual = derive_actual_state(namespace_journal, bindings, preflight)
        # Existing profile-scoped isolated resources cannot be silently
        # reinterpreted as consumer-owned allocations. Preserve them for
        # explicit retirement before creating replacement allocations.
        legacy = {
            name
            for name, definition in original_policy["vpn_profiles"].items()
            if definition["sharing"] == "isolated" and name not in desired["vpn_profiles"]
        }
        for name in sorted(legacy):
            state = actual["profiles"].get(name)
            if state and (state["present_resources"] or state["blockers"]):
                raise RegistryError(
                    f"legacy isolated profile {name} retains resources; "
                    "review and retire the old profile before enabling per-consumer allocations"
                )
        graph = validated["graph"] and _read_document(validated["graph"])
        reconciliation = reconcile_desired(desired, actual, graph)
        decisions = {item["profile"]: item for item in reconciliation["decisions"]}
        allocation_profiles = {
            resource["allocation_id"]: resource["profile"] for resource in namespace_journal["allocations"]["resources"]
        }
        stale = {
            item["allocation_id"]: item["allocation_id"]
            for item in preflight["resources"]
            if item["finding"] in _ABSENT_FINDINGS
        }
        named = credentials
        eligibility: dict[str, str | None] = {}
        for name, decision in decisions.items():
            record = actual["profiles"].get(name)
            reason = _eligibility(decision, record, name in desired["vpn_profiles"])
            if reason is not None or name not in tunnels:
                if reason is None:
                    reason = "the desired profile has no provider tunnel plan"
                eligibility[name] = reason
                continue
            eligibility[name] = None if name in named else "the tunnel plan has no pinned credential input"
        dependencies = (
            graph["dependencies"] if isinstance(graph, dict) and isinstance(graph.get("dependencies"), dict) else None
        )
        restored: list[str] = []
        for name in _creation_order(
            [name for name in sorted(eligibility) if eligibility[name] is None],
            dependencies,
        ):
            refusal = _dependency_refusal(name, dependencies, eligibility, restored, decisions)
            if refusal is not None:
                eligibility[name] = f"the prerequisite cannot be restored this boot: {refusal}"
                continue
            profile_stale = sorted(
                token for identity, token in stale.items() if allocation_profiles.get(identity) == name
            )
            _restore_profile(
                name,
                desired["vpn_profiles"][name],
                tunnels[name],
                named[name],
                validated,
                profile_stale,
                namespace_journal,
                observation,
                helpers,
            )
            restored.append(name)
        final, final_preflight = _fresh_reconciliation(validated, desired, helpers, graph)
        refused = [
            {"profile": name, "reason": reason}
            for name, reason in sorted(eligibility.items())
            if reason is not None and name in desired["vpn_profiles"]
        ]
        report = {
            "version": 1,
            "mode": RESTORATION_MODE,
            "boot_id": boot_identity,
            "network_changes_applied": bool(restored),
            "reconciled": bool(final["reconciled"]),
            "restored": sorted(restored),
            "blocked": sorted(item["profile"] for item in final["decisions"] if item["action"] == "blocked"),
            "operator_review_required": bool(final_preflight["operator_review_required"]),
            "profiles_not_restored": refused,
            "unresolved_intents": final["unresolved_intents"],
            "unclaimed": final_preflight["unclaimed"],
            "decisions": final["decisions"],
            "recorded_at": restart_at,
            "recovery": {
                "actions": recovery["actions"],
                "review_required": recovery["review_required"],
            },
            "limitations": (
                "Restores only pinned profiles whose owned resources are absent in this boot session. "
                "Verified-but-undesired resources belong to the confirmed cleanup increment, "
                "configuration replacements remain plans, and recording failures leave uncertain "
                "evidence for review rather than being resolved silently."
            ),
        }
        _record_run(validated["run_record"], boot_identity, restart_at, final, sorted(restored), final_preflight)
        return report


def _record_run(path: str, boot_id: str, recorded_at: str, final: dict, restored: list[str], preflight: dict) -> None:
    """Append the completed run to the bounded, persistent record."""
    record_startup_run(
        path,
        {
            "boot_id": boot_id,
            "recorded_at": recorded_at,
            "reconciled": bool(final["reconciled"]),
            "restored": restored,
            "blocked": sorted(item["profile"] for item in final["decisions"] if item["action"] == "blocked"),
            "operator_review_required": bool(preflight["operator_review_required"]),
        },
    )


def _fresh_reconciliation(
    config: dict, desired: dict, helpers: RestoreKernel, graph: object | None
) -> tuple[dict, dict]:
    journal = validate_journal(_read_document(config["journal"]))
    bindings = _read_document(config["bindings"])
    intents = _read_document(config["intent"]) if config["intent"] else None
    observation = helpers.observe()
    preflight = preflight_ownership(journal, bindings, observation, intents)
    actual = derive_actual_state(journal, bindings, preflight)
    return reconcile_desired(desired, actual, graph), preflight
