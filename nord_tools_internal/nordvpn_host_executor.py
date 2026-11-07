"""Crash-durable lifecycle executor for the supported host-default profile."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Callable

from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from nord_tools_internal.nordvpn_host_store import (
    empty_host_store,
    locked_host_store,
    read_host_store,
    record_step_evidence,
    record_step_intent,
    reopen_absent_step,
    reopen_present_retirement,
    write_host_store,
)
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_startup import read_boot_id


class HostProtectionError(RuntimeError):
    """Host protection could not proceed without weakening its safety state."""


@dataclass(frozen=True)
class HostKernel:
    """Injected privileged surface; each mutator must return readback evidence."""

    inventory: Callable[[], dict]
    install_barrier: Callable[[HostProtectionPlan], dict]
    install_endpoint: Callable[[HostProtectionPlan], dict]
    install_wireguard: Callable[[HostProtectionPlan, int], dict]
    install_routes: Callable[[HostProtectionPlan], dict]
    install_resolver: Callable[[HostProtectionPlan], dict]
    verify_ready: Callable[[HostProtectionPlan], dict]
    resource_state: Callable[[str, dict, HostProtectionPlan], str]
    observe_resource: Callable[[str, HostProtectionPlan], tuple[str, dict | None]]
    remove_resolver: Callable[[HostProtectionPlan, dict], dict]
    remove_routes: Callable[[HostProtectionPlan, dict], dict]
    remove_wireguard: Callable[[HostProtectionPlan, dict], dict]
    remove_endpoint: Callable[[HostProtectionPlan, dict], dict]
    remove_barrier: Callable[[HostProtectionPlan, dict], dict]


_ACTIVATION_STEPS = (
    "barrier",
    "endpoint",
    "wireguard",
    "routes",
    "resolver",
)
_RETIREMENT = (
    ("remove_resolver", "resolver"),
    ("remove_routes", "routes"),
    ("remove_wireguard", "wireguard"),
    ("remove_endpoint", "endpoint"),
    ("remove_barrier", "barrier"),
)


def _kernel(plan: HostProtectionPlan) -> HostKernel:
    from nord_tools_internal.nordvpn_host_linux import linux_host_kernel

    return linux_host_kernel(plan)


def _load_or_empty(path: Path) -> dict:
    return read_host_store(path) if path.exists() else empty_host_store()


def _step(document: dict, name: str) -> dict | None:
    record = document["record"]
    return next((item for item in record["steps"] if item["name"] == name), None) if record else None


def _validate_inventory(inventory: object, plan: HostProtectionPlan, *, allow_owned: bool) -> dict:
    if not isinstance(inventory, dict):
        raise HostProtectionError("host inventory is malformed")
    required = {"boot_id", "links", "resolver_manager", "conflicts", "owned_resources"}
    if set(inventory) != required:
        raise HostProtectionError("host inventory is incomplete or has unknown fields")
    if not isinstance(inventory["links"], list) or not isinstance(inventory["conflicts"], list):
        raise HostProtectionError("host link or conflict inventory is malformed")
    matches = [
        item
        for item in inventory["links"]
        if isinstance(item, dict)
        and item.get("name") == plan.egress_interface
        and item.get("index") == plan.egress_ifindex
    ]
    if len(matches) != 1:
        raise HostProtectionError("the pinned physical egress interface identity is absent or replaced")
    if inventory["resolver_manager"] != "systemd-resolved":
        raise HostProtectionError("the supported host profile requires systemd-resolved")
    if inventory["conflicts"]:
        raise HostProtectionError("conflicting host network management was detected")
    if not isinstance(inventory["owned_resources"], list):
        raise HostProtectionError("host owned-resource inventory is malformed")
    if inventory["owned_resources"] and not allow_owned:
        raise HostProtectionError("pre-existing host protection objects have no matching durable ownership record")
    return copy.deepcopy(inventory)


def preview_host_protection(plan: HostProtectionPlan) -> dict:
    """Render the exact mutation order without inspecting or changing the host."""
    if not isinstance(plan, HostProtectionPlan):
        raise RegistryError("validated host protection plan required")
    return {
        "version": 1,
        "mode": "host_default_dry_run",
        "network_changes_applied": False,
        "mutation_authorised": False,
        "generation": plan.generation,
        "plan_sha256": plan.fingerprint(),
        "steps": list(_ACTIVATION_STEPS),
        "ordering": "deny barrier, endpoint path, WireGuard, dual-stack routes, resolver, packet readiness",
        "requires": [
            "root execution",
            "private lifecycle store directory",
            "descriptor-supplied WireGuard private key",
            "stable static physical egress",
            "systemd-resolved",
            "fresh conflict-free host inventory",
        ],
    }


def _new_record(plan: HostProtectionPlan, boot_id: str) -> dict:
    return {
        "version": 1,
        "history": [],
        "record": {
            "generation": plan.generation,
            "plan_sha256": plan.fingerprint(),
            "boot_id": boot_id,
            "operation": "activate",
            "outcome": "preparing",
            "ordinary_egress_blocked": False,
            "steps": [],
        },
    }


def prepare_host_boot_barrier(
    plan: HostProtectionPlan,
    store_path: str | Path,
    *,
    kernel: HostKernel | None = None,
    boot_id: str | None = None,
) -> dict:
    """Install the deny barrier before network configuration during boot.

    A record from an earlier boot is archived only after every recorded host
    object is independently absent.  The new boot then receives a fresh
    pending intent before nftables is touched.  No endpoint exception, route,
    resolver or WireGuard configuration is attempted at this stage.
    """
    if not isinstance(plan, HostProtectionPlan):
        raise RegistryError("validated host protection plan required")
    helpers = kernel or _kernel(plan)
    if kernel is None and os.geteuid() != 0:
        raise HostProtectionError("early host deny-barrier installation requires root")
    identity = boot_id or read_boot_id()
    target = Path(store_path).absolute()
    with locked_host_store(target):
        document = _load_or_empty(target)
        record = document["record"]
        if record is not None and record["boot_id"] != identity:
            if record["generation"] != plan.generation or record["plan_sha256"] != plan.fingerprint():
                raise HostProtectionError("the host plan changed across reboot; prior resources cannot be identified")
            for step in record["steps"]:
                if step["name"].startswith("remove_") or step["evidence"] is None:
                    continue
                if helpers.resource_state(step["name"], step["evidence"], plan) != "absent":
                    raise HostProtectionError("a prior-boot host resource remains present or ambiguous")
            document["history"].append(record)
            if len(document["history"]) > 32:
                raise HostProtectionError("host protection history is full; archive it deliberately")
            document["record"] = None
            write_host_store(target, document)
            record = None
        if record is None:
            for name in _ACTIVATION_STEPS:
                if helpers.resource_state(name, {}, plan) != "absent":
                    raise HostProtectionError("pre-existing host protection objects lack current-boot ownership")
            fresh = _new_record(plan, identity)
            fresh["history"] = document["history"]
            document = fresh
            write_host_store(target, document)
        elif record["generation"] != plan.generation or record["plan_sha256"] != plan.fingerprint():
            raise HostProtectionError("a different host protection generation retains current-boot evidence")
        current = _step(document, "barrier")
        if current and current["state"] == "observed":
            if helpers.resource_state("barrier", current["evidence"], plan) != "present":
                document["record"]["outcome"] = "uncertain"
                write_host_store(target, document)
                raise HostProtectionError("the current-boot host barrier identity drifted")
        elif current is not None:
            raise HostProtectionError("the current-boot host barrier has unresolved evidence")
        else:
            document = record_step_intent(document, "barrier", {"plan_sha256": plan.fingerprint()})
            write_host_store(target, document)
            try:
                evidence = helpers.install_barrier(plan)
                if helpers.resource_state("barrier", evidence, plan) != "present":
                    raise HostProtectionError("the early host barrier readback failed")
            except BaseException:
                _persist_uncertain(target, document, "barrier")
                raise
            document = record_step_evidence(document, "barrier", "observed", evidence)
            document["record"]["ordinary_egress_blocked"] = True
            write_host_store(target, document)
        return {
            "version": 1,
            "mode": "host_default_boot_barrier",
            "network_changes_applied": current is None,
            "boot_id": identity,
            "generation": plan.generation,
            "ordinary_host_egress_blocked": True,
            "next_stage": "network-online host activation",
        }


def _persist_uncertain(path: Path, document: dict, name: str) -> dict:
    current = _step(document, name)
    if current is not None and current["state"] == "pending":
        document = record_step_evidence(document, name, "uncertain", {"reason": "mutation did not verify"})
    document["record"]["outcome"] = "uncertain"
    return write_host_store(path, document)


def activate_host_protection(
    plan: HostProtectionPlan,
    store_path: str | Path,
    private_key_fd: int,
    *,
    kernel: HostKernel | None = None,
    boot_id: str | None = None,
) -> dict:
    """Install and verify protection, with durable intent before every mutation."""
    if not isinstance(plan, HostProtectionPlan):
        raise RegistryError("validated host protection plan required")
    if type(private_key_fd) is not int or private_key_fd < 0:
        raise RegistryError("host protection requires a private-key descriptor")
    helpers = kernel or _kernel(plan)
    if kernel is None and os.geteuid() != 0:
        raise HostProtectionError("host protection activation requires root")
    identity = boot_id or read_boot_id()
    target = Path(store_path).absolute()
    with locked_host_store(target):
        document = _load_or_empty(target)
        record = document["record"]
        if record is None:
            inventory = _validate_inventory(helpers.inventory(), plan, allow_owned=False)
            if inventory["boot_id"] != identity:
                raise HostProtectionError("host inventory boot identity changed during activation preflight")
            document = _new_record(plan, identity)
            write_host_store(target, document)
        else:
            if record["generation"] != plan.generation or record["plan_sha256"] != plan.fingerprint():
                raise HostProtectionError("a different host protection generation retains durable evidence")
            if record["boot_id"] != identity:
                raise HostProtectionError("host protection evidence crosses a reboot and requires recovery review")
            if record["outcome"] == "retired":
                raise HostProtectionError("retired host evidence must be archived before a new activation")
            inventory = _validate_inventory(helpers.inventory(), plan, allow_owned=True)
            if inventory["boot_id"] != identity:
                raise HostProtectionError("host inventory boot identity changed during activation preflight")
        callbacks = {
            "barrier": lambda: helpers.install_barrier(plan),
            "endpoint": lambda: helpers.install_endpoint(plan),
            "wireguard": lambda: helpers.install_wireguard(plan, private_key_fd),
            "routes": lambda: helpers.install_routes(plan),
            "resolver": lambda: helpers.install_resolver(plan),
        }
        for name in _ACTIVATION_STEPS:
            current = _step(document, name)
            retry_authorised = False
            if current and current["state"] == "observed":
                if helpers.resource_state(name, current["evidence"], plan) != "present":
                    document["record"]["outcome"] = "uncertain"
                    write_host_store(target, document)
                    raise HostProtectionError(f"recorded host {name} identity drifted")
                continue
            if current and current["state"] == "absent":
                document = reopen_absent_step(document, name, {"plan_sha256": plan.fingerprint()})
                write_host_store(target, document)
                current = _step(document, name)
                retry_authorised = True
            if current is not None:
                if current["state"] != "pending" or not retry_authorised:
                    raise HostProtectionError(f"host {name} has unresolved mutation evidence")
            else:
                document = record_step_intent(document, name, {"plan_sha256": plan.fingerprint()})
                write_host_store(target, document)
            try:
                evidence = callbacks[name]()
                if not isinstance(evidence, dict) or helpers.resource_state(name, evidence, plan) != "present":
                    raise HostProtectionError(f"host {name} readback did not match its intent")
            except BaseException:
                _persist_uncertain(target, document, name)
                raise
            document = record_step_evidence(document, name, "observed", evidence)
            if name == "barrier":
                document["record"]["ordinary_egress_blocked"] = True
            write_host_store(target, document)
        readiness = helpers.verify_ready(plan)
        if not isinstance(readiness, dict) or readiness.get("barrier") is not True:
            document["record"]["outcome"] = "uncertain"
            write_host_store(target, document)
            raise HostProtectionError("the host deny barrier could not be verified")
        ready = all(readiness.get(key) is True for key in ("wireguard", "routes", "resolver", "handshake"))
        document["record"]["outcome"] = "active" if ready else "protected_unavailable"
        document["record"]["ordinary_egress_blocked"] = True
        write_host_store(target, document)
        return host_protection_status(plan, target, kernel=helpers, already_locked=True)


def host_protection_status(
    plan: HostProtectionPlan,
    store_path: str | Path,
    *,
    kernel: HostKernel | None = None,
    already_locked: bool = False,
) -> dict:
    """Compare desired, durable and observed state without inferring safety from a flag."""
    helpers = kernel or _kernel(plan)
    target = Path(store_path).absolute()

    def inspect() -> dict:
        document = _load_or_empty(target)
        record = document["record"]
        inventory = helpers.inventory()
        observed: dict[str, str] = {}
        if record is not None:
            for step in record["steps"]:
                if step["evidence"] is not None and not step["name"].startswith("remove_"):
                    observed[step["name"]] = helpers.resource_state(step["name"], step["evidence"], plan)
        barrier = observed.get("barrier") == "present"
        boot_mismatch = record is not None and record["boot_id"] != inventory.get("boot_id")
        if record is None:
            state = "absent"
        elif (
            boot_mismatch
            or any(value == "ambiguous" for value in observed.values())
            or record["outcome"] == "uncertain"
        ):
            state = "uncertain"
        elif record["outcome"] == "active" and all(value == "present" for value in observed.values()):
            state = "active_verified"
        elif barrier and record["outcome"] in {"preparing", "protected_unavailable"}:
            state = "protected_tunnel_unavailable"
        elif record["outcome"] == "retired" and not barrier:
            state = "absent"
        else:
            state = "degraded"
        return {
            "version": 1,
            "mode": "host_default_status",
            "network_changes_applied": False,
            "state": state,
            "ordinary_host_egress_blocked": barrier,
            "operator_review_required": state in {"uncertain", "degraded"},
            "boot_identity_matches": not boot_mismatch,
            "desired_generation": plan.generation,
            "durable": record,
            "history_count": len(document["history"]),
            "observed_resources": observed,
            "inventory": inventory,
        }

    if already_locked:
        return inspect()
    with locked_host_store(target):
        return inspect()


def deactivate_host_protection(
    plan: HostProtectionPlan,
    store_path: str | Path,
    *,
    expose_host_egress: bool,
    kernel: HostKernel | None = None,
) -> dict:
    """Retire exact owned resources; barrier removal needs explicit authority."""
    if expose_host_egress is not True:
        raise HostProtectionError("deactivation requires explicit authority to expose ordinary host egress")
    helpers = kernel or _kernel(plan)
    if kernel is None and os.geteuid() != 0:
        raise HostProtectionError("host protection deactivation requires root")
    target = Path(store_path).absolute()
    with locked_host_store(target):
        document = read_host_store(target)
        record = document["record"]
        if record is None or record["plan_sha256"] != plan.fingerprint() or record["generation"] != plan.generation:
            raise HostProtectionError("matching host protection ownership evidence is absent")
        inventory = _validate_inventory(helpers.inventory(), plan, allow_owned=True)
        if inventory["boot_id"] != record["boot_id"]:
            raise HostProtectionError("host protection retirement cannot use evidence from another boot")
        if record["outcome"] == "retired":
            return host_protection_status(plan, target, kernel=helpers, already_locked=True)
        record["operation"] = "deactivate"
        record["outcome"] = "retiring"
        write_host_store(target, document)
        removers = {
            "remove_resolver": helpers.remove_resolver,
            "remove_routes": helpers.remove_routes,
            "remove_wireguard": helpers.remove_wireguard,
            "remove_endpoint": helpers.remove_endpoint,
            "remove_barrier": helpers.remove_barrier,
        }
        for retirement, original in _RETIREMENT:
            creation = _step(document, original)
            if creation is None or creation["state"] != "observed" or creation["evidence"] is None:
                raise HostProtectionError(f"cannot retire host {original} without observed creation evidence")
            current = _step(document, retirement)
            if current and current["state"] == "absent":
                continue
            retry_authorised = False
            if current and current["state"] == "observed":
                document = reopen_present_retirement(document, retirement, {"created_evidence": creation["evidence"]})
                write_host_store(target, document)
                current = _step(document, retirement)
                retry_authorised = True
            if current is not None:
                if current["state"] != "pending" or not retry_authorised:
                    raise HostProtectionError(f"host {original} retirement has unresolved evidence")
            else:
                document = record_step_intent(document, retirement, {"created_evidence": creation["evidence"]})
                write_host_store(target, document)
            if helpers.resource_state(original, creation["evidence"], plan) != "present":
                document["record"]["outcome"] = "uncertain"
                write_host_store(target, document)
                raise HostProtectionError(f"host {original} identity drifted before retirement")
            try:
                evidence = removers[retirement](plan, creation["evidence"])
                if helpers.resource_state(original, creation["evidence"], plan) != "absent":
                    raise HostProtectionError(f"host {original} remains after retirement")
            except BaseException:
                _persist_uncertain(target, document, retirement)
                raise
            document = record_step_evidence(document, retirement, "absent", evidence)
            if original == "barrier":
                document["record"]["ordinary_egress_blocked"] = False
            write_host_store(target, document)
        document["record"]["outcome"] = "retired"
        write_host_store(target, document)
        return host_protection_status(plan, target, kernel=helpers, already_locked=True)


def recover_host_protection(
    plan: HostProtectionPlan,
    store_path: str | Path,
    *,
    kernel: HostKernel | None = None,
    execute: bool = False,
) -> dict:
    """Classify interrupted steps, retaining the barrier and never exposing traffic."""
    helpers = kernel or _kernel(plan)
    target = Path(store_path).absolute()
    with locked_host_store(target):
        document = read_host_store(target)
        record = document["record"]
        if record is None:
            return host_protection_status(plan, target, kernel=helpers, already_locked=True)
        if record["plan_sha256"] != plan.fingerprint() or record["generation"] != plan.generation:
            raise HostProtectionError("recovery plan does not match durable host evidence")
        if execute:
            inventory = _validate_inventory(helpers.inventory(), plan, allow_owned=True)
            if inventory["boot_id"] != record["boot_id"]:
                raise HostProtectionError("cross-boot recovery must run through the early barrier transition")
        findings = []
        for step in record["steps"]:
            if step["state"] not in {"pending", "uncertain"}:
                continue
            original = step["name"].removeprefix("remove_")
            creation = _step(document, original)
            state, observed_evidence = helpers.observe_resource(original, plan)
            evidence = observed_evidence or step["evidence"] or (creation and creation["evidence"])
            findings.append({"step": step["name"], "observed": state})
            if not execute:
                continue
            if state == "absent":
                # Absence permits an activation retry, but does not prove a
                # partially retired object was ours or safely removed.
                document = record_step_evidence(document, step["name"], "absent", evidence or {})
            elif state == "present" and step["name"].startswith("remove_"):
                # Retirement may resume only against an independently
                # recorded creation identity, never a fresh name match.
                created = creation and creation["evidence"]
                if (
                    creation is not None
                    and creation["state"] == "observed"
                    and isinstance(created, dict)
                    and created
                    and helpers.resource_state(original, created, plan) == "present"
                ):
                    document = record_step_evidence(document, step["name"], "observed", created)
                else:
                    document["record"]["outcome"] = "uncertain"
            elif state == "present":
                # A pending creation has no durable creation identity.  Even
                # an exact configuration match could be a foreign object.
                document["record"]["outcome"] = "uncertain"
            else:
                document["record"]["outcome"] = "uncertain"
        if execute:
            write_host_store(target, document)
        status = host_protection_status(plan, target, kernel=helpers, already_locked=True)
        status["mode"] = "host_default_recovery"
        status["execute"] = execute
        status["findings"] = findings
        status["automatic_barrier_removal"] = False
        return status
