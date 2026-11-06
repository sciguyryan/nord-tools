"""Verified generation replacement built on production lifecycle executors.

The handover journal coordinates selection; it never substitutes for fresh
creation-time ownership evidence.  Generation kernel profiles are distinct, so
provisioning and cleanup can operate on B and A independently.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Callable

from nord_tools_internal.nordvpn_allocation_profiles import (
    kernel_profile_for_allocation,
    kernel_profile_for_generation,
)
from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup
from nord_tools_internal.nordvpn_consumer_reference_store import (
    ConsumerReferenceError,
    locked_consumer_references,
    read_private_json,
)
from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_generation_handover import (
    AllocationGeneration,
    GenerationHandoverError,
    _advance_verified_handover,
    policy_digest,
    prepare_generation_handover,
    read_handover,
)
from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state
from nord_tools_internal.nordvpn_runtime_consumers import _read as read_runtime_consumers_locked
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups
from nord_tools_internal.nordvpn_startup import validate_startup_config


def _read(path: str | Path) -> dict:
    document = read_private_json(path)
    if not isinstance(document, dict):
        raise RegistryError(f"{path} must contain a JSON object")
    return document


def _generation_resources(generation: AllocationGeneration, journal: dict, preflight: dict) -> list[dict]:
    resources = [item for item in journal["allocations"]["resources"] if item["profile"] == generation.kernel_profile]
    if len(resources) != 4 or sorted(item["kind"] for item in resources) != [
        "interface",
        "interface",
        "interface",
        "namespace",
    ]:
        raise RegistryError("generation does not have one complete production allocation")
    states = {item["allocation_id"]: item["state"] for item in journal["events"]}
    findings = {item["allocation_id"]: item["finding"] for item in preflight["resources"]}
    if any(states.get(item["allocation_id"]) != "active" for item in resources):
        raise RegistryError("generation resources are not active")
    if any(findings.get(item["allocation_id"]) != "verified_current" for item in resources):
        raise RegistryError("generation ownership is not freshly verified")
    return resources


def _namespace(resources: list[dict]) -> str:
    return next(item["identifier"] for item in resources if item["kind"] == "namespace")


def _packet_ready(namespace: str, dns_servers: tuple[str, ...], tunnel: dict) -> bool:
    """Require DNS, a pinned WireGuard peer and a tunnel-routed DNS path."""
    if not dns_servers:
        return False
    query_script = """
import socket, sys
server = sys.argv[1]
family = socket.AF_INET6 if ':' in server else socket.AF_INET
query = b'NT\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00' + b'\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'
sock = socket.socket(family, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(query, (server, 53))
reply = sock.recv(4096)
if len(reply) < 12 or reply[:2] != b'NT' or not reply[2] & 0x80:
    raise SystemExit(2)
"""
    try:
        dns = subprocess.run(
            ["ip", "netns", "exec", namespace, sys.executable, "-I", "-c", query_script, dns_servers[0]],
            capture_output=True,
            timeout=10,
            check=False,
        )
        handshake = subprocess.run(
            ["ip", "netns", "exec", namespace, "wg", "show", "all", "latest-handshakes"],
            capture_output=True,
            timeout=5,
            check=False,
            text=True,
        )
        route = subprocess.run(
            ["ip", "-n", namespace, "-j", "route", "get", dns_servers[0]],
            capture_output=True,
            timeout=5,
            check=False,
            text=True,
        )
        endpoint = subprocess.run(
            ["ip", "netns", "exec", namespace, "wg", "show", "all", "endpoints"],
            capture_output=True,
            timeout=5,
            check=False,
            text=True,
        )
        transfer = subprocess.run(
            ["ip", "netns", "exec", namespace, "wg", "show", "all", "transfer"],
            capture_output=True,
            timeout=5,
            check=False,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RegistryError("replacement packet-readiness observation failed") from None
    diagnostic = "; ".join(
        (
            f"dns_exit={dns.returncode}",
            f"dns_error={dns.stderr.decode(errors='replace').strip()[-160:] or '-'}",
            f"route={route.stdout.strip()[:240] or '-'}",
            f"endpoint={endpoint.stdout.strip()[:160] or '-'}",
            f"handshake={handshake.stdout.strip()[:160] or '-'}",
            f"transfer={transfer.stdout.strip()[:160] or '-'}",
        )
    )
    if dns.returncode or handshake.returncode or route.returncode or endpoint.returncode or transfer.returncode:
        raise RegistryError(f"replacement packet readiness failed ({diagnostic})")
    expected_peer = tunnel["peer_public_key"]
    expected_address = ipaddress.ip_address(tunnel["endpoint_address"])
    expected_port = tunnel["endpoint_port"]

    def peer_rows(output: str) -> dict[tuple[str, str], str]:
        rows = {}
        for line in output.splitlines():
            parts = line.split("\t", 2)
            if len(parts) != 3 or not parts[0] or not parts[1] or (parts[0], parts[1]) in rows:
                raise RegistryError("replacement WireGuard peer observation is malformed or ambiguous")
            rows[(parts[0], parts[1])] = parts[2]
        return rows

    handshakes = peer_rows(handshake.stdout)
    endpoints = peer_rows(endpoint.stdout)
    transfers = peer_rows(transfer.stdout)
    if len(handshakes) != 1 or handshakes.keys() != endpoints.keys() or handshakes.keys() != transfers.keys():
        raise RegistryError("replacement WireGuard observations disagree on the pinned peer")
    (interface, peer), timestamp = next(iter(handshakes.items()))
    if peer != expected_peer or not timestamp.isdigit() or int(timestamp) <= 0:
        raise RegistryError(f"replacement tunnel has no verified pinned-peer handshake ({diagnostic})")
    endpoint_value = endpoints[(interface, peer)]
    try:
        if endpoint_value.startswith("["):
            address, port = endpoint_value[1:].split("]:", 1)
        else:
            address, port = endpoint_value.rsplit(":", 1)
        if ipaddress.ip_address(address) != expected_address or int(port) != expected_port:
            raise ValueError("unexpected endpoint")
        received, sent = transfers[(interface, peer)].split("\t")
        if not received.isdigit() or not sent.isdigit():
            raise ValueError("invalid transfer counters")
        routes = json.loads(route.stdout)
        if (
            not isinstance(routes, list)
            or len(routes) != 1
            or not isinstance(routes[0], dict)
            or routes[0].get("dev") != interface
            or routes[0].get("dst") != dns_servers[0]
            or routes[0].get("type", "unicast") != "unicast"
        ):
            raise ValueError("DNS route does not use the verified WireGuard interface")
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RegistryError(f"replacement peer, endpoint or DNS route is inconsistent ({diagnostic})") from exc
    return True


def _verify(
    config: dict,
    generation: AllocationGeneration,
    *,
    observe: Callable[[], dict],
    packet_verifier: Callable[[str], bool],
) -> str:
    journal = validate_journal(_read(config["journal"]))
    preflight = preflight_ownership(journal, _read(config["bindings"]), observe(), _read(config["intent"]))
    if preflight.get("operator_review_required"):
        raise RegistryError("ownership review is required before generation verification")
    resources = _generation_resources(generation, journal, preflight)
    namespace = _namespace(resources)
    if packet_verifier(namespace) is not True:
        raise RegistryError("replacement failed packet-level tunnel readiness")
    return namespace


def _production_provision(config: dict, policy: dict, replacement: AllocationGeneration) -> dict:
    """Provision B through restore_boot_state using a generation-scoped policy."""
    profile = replacement.profile
    if profile not in policy["vpn_profiles"] or profile not in config["tunnels"]:
        raise RegistryError("replacement profile lacks a pinned production tunnel plan")
    generated_profiles = dict(policy["vpn_profiles"])
    definition = dict(generated_profiles[profile])
    sharing = definition["sharing"]
    if sharing == "shared":
        generated_profiles.pop(profile)
        consumers = tuple(name for name, application in policy["applications"].items() if application["vpn"] == profile)
    else:
        groups = [
            group for group in resolve_ownership_groups(policy) if group.allocation_key == replacement.allocation_key
        ]
        if len(groups) != 1 or groups[0].profile != profile:
            raise RegistryError("replacement allocation is not an unambiguous policy ownership group")
        consumers = groups[0].consumers
        # The generation kernel profile is already allocation-specific; do not
        # let normal isolated-profile expansion hash it into another identity.
        definition["sharing"] = "shared"
    generated_profiles[replacement.kernel_profile] = definition
    generated_applications = {
        name: {
            **definition,
            **({"vpn": replacement.kernel_profile} if name in consumers else {}),
        }
        for name, definition in policy["applications"].items()
    }
    generated_defaults = dict(policy["defaults"])
    if sharing == "shared" and generated_defaults["vpn"] == profile:
        generated_defaults["vpn"] = replacement.kernel_profile
    generated_policy = {
        **policy,
        "defaults": generated_defaults,
        "vpn_profiles": generated_profiles,
        "applications": generated_applications,
    }
    generated_tunnels = dict(config["tunnels"])
    generated_tunnels[replacement.kernel_profile] = generated_tunnels.pop(profile)
    generated_credentials = dict(config["credentials"])
    generated_credentials[replacement.kernel_profile] = generated_credentials.pop(profile, None)
    generated_config = {
        **config,
        "graph": None,
        "tunnels": generated_tunnels,
        "credentials": generated_credentials,
    }
    generated_config.pop("handovers", None)
    if generated_config["credentials"][replacement.kernel_profile] is None:
        raise RegistryError("replacement profile lacks a pinned production credential")
    directory = Path(config["journal"]).parent
    descriptor, filename = tempfile.mkstemp(prefix=".nord-replacement-policy.", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(generated_policy, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        generated_config["policy"] = filename
        return restore_boot_state(generated_config)
    finally:
        try:
            os.unlink(filename)
        except FileNotFoundError:
            pass


def prepare_replacement(
    config: object,
    *,
    profile: str,
    allocation_key: str,
    old_generation_id: str,
    replacement_generation_id: str,
    handover_path: str,
    runtime_consumers_path: str,
    observe: Callable[[], dict],
    provision: Callable[[dict, dict, AllocationGeneration], object] | None = None,
    packet_verifier: Callable[[str], bool] | None = None,
) -> dict:
    """Persist intent, provision independent B, then mark B structurally and packet verified."""
    validated = validate_startup_config(config)
    policy = validate_policy(_read(validated["policy"]))
    if profile not in policy["vpn_profiles"]:
        raise RegistryError("replacement profile is not present in the policy")
    sharing = policy["vpn_profiles"][profile]["sharing"]
    matching_groups = [
        group
        for group in resolve_ownership_groups(policy)
        if group.profile == profile and group.allocation_key == allocation_key
    ]
    if sharing == "shared":
        if allocation_key != f"profile:{profile}":
            raise RegistryError("shared replacement allocation key does not match its profile")
    elif len(matching_groups) != 1:
        raise RegistryError("isolated replacement requires an exact registered allocation key")
    digest = policy_digest(policy)
    old_kernel = kernel_profile_for_allocation(allocation_key, profile, sharing)
    old = AllocationGeneration(profile, allocation_key, old_generation_id, old_kernel, digest)
    replacement = AllocationGeneration(
        profile,
        allocation_key,
        replacement_generation_id,
        kernel_profile_for_generation(profile, allocation_key, replacement_generation_id),
        digest,
    )
    resume_phase = None
    # Preparation holds lifecycle then consumer authority while establishing A
    # and the durable selection intent. Active A leases are deliberately valid.
    with lifecycle_execution_lock(validated["journal"]), locked_consumer_references(runtime_consumers_path):
        journal = validate_journal(_read(validated["journal"]))
        preflight = preflight_ownership(journal, _read(validated["bindings"]), observe(), _read(validated["intent"]))
        _generation_resources(old, journal, preflight)
        if Path(handover_path).exists() or Path(handover_path).is_symlink():
            current = read_handover(handover_path)
            expected_generations = {
                old.generation_id: old.__dict__,
                replacement.generation_id: replacement.__dict__,
            }
            if (
                current["version"] != 2
                or current["profile"] != profile
                or current["policy_sha256"] != digest
                or current["generations"] != expected_generations
                or current["phase"] not in {"prepared", "verified", "active", "draining"}
            ):
                raise GenerationHandoverError("existing handover does not match the requested replacement")
            resume_phase = current["phase"]
        else:
            prepare_generation_handover(handover_path, old=old, replacement=replacement, policy=policy)
    if resume_phase in {"verified", "active", "draining"}:
        return {
            "mode": "generation_replacement",
            "phase": resume_phase,
            "network_changes_applied": False,
        }
    (provision or _production_provision)(validated, policy, replacement)
    dns = tuple(validated["tunnels"][profile].get("dns_servers", ()))
    verifier = packet_verifier or (
        lambda namespace: _packet_ready(namespace, dns, validated["tunnels"][replacement.profile])
    )
    with lifecycle_execution_lock(validated["journal"]), locked_consumer_references(runtime_consumers_path):
        _verify(validated, replacement, observe=observe, packet_verifier=verifier)
        updated = _advance_verified_handover(
            handover_path,
            expected_phase="prepared",
            next_phase="verified",
            policy=policy,
            verified=True,
        )
    return {"mode": "generation_replacement", "phase": updated["phase"], "network_changes_applied": True}


def activate_replacement(
    config: object,
    *,
    handover_path: str,
    runtime_consumers_path: str,
    observe: Callable[[], dict],
    packet_verifier: Callable[[str], bool] | None = None,
) -> dict:
    """Freshly verify B and durably switch future cooperating launches to it."""
    validated = validate_startup_config(config)
    policy = validate_policy(_read(validated["policy"]))
    with lifecycle_execution_lock(validated["journal"]), locked_consumer_references(runtime_consumers_path):
        handover = read_handover(handover_path)
        if handover["phase"] != "verified" or handover["policy_sha256"] != policy_digest(policy):
            raise GenerationHandoverError("replacement is not verified for this policy")
        replacement = AllocationGeneration(**handover["generations"][handover["replacement"]])
        dns = tuple(validated["tunnels"][replacement.profile].get("dns_servers", ()))
        verifier = packet_verifier or (
            lambda namespace: _packet_ready(namespace, dns, validated["tunnels"][replacement.profile])
        )
        _verify(validated, replacement, observe=observe, packet_verifier=verifier)
        updated = _advance_verified_handover(
            handover_path,
            expected_phase="verified",
            next_phase="active",
            policy=policy,
            verified=True,
        )
    return {"mode": "generation_replacement", "phase": updated["phase"], "selected": updated["replacement"]}


def replacement_status(
    config: object,
    *,
    handover_path: str,
    runtime_consumers_path: str,
    observe: Callable[[], dict],
) -> dict:
    """Reconcile durable intent with fresh ownership and exact-generation leases."""
    validated = validate_startup_config(config)
    policy = validate_policy(_read(validated["policy"]))
    with lifecycle_execution_lock(validated["journal"]), locked_consumer_references(runtime_consumers_path):
        handover = read_handover(handover_path)
        if handover["version"] != 2 or handover["policy_sha256"] != policy_digest(policy):
            raise GenerationHandoverError("handover is not allocation-bound to the current policy")
        journal = validate_journal(_read(validated["journal"]))
        preflight = preflight_ownership(journal, _read(validated["bindings"]), observe(), _read(validated["intent"]))
        findings = {item["allocation_id"]: item["finding"] for item in preflight["resources"]}
        states = {item["allocation_id"]: item["state"] for item in journal["events"]}
        generations = {}
        for generation_id in (handover["old"], handover["replacement"]):
            generation = AllocationGeneration(**handover["generations"][generation_id])
            resources = [
                item for item in journal["allocations"]["resources"] if item["profile"] == generation.kernel_profile
            ]
            generations[generation_id] = {
                "kernel_profile": generation.kernel_profile,
                "resource_count": len(resources),
                "states": sorted({states.get(item["allocation_id"], "unknown") for item in resources}),
                "findings": sorted({findings.get(item["allocation_id"], "unobserved") for item in resources}),
            }
        leases = read_runtime_consumers_locked(runtime_consumers_path, policy)
        lease_counts = {
            generation_id: sum(
                1 for item in leases["leases"] if leases["version"] == 2 and item["generation_id"] == generation_id
            )
            for generation_id in (handover["old"], handover["replacement"])
        }
        selected = handover["replacement"] if handover["phase"] in {"active", "draining"} else handover["old"]
        selected_state = generations[selected]
        launchable = (
            selected_state["resource_count"] == 4
            and selected_state["states"] == ["active"]
            and selected_state["findings"] == ["verified_current"]
        )
        return {
            "mode": "generation_replacement_status",
            "phase": handover["phase"],
            "profile": handover["profile"],
            "selected_generation": selected,
            "selected_generation_ownership_verified": launchable,
            "generations": generations,
            "lease_counts": lease_counts,
            "safe_to_retire_old": launchable and lease_counts[handover["old"]] == 0,
            "network_changes_applied": False,
        }


def retire_old_generation(
    config: object,
    *,
    handover_path: str,
    runtime_consumers_path: str,
    observe: Callable[[], dict],
    cleanup=plan_cleanup,
    execute: bool = False,
    expected_generation_id: str | None = None,
    packet_verifier: Callable[[str], bool] | None = None,
) -> dict:
    """Retire only A after exact-generation leases and ownership are clear."""
    validated = validate_startup_config(config)
    policy = validate_policy(_read(validated["policy"]))
    with lifecycle_execution_lock(validated["journal"]), locked_consumer_references(runtime_consumers_path):
        handover = read_handover(handover_path)
        if handover["phase"] not in {"active", "draining"}:
            raise GenerationHandoverError("old generation cannot retire before activation")
        if handover["version"] != 2 or handover["policy_sha256"] != policy_digest(policy):
            raise GenerationHandoverError("handover is not bound to the current policy")
        old = AllocationGeneration(**handover["generations"][handover["old"]])
        replacement = AllocationGeneration(**handover["generations"][handover["replacement"]])
        if expected_generation_id is not None and old.generation_id != expected_generation_id:
            raise GenerationHandoverError("requested generation is not the draining old generation")
        leases = read_runtime_consumers_locked(runtime_consumers_path, policy)
        if leases["version"] != 2:
            raise ConsumerReferenceError("legacy leases are ambiguous and prevent generation retirement")
        if any(item["generation_id"] == old.generation_id for item in leases["leases"]):
            raise ConsumerReferenceError("old generation retains consumers or launch reservations")
        journal = validate_journal(_read(validated["journal"]))
        preflight = preflight_ownership(journal, _read(validated["bindings"]), observe(), _read(validated["intent"]))
        _generation_resources(old, journal, preflight)
        # A is irreversibly removed only while B is independently healthy.
        # Check under the same lifecycle and lease locks as cleanup.
        dns = tuple(validated["tunnels"][replacement.profile].get("dns_servers", ()))
        verifier = packet_verifier or (
            lambda namespace: _packet_ready(namespace, dns, validated["tunnels"][replacement.profile])
        )
        _verify(validated, replacement, observe=observe, packet_verifier=verifier)
        if execute and handover["phase"] == "active":
            _advance_verified_handover(
                handover_path,
                expected_phase="active",
                next_phase="draining",
                policy=policy,
                verified=True,
                old_consumers=0,
            )
        # Cleanup revalidates ownership before mutation while the authority
        # locks remain held. Passing no desired policy makes only the explicit
        # scope removable; every other generation/profile is preserved.
        result = cleanup(
            validated["journal"],
            validated["bindings"],
            intent_path=validated["intent"],
            selected_profiles=(old.kernel_profile,),
            desired_policy=None,
            consumer_policy=policy,
            runtime_consumers_path=runtime_consumers_path,
            resolvers=True,
            execute=execute,
            already_locked=True,
        )
    return {**result, "generation_id": old.generation_id, "kernel_profile": old.kernel_profile}
