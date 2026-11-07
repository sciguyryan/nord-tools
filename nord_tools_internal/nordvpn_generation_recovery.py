"""Conservative generation-handover recovery and drift classification.

A handover record is intent, not ownership proof. Only the already authorised
replacement and retirement executors may mutate kernel resources. This module
never infers authority from an allocation name or an earlier status result.
"""

from __future__ import annotations

from collections.abc import Callable

from nord_tools_internal.nordvpn_consumer_reference_store import locked_consumer_references
from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_dns_confinement import (
    verify_dns_peer_allowed_ips,
    verify_dns_routes,
    verify_resolver_file,
)
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy
from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy
from nord_tools_internal.nordvpn_isolation_install import _verify_base_chains
from nord_tools_internal.nordvpn_underlay_install import verify_tunnel_route_readback
from nord_tools_internal.nordvpn_generation_handover import (
    AllocationGeneration,
    GenerationHandoverError,
    _advance_verified_handover,
    policy_digest,
    read_handover,
)
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_replacement_executor import (
    _packet_ready,
    _read,
    _verify,
)
from nord_tools_internal.nordvpn_runtime_consumers import _read as read_runtime_consumers_locked
from nord_tools_internal.nordvpn_startup import validate_startup_config


def _classify(record: dict, observed: dict, leases: dict) -> dict:
    """Classify fresh generation evidence; never infer kernel mutation authority.

    A lease is tied to the complete generation identity, not just a name. A
    missing or retired generation with a live lease is disputed, not cleaned.
    """
    if leases["version"] != 2:
        raise GenerationHandoverError("legacy consumer leases cannot be attributed to a generation")
    generations = {}
    bindings = record.get("generations", {})
    for generation_id in (record["old"], record["replacement"]):
        state = observed[generation_id]
        binding = bindings.get(generation_id)
        matching = []
        for lease in leases["leases"]:
            if lease["profile"] != record["profile"] or lease["generation_id"] != generation_id:
                continue
            if binding is not None and (
                lease["allocation_key"] != binding["allocation_key"]
                or lease["kernel_profile"] != binding["kernel_profile"]
            ):
                raise GenerationHandoverError("runtime lease conflicts with generation ownership binding")
            matching.append(lease)
        complete = (
            state["resource_count"] == 4 and state["states"] == ["active"] and state["findings"] == ["verified_current"]
        )
        absent = state["resource_count"] == 0 and not state["states"] and not state["findings"]
        retired = (
            state["resource_count"] > 0
            and state["states"] == ["retired"]
            and state["findings"] == ["consistent_retired"]
        )
        generations[generation_id] = {
            "ownership_converged": complete,
            "retired_or_absent": absent or retired,
            "lease_count": len(matching),
            "findings": state["findings"],
            "states": state["states"],
        }
    old = generations[record["old"]]
    new = generations[record["replacement"]]
    phase = record["phase"]
    if (old["retired_or_absent"] and old["lease_count"]) or (new["retired_or_absent"] and new["lease_count"]):
        disposition = "operator_review_lease_without_generation"
    elif phase in {"prepared", "verified"}:
        if not old["ownership_converged"]:
            disposition = "operator_review_old_generation"
        elif new["retired_or_absent"] and phase == "prepared":
            disposition = "eligible_for_explicit_reprovision"
        elif not new["ownership_converged"]:
            disposition = "operator_review_partial_replacement"
        elif phase == "prepared":
            disposition = "verify_replacement_before_promotion"
        else:
            disposition = "verified_awaiting_explicit_activation"
    elif not new["ownership_converged"]:
        disposition = "selected_generation_drift_fail_closed"
    elif old["lease_count"]:
        disposition = "draining_active_consumers"
    elif old["ownership_converged"]:
        disposition = "eligible_for_explicit_retirement"
    elif old["retired_or_absent"]:
        disposition = "old_generation_retired"
    else:
        disposition = "operator_review_partial_retirement"
    return {
        "schema_version": 1,
        "mode": "generation_recovery",
        "profile": record["profile"],
        "phase": phase,
        "selected_generation": record["replacement"] if phase in {"active", "draining"} else record["old"],
        "disposition": disposition,
        "generations": generations,
        "network_changes_applied": False,
        "automatic_kernel_repair_authorised": False,
    }


def _verify_live_confinement(namespace: str, resources: list[dict], tunnel: dict) -> None:
    """Recheck production default/endpoint routing and pinned namespace DNS.

    Names come from the ownership-verified journal, not untrusted discovery.
    This does not replace packet verification or certify the firewall forever.
    """
    identifiers = {item["identifier"] for item in resources if item["kind"] == "interface"}
    wireguard = [name for name in identifiers if name.startswith("ntwg")]
    underlay = [name for name in identifiers if name.startswith("ntul")]
    if len(wireguard) != 1 or len(underlay) != 1:
        raise GenerationHandoverError("generation interface roles are ambiguous")
    _verify_base_chains(
        namespace,
        NamespaceIsolationPolicy(
            tunnel_interface=wireguard[0],
            underlay_interface=underlay[0],
            endpoint_address=tunnel["endpoint_address"],
            endpoint_port=tunnel["endpoint_port"],
        ),
    )
    verify_tunnel_route_readback(namespace, wireguard[0], underlay[0], tunnel["endpoint_address"])
    if "dns_servers" in tunnel:
        resolver = NamespaceResolverPolicy(tuple(tunnel["dns_servers"]))
        verify_dns_routes(namespace, wireguard[0], resolver)
        verify_dns_peer_allowed_ips(namespace, wireguard[0], resolver)
        verify_resolver_file(namespace, resolver)


def recover_generation(
    config: object,
    *,
    handover_path: str,
    runtime_consumers_path: str,
    observe: Callable[[], dict],
    execute: bool = False,
    packet_verifier: Callable[[str], bool] | None = None,
    allow_reprovision: bool = False,
    expected_profile: str | None = None,
    expected_allocation_key: str | None = None,
) -> dict:
    """Reobserve under authority; optionally finish a fully verified prepared record.

    Reprovisioning is separately authorised, and only when the journal contains
    no resources for B. The production executor revalidates A and durable intent
    under its own locks before making changes. Activation and retirement remain
    separate explicit operations.
    """
    validated = validate_startup_config(config)
    policy = validate_policy(_read(validated["policy"]))
    with lifecycle_execution_lock(validated["journal"]), locked_consumer_references(runtime_consumers_path):
        record = read_handover(handover_path)
        if record["version"] != 2 or record["policy_sha256"] != policy_digest(policy):
            raise GenerationHandoverError("recovery record is not bound to the current policy")
        if expected_profile is not None and record["profile"] != expected_profile:
            raise GenerationHandoverError("recovery record belongs to another profile")
        if expected_allocation_key is not None and any(
            record["generations"][generation_id]["allocation_key"] != expected_allocation_key
            for generation_id in (record["old"], record["replacement"])
        ):
            raise GenerationHandoverError("recovery record belongs to another allocation")
        # The status function re-enters the same process-wide locks, which are
        # flock-based and therefore cannot be nested safely. Derive status from
        # the same preflight machinery while retaining our authority locks.
        from nord_tools_internal.nordvpn_lifecycle import validate_journal
        from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership

        journal = validate_journal(_read(validated["journal"]))
        preflight = preflight_ownership(journal, _read(validated["bindings"]), observe(), _read(validated["intent"]))
        if preflight.get("operator_review_required"):
            raise GenerationHandoverError("unresolved ownership evidence requires operator review")
        findings = {item["allocation_id"]: item["finding"] for item in preflight["resources"]}
        states = {item["allocation_id"]: item["state"] for item in journal["events"]}
        observed = {}
        owned_resources = {}
        for generation_id in (record["old"], record["replacement"]):
            generation = AllocationGeneration(**record["generations"][generation_id])
            resources = [
                item for item in journal["allocations"]["resources"] if item["profile"] == generation.kernel_profile
            ]
            owned_resources[generation_id] = resources
            if resources and (
                len(resources) != 4
                or sorted(item["kind"] for item in resources) != ["interface", "interface", "interface", "namespace"]
            ):
                # An unexpected shape must never be mistaken for a valid or
                # cleanly retired generation.
                resource_states = ["inconsistent"]
                resource_findings = ["operator_review"]
            else:
                resource_states = sorted({states.get(item["allocation_id"], "unknown") for item in resources})
                resource_findings = sorted({findings.get(item["allocation_id"], "unobserved") for item in resources})
            observed[generation_id] = {
                "resource_count": len(resources),
                "states": resource_states,
                "findings": resource_findings,
            }
        leases = read_runtime_consumers_locked(runtime_consumers_path, policy)
        result = _classify(record, observed, leases)
        # Kernel ownership alone does not prove the selected tunnel can carry
        # packets. A failed packet probe is drift, never fallback authority.
        if (
            record["phase"] in {"active", "draining"}
            and result["generations"][record["replacement"]]["ownership_converged"]
        ):
            replacement = AllocationGeneration(**record["generations"][record["replacement"]])
            dns = tuple(validated["tunnels"][replacement.profile].get("dns_servers", ()))
            verifier = packet_verifier or (
                lambda namespace: _packet_ready(namespace, dns, validated["tunnels"][replacement.profile])
            )
            try:
                namespace = _verify(validated, replacement, observe=observe, packet_verifier=verifier)
                _verify_live_confinement(
                    namespace,
                    owned_resources[record["replacement"]],
                    validated["tunnels"][replacement.profile],
                )
            except (RegistryError, ValueError, OSError, RuntimeError) as exc:
                result["disposition"] = "selected_generation_drift_fail_closed"
                result["selected_packet_verified"] = False
                result["drift_reason"] = type(exc).__name__
            else:
                result["selected_packet_verified"] = True
        if execute and result["disposition"] == "verify_replacement_before_promotion":
            replacement = AllocationGeneration(**record["generations"][record["replacement"]])
            dns = tuple(validated["tunnels"][replacement.profile].get("dns_servers", ()))
            verifier = packet_verifier or (
                lambda namespace: _packet_ready(namespace, dns, validated["tunnels"][replacement.profile])
            )
            namespace = _verify(validated, replacement, observe=observe, packet_verifier=verifier)
            _verify_live_confinement(
                namespace,
                owned_resources[record["replacement"]],
                validated["tunnels"][replacement.profile],
            )
            _advance_verified_handover(
                handover_path,
                expected_phase="prepared",
                next_phase="verified",
                policy=policy,
                verified=True,
            )
            result["phase"] = "verified"
            result["disposition"] = "verified_awaiting_explicit_activation"
            result["durable_record_changed"] = True
        else:
            result["durable_record_changed"] = False
    # Never call the production executor with lifecycle or lease locks already
    # held. It acquires both itself and must revalidate after the hand-off.
    if execute and allow_reprovision and result["disposition"] == "eligible_for_explicit_reprovision":
        from nord_tools_internal.nordvpn_replacement_executor import prepare_replacement

        repaired = prepare_replacement(
            validated,
            profile=record["profile"],
            allocation_key=record["generations"][record["old"]]["allocation_key"],
            old_generation_id=record["old"],
            replacement_generation_id=record["replacement"],
            handover_path=handover_path,
            runtime_consumers_path=runtime_consumers_path,
            observe=observe,
            packet_verifier=packet_verifier,
        )
        return {
            **result,
            "phase": repaired["phase"],
            "disposition": "verified_awaiting_explicit_activation",
            "durable_record_changed": True,
            "network_changes_applied": repaired["network_changes_applied"],
            "repair": "verified_reprovision",
        }
    return result
