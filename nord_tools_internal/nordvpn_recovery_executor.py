"""Conservative crash, restart and interrupted-cleanup recovery.

This module is the only sanctioned path for resolving the uncertainty the
provisioning and cleanup executors can leave behind. It plans from the evidence
on disk, never from assumption: every unresolved operation intent and every
interrupted lifecycle state is paired with a fresh read-only observation and
classified into a small set of dispositions whose obligations are stated exactly
in the plan.

Two authority walls divide the plan. Boot execution is state convergence only:
everything is already certified by recorded creation time bindings, so only the
durable bookkeeping is finished, and any unresolved uncertainty aborts the run
for review; nothing at boot deletes beyond the identity-verified rollback of a
half-built creation recorded with a pending intent. Operator execution adds the
deletions at all: resuming a confirmed retirement, rolling back anything the
boot wall refused, and resolving uncertain outcomes once fresh evidence proves
them. Lookalike namespaces, live-but-unbound resources and mixed evidence are
never touched; they are listed with their exact findings and nothing worse is
done to them.
"""

from __future__ import annotations

from contextlib import nullcontext
import datetime
from pathlib import Path

from nord_tools_internal.nordvpn_cleanup_executor import (
    _ABSENT_FINDINGS,
    _REVIEW,
    CleanupKernel,
    _execution_lock,
    _observed_links,
    _read_document,
    _real_kernel as _cleanup_kernel,
)

from nord_tools_internal.nordvpn_lifecycle import record_transition, validate_journal
from nord_tools_internal.nordvpn_drift_recovery_policy import classify_drift_recovery
from nord_tools_internal.nordvpn_lifecycle_store import update_journal
from nord_tools_internal.nordvpn_operation_store import update_intent, update_recovered_intent
from nord_tools_internal.nordvpn_operational_preflight import verify_operational_preflight
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError
from nord_tools_internal.nordvpn_registry import RegistryError


BOOT = "boot"
OPERATOR = "operator"
_INTERRUPTED_STATES = frozenset({"creating", "retiring", "failed", "degraded"})
_EXECUTABLE = frozenset(
    {
        "complete_creation",
        "rollback_creation",
        "resolve_create_failed",
        "complete_retirement_records",
        "resume_retirement",
    }
)


def _retire_chain(current: str | None) -> tuple[str, ...]:
    """The canonical record-only chain from any lifecycle state to retirement."""
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
        raise RegistryError(f"unknown lifecycle state {current!r} during recovery")
    sequence = reaches[current]
    if sequence is None:
        return ()
    return sequence + ("retired",)


def _current_generation(allocations: dict[str, dict], states: dict[str, str], profile: str) -> list[dict]:
    """Return the profile generation that can still affect the live host.

    Allocation history is append-only, so recreating a cleaned profile leaves
    its retired generations in the journal.  Those historical allocations
    must not make a newly staged generation look mixed or partially bound.
    """
    return [
        resource
        for resource in allocations.values()
        if resource["profile"] == profile and states.get(resource["allocation_id"]) != "retired"
    ]


def plan_recovery(
    journal_path: str | Path,
    bindings_path: str | Path,
    intent_path: str | Path | None,
    *,
    execute: bool = False,
    boot: bool = False,
    resolvers: bool = False,
    kernel: CleanupKernel | None = None,
    recorded_at: str | None = None,
    already_locked: bool = False,
    operational_preflight_complete: bool = False,
) -> dict:
    """Classify the uncertain evidence and, when executed, converge what is safe.

    Boot execution is the state-convergence wall: only certified bookkeeping
    happens and anything unresolved aborts the run for review. Operator
    execution adds deletions and evidence-gated resolution of uncertain
    outcomes, because an operator explicitly invoked this command.
    """
    if intent_path is None:
        raise RegistryError("recovery requires the operation intent store; recovery exists for exactly that evidence")
    if execute and kernel is None and not operational_preflight_complete:
        verify_operational_preflight("namespace")
    helpers = kernel or _cleanup_kernel()
    logged_at = recorded_at or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    with _execution_lock(journal_path) if not already_locked else nullcontext():
        journal = validate_journal(_read_document(journal_path))
        bindings = _read_document(bindings_path)
        intents = _read_document(intent_path)
        observation = helpers.observe()
        preflight = preflight_ownership(journal, bindings, observation, intents)
        bindings_by_token = {entry["allocation_id"]: entry for entry in bindings["bindings"]}
        unresolved = [
            operation for operation in intents.get("operations", []) if operation["outcome"] in {"pending", "uncertain"}
        ]
        items = _classify(journal, intents, helpers, bindings_by_token, preflight)
        reviewed = [item for item in items if item["disposition"] == _REVIEW and item.get("profile_quarantined", True)]
        report = {
            "version": 1,
            "mode": "startup_recovery_report",
            "executed": False,
            "network_changes_applied": False,
            "boot_mode": boot,
            "authority": BOOT if boot else OPERATOR,
            "operator_review_required": bool(reviewed)
            or any(operation["outcome"] == "uncertain" for operation in unresolved),
            "items": items,
            "review_required": reviewed,
            "unclaimed": preflight["unclaimed"],
            "actions": [],
            "drift_policy": classify_drift_recovery(items),
            "recorded_at": logged_at,
            "limitations": (
                "This recovery resolves only what recorded creation-time bindings and fresh observations certify. "
                "Lookalike or unbound live resources are never touched; uncertain outcomes require explicit "
                "operator execution; deletions never touch the host outside owned namespaces and interfaces."
            ),
        }
        if not execute:
            return report
        actions = _execute_items(items, helpers, journal_path, bindings_path, intent_path, resolvers, boot)
        report["executed"] = True
        report["network_changes_applied"] = any(action.get("kernel_changed") for action in actions)
        report["actions"] = actions
        # The report describes the state after the run, not the pre-run plan.
        final_journal = validate_journal(_read_document(journal_path))
        final_bindings = _read_document(bindings_path)
        final_intents = _read_document(intent_path)
        final_items = _classify(
            final_journal,
            final_intents,
            helpers,
            {entry["allocation_id"]: entry for entry in final_bindings["bindings"]},
            preflight_ownership(final_journal, final_bindings, helpers.observe(), final_intents),
        )
        report["items"] = final_items
        report["drift_policy"] = classify_drift_recovery(final_items)
        reviewed = [
            item for item in final_items if item["disposition"] == _REVIEW and item.get("profile_quarantined", True)
        ]
        report["review_required"] = reviewed
        report["operator_review_required"] = bool(reviewed) or any(
            operation["outcome"] == "uncertain" for operation in final_intents.get("operations", [])
        )
        if boot:
            resolved_profiles = {action["profile"] for action in actions if action.get("action") == "rollback_deleted"}
            resolved_tokens = {action["allocation_id"] for action in actions}
            leftover_review = [item for item in reviewed if item["profile"] not in resolved_profiles]
            unexecuted_authority = [
                item
                for item in items
                if item["disposition"] != _REVIEW
                and item["authority"] == OPERATOR
                and item["allocation_id"] not in resolved_tokens
            ]
            remaining = (
                leftover_review
                or unexecuted_authority
                or [item for item in items if item.get("outcome") == "uncertain"]
            )
            if remaining:
                raise ProvisioningUncertainError(
                    "boot recovery leaves uncertain evidence for operator review: "
                    + "; ".join(f"{item['identifier']}: {item['disposition']}" for item in remaining[:4])
                )
        return report


def _classify(
    journal: dict,
    intents: dict,
    helpers,
    bindings_by_token: dict,
    preflight,
) -> list[dict]:
    """One disposition per unresolved operation or interrupted record.

    A pending or uncertain intent makes the readiness gate report the
    resource as uncertain intent regardless of the kernel, so absence and
    identity are judged from the fresh observation here, never from that gate
    finding.
    """
    allocations = {resource["allocation_id"]: resource for resource in journal["allocations"]["resources"]}
    states = {event["allocation_id"]: event["state"] for event in journal["events"]}
    findings = {item["allocation_id"]: item for item in preflight["resources"]}
    links = _observed_links(helpers.observe())
    unresolved_by_token = {
        operation["allocation_id"]: operation
        for operation in intents.get("operations", [])
        if operation["outcome"] in {"pending", "uncertain"}
    }
    # Record-only bookkeeping stays boot-level; any state-advancing convergence
    # for a generation with an uncertain intent belongs to the operator.
    uncertain_profiles = {
        allocations[token]["profile"]
        for token, operation in unresolved_by_token.items()
        if operation["outcome"] == "uncertain"
    }
    # A namespace creation intent can precede all kernel mutations while its
    # dependent allocations have already entered "creating". Converge that
    # generation only when every allocation is unbound, no named resource is
    # observed, and no other operation could have started a mutation.
    pristine_profiles: set[str] = set()
    for token, operation in unresolved_by_token.items():
        root = allocations[token]
        if root["kind"] != "namespace" or operation["action"] != "create":
            continue
        profile = root["profile"]
        generation = _current_generation(allocations, states, profile)
        if any(resource["allocation_id"] in bindings_by_token for resource in generation):
            continue
        if any(
            other["allocation_id"] != token
            for other in intents.get("operations", [])
            if allocations[other["allocation_id"]]["profile"] == profile
        ):
            continue
        if any(states.get(resource["allocation_id"]) != "creating" for resource in generation):
            continue
        if any(
            helpers.netns_identity(resource["identifier"]) is not None
            for resource in generation
            if resource["kind"] == "namespace"
        ):
            continue
        if any(
            (scope, resource["identifier"]) in links
            for resource in generation
            if resource["kind"] == "interface"
            for scope in ("host", root["identifier"])
        ):
            continue
        pristine_profiles.add(profile)

    # A namespace creation may be interrupted before its first kernel call,
    # leaving its dependent allocations staged but never bound. Only permit
    # record-only retirement when the entire unbound generation is absent in
    # the fresh observation and the namespace has a pending create intent.
    # A same-name host link or any live namespace prevents this proof.
    observed = helpers.observe()
    observed_names = {link["name"] for link in observed.get("host_interfaces", [])}
    observed_names.update(
        link["name"] for namespace in observed.get("namespace_details", []) for link in namespace.get("interfaces", [])
    )
    absent_staged_profiles: set[str] = set()
    for token, operation in unresolved_by_token.items():
        namespace = allocations[token]
        if operation["action"] != "create" or namespace["kind"] != "namespace":
            continue
        profile = namespace["profile"]
        generation = _current_generation(allocations, states, profile)
        if (
            helpers.netns_identity(namespace["identifier"]) is None
            and not any(resource["allocation_id"] in bindings_by_token for resource in generation)
            and not any(resource["identifier"] in observed_names for resource in generation)
            and not any(
                other["allocation_id"] != token and other["allocation_id"] in unresolved_by_token
                for other in generation
            )
            and all(states.get(resource["allocation_id"]) == "creating" for resource in generation)
        ):
            absent_staged_profiles.add(profile)

    # A failed provisioning attempt can remove its namespace before returning
    # while leaving only a partial set of creation-time bindings. The namespace
    # binding and fresh global name inventory then prove that the entire failed
    # generation is absent; explicit operator recovery may retire its records
    # without inventing ownership for the never-bound interface.
    rolled_back_profiles: set[str] = set()
    for token, operation in unresolved_by_token.items():
        namespace = allocations[token]
        if operation["action"] != "create" or namespace["kind"] != "namespace":
            continue
        profile = namespace["profile"]
        generation = _current_generation(allocations, states, profile)
        namespace_binding = bindings_by_token.get(token)
        if (
            operation["outcome"] == "uncertain"
            and namespace_binding is not None
            and helpers.netns_identity(namespace["identifier"]) is None
            and all(states.get(resource["allocation_id"]) == "failed" for resource in generation)
            and not any(resource["identifier"] in observed_names for resource in generation)
            and not any(
                other["allocation_id"] != token and other["allocation_id"] in unresolved_by_token
                for other in generation
            )
        ):
            rolled_back_profiles.add(profile)

    items: list[dict] = []
    seen: set[str] = set()

    for token, operation in sorted(
        unresolved_by_token.items(), key=lambda entry: (allocations[entry[0]]["profile"], entry[0])
    ):
        allocation = allocations[token]
        current = states.get(token)
        entry = bindings_by_token.get(token)
        finding = findings[token]["finding"]
        item = {
            "allocation_id": token,
            "profile": allocation["profile"],
            "kind": allocation["kind"],
            "identifier": allocation["identifier"],
            "action": operation["action"],
            "outcome": operation["outcome"],
            "lifecycle_state": current if current is not None else "unrecorded",
            "finding": finding,
            "binding_recorded": entry is not None,
        }
        seen.add(token)
        binding = None if entry is None else entry["binding"]
        if allocation["kind"] == "namespace":
            live = helpers.netns_identity(allocation["identifier"])
            lookalike = binding is not None and live is not None and live != binding
            absent = live is None
        else:
            absent = binding is not None and (binding["scope"], allocation["identifier"]) not in links
            lookalike = (
                binding is not None
                and not absent
                and links.get((binding["scope"], allocation["identifier"])) != binding["ifindex"]
            )
        if operation["action"] == "create":
            if absent:
                item["disposition"] = "resolve_create_failed"
                item["authority"] = BOOT if operation["outcome"] == "pending" else OPERATOR
                item["reason"] = "the awaited resource is absent; the failed attempt is recorded without kernel action"
            elif binding is None:
                item["disposition"] = _REVIEW
                item["authority"] = OPERATOR
                item["reason"] = "the live creation has no recorded creation-time binding; review, never adopt"
            elif allocation["kind"] != "namespace":
                item["disposition"] = _REVIEW
                item["authority"] = OPERATOR
                item["reason"] = "a create intent on an allocation this layer cannot verify by identity alone"
            elif lookalike:
                item["disposition"] = _REVIEW
                item["authority"] = OPERATOR
                item["reason"] = "the live mount identity no longer matches the recorded binding"
            elif _generation_complete(allocations, journal, bindings_by_token, helpers, allocation):
                item["disposition"] = "complete_creation"
                item["authority"] = BOOT if operation["outcome"] == "pending" else OPERATOR
                item["reason"] = "every binding was recorded and still matches; finish the durable bookkeeping"
            else:
                item["disposition"] = "rollback_creation"
                item["authority"] = OPERATOR if operation["outcome"] == "uncertain" else BOOT
                item["reason"] = "the recorded namespace still matches but the creation was left incomplete"
        else:
            if binding is None:
                item["disposition"] = _REVIEW
                item["authority"] = OPERATOR
                item["reason"] = "the retirement has no recorded binding to verify against"
            elif absent:
                item["disposition"] = "complete_retirement_records"
                item["authority"] = BOOT if operation["outcome"] == "pending" else OPERATOR
                item["reason"] = "the awaited resource is absent; retirement completes as records only"
            elif lookalike:
                item["disposition"] = _REVIEW
                item["authority"] = OPERATOR
                item["reason"] = "the observed resource does not match the recorded binding; never delete a lookalike"
            else:
                item["disposition"] = "resume_retirement"
                item["authority"] = OPERATOR
                item["reason"] = "the recorded identity still matches; resume the confirmed retirement"
        items.append(item)

    for token in sorted(set(allocations) - seen, key=lambda token: (allocations[token]["profile"], token)):
        allocation = allocations[token]
        state = states.get(token)
        if (
            state == "active"
            and findings[token]["finding"]
            not in (
                "verified_current",
                "consistent_retired",
            )
            and findings[token]["finding"] not in _ABSENT_FINDINGS
        ):
            # A present, undisputed-but-unverifiable allocation is the
            # operator's review, with or without an unresolved intent.
            finding = findings[token]["finding"]
            entry = bindings_by_token.get(token)
            items.append(
                {
                    "allocation_id": token,
                    "profile": allocation["profile"],
                    "kind": allocation["kind"],
                    "identifier": allocation["identifier"],
                    "action": "bookkeeping",
                    "outcome": None,
                    "lifecycle_state": state,
                    "finding": finding,
                    "binding_recorded": entry is not None,
                    "disposition": _REVIEW,
                    "authority": OPERATOR,
                    "reason": f"the live allocation is not verifiable ({finding}); review before any action",
                }
            )
            seen.add(token)
            continue
        if state not in _INTERRUPTED_STATES:
            continue
        finding = findings[token]["finding"]
        entry = bindings_by_token.get(token)
        binding = None if entry is None else entry["binding"]
        if allocation["kind"] == "namespace":
            live = helpers.netns_identity(allocation["identifier"])
            matches = binding is not None and live == binding
        else:
            matches = (
                binding is not None and links.get((binding["scope"], allocation["identifier"])) == binding["ifindex"]
            )
        item = {
            "allocation_id": token,
            "profile": allocation["profile"],
            "kind": allocation["kind"],
            "identifier": allocation["identifier"],
            "action": "bookkeeping",
            "outcome": None,
            "lifecycle_state": state,
            "finding": finding,
            "binding_recorded": entry is not None,
        }
        if allocation["profile"] in pristine_profiles and state == "creating":
            item["disposition"] = "complete_retirement_records"
            item["authority"] = BOOT if not uncertain_profiles.intersection({allocation["profile"]}) else OPERATOR
            item["reason"] = "the entire unbound generation is absent and only its namespace creation intent began"
        elif state == "creating" and binding is None and allocation["profile"] in absent_staged_profiles:
            item["disposition"] = "complete_retirement_records"
            item["authority"] = OPERATOR if allocation["profile"] in uncertain_profiles else BOOT
            item["reason"] = "the entire unbound staged generation is absent; retire records only"
        elif state == "failed" and allocation["profile"] in rolled_back_profiles:
            item["disposition"] = "complete_retirement_records"
            item["authority"] = OPERATOR
            item["reason"] = "the failed generation was rolled back and is absent; retire records only"
        elif binding is None and (
            allocation["kind"] == "namespace" and helpers.netns_identity(allocation["identifier"]) is not None
        ):
            item["disposition"] = _REVIEW
            item["authority"] = OPERATOR
            item["reason"] = "the live resource has no recorded binding; review, never adopt or delete"
        elif finding in _ABSENT_FINDINGS:
            item["disposition"] = "complete_retirement_records"
            item["authority"] = BOOT
            item["reason"] = "kernel-absent interrupted record; bookkeeping completes without kernel effects"
        elif binding is None and (
            allocation["kind"] == "namespace" and helpers.netns_identity(allocation["identifier"]) is not None
        ):
            item["disposition"] = _REVIEW
            item["authority"] = OPERATOR
            item["reason"] = "the live resource has no recorded binding; review, never adopt or delete"
        elif binding is not None and not matches:
            item["disposition"] = _REVIEW
            item["authority"] = OPERATOR
            item["reason"] = f"the recorded resource now looks different ({finding}); review before any action"
        elif finding in _ABSENT_FINDINGS:
            item["disposition"] = "complete_retirement_records"
            item["authority"] = BOOT
            item["reason"] = "kernel-absent interrupted record; bookkeeping completes without kernel effects"
        elif (
            state == "creating"
            and binding is not None
            and _generation_complete(allocations, journal, bindings_by_token, helpers, allocation)
        ):
            item["disposition"] = "complete_creation"
            item["authority"] = OPERATOR if allocation["profile"] in uncertain_profiles else BOOT
            item["reason"] = "the recorded set is complete and still matches; finish the lifecycle states"
        elif state == "retiring" and binding is not None and matches:
            item["disposition"] = "resume_retirement"
            item["authority"] = OPERATOR
            item["reason"] = "a retirement was interrupted mid-flight; the operator must resume it deliberately"
        else:
            item["disposition"] = _REVIEW
            item["authority"] = OPERATOR
            item["reason"] = f"the interrupted state {state} cannot be converged from {finding}"
        items.append(item)

    # An absent, never-bound dependent from a half-built creation is resolved
    # only by the identity-bound namespace rollback. The same applies to an
    # unbound interface observed solely inside that verified namespace: it is
    # removed by deleting the namespace, never by claiming the interface name.
    # Every other review item quarantines the whole profile.
    rollback_profiles = {item["profile"] for item in items if item["disposition"] == "rollback_creation"}
    rollback_namespaces = {
        item["profile"]: item["identifier"]
        for item in items
        if item["disposition"] == "rollback_creation" and item["kind"] == "namespace"
    }
    subordinate = set()
    for item in items:
        allocation = allocations[item["allocation_id"]]
        if (
            item["disposition"] != _REVIEW
            or item["profile"] not in rollback_profiles
            or item["lifecycle_state"] != "creating"
            or allocation["kind"] != "interface"
        ):
            continue
        entry = bindings_by_token.get(item["allocation_id"])
        if entry is None:
            live_scopes = {scope for scope, name in links if name == allocation["identifier"]}
            certified = not live_scopes or live_scopes == {rollback_namespaces[item["profile"]]}
        else:
            binding = entry["binding"]
            certified = links.get((binding["scope"], allocation["identifier"])) == binding["ifindex"]
        if certified:
            subordinate.add(item["allocation_id"])
    disputed_profiles = {
        item["profile"] for item in items if item["disposition"] == _REVIEW and item["allocation_id"] not in subordinate
    }
    for item in items:
        if item["disposition"] != _REVIEW and item["profile"] in disputed_profiles:
            item["disposition"] = _REVIEW
            item["authority"] = OPERATOR
            item["reason"] = "the profile is quarantined by other disputed evidence; review before any action"
        item["profile_quarantined"] = item["profile"] in disputed_profiles
    return items


def _generation_complete(
    allocations: dict[str, dict],
    journal: dict,
    bindings_by_token: dict,
    helpers,
    allocation: dict,
) -> bool:
    """A creation's bookkeeping is finishable when every binding was recorded."""
    if bindings_by_token.get(allocation["allocation_id"]) is None:
        return False
    links = _observed_links(helpers.observe())
    states = {event["allocation_id"]: event["state"] for event in journal["events"]}
    resources = _current_generation(allocations, states, allocation["profile"])
    for resource in resources:
        entry = bindings_by_token.get(resource["allocation_id"])
        if entry is None:
            return False
        if resource["kind"] == "namespace":
            live = helpers.netns_identity(resource["identifier"])
            if live is None or live != entry["binding"]:
                return False
            continue
        scope = entry["binding"]["scope"]
        if links.get((scope, resource["identifier"])) != entry["binding"]["ifindex"]:
            return False
    return True


def _execute_items(
    items: list[dict],
    helpers,
    journal_path: str | Path,
    bindings_path: str | Path,
    intent_path: str | Path | None,
    resolvers: bool,
    boot: bool,
) -> list[dict]:
    """Apply executable dispositions; lookalikes and operator items stay put."""
    from nord_tools_internal.nordvpn_cleanup_executor import _delete_host_interface, _delete_namespace

    deletions: list[dict] = []
    actions: list[dict] = []
    intents_by_token = {
        operation["allocation_id"]: operation
        for operation in _read_document(intent_path).get("operations", [])
        if operation["outcome"] in {"pending", "uncertain"}
    }

    def resolution(token: str, outcome: str) -> dict | None:
        document = validate_journal(_read_document(journal_path))
        operation = intents_by_token.get(token)
        if operation is None:
            return None
        if operation["outcome"] == "uncertain":
            if boot:
                actions.append(
                    {
                        "allocation_id": token,
                        "identifier": index[token]["identifier"],
                        "action": "left_for_operator_review",
                        "kernel_changed": False,
                    }
                )
                return None
            update_recovered_intent(intent_path, document, operation_id=operation["operation_id"], outcome=outcome)
        else:
            update_intent(intent_path, document, operation_id=operation["operation_id"], outcome=outcome)
        intents_by_token.pop(token, None)
        return {"operation_id": operation["operation_id"], "outcome": outcome}

    index = {item["allocation_id"]: item for item in items}
    for item in items:
        token = item["allocation_id"]
        disposition = item["disposition"]
        if disposition == _REVIEW:
            continue
        if boot and item["authority"] != BOOT:
            # The operator wall: boot never advances a generation the intent
            # store marks uncertain, and never resumes confirmed deletions.
            continue
        if disposition == "complete_creation":
            if item["outcome"] == "uncertain" and boot:
                continue
            if item["lifecycle_state"] == "creating":
                update_journal(journal_path, lambda raw: record_transition(raw, token, "active"))
            if item["action"] == "create":
                resolution(token, "completed")
            actions.append({**item, "action": "completed_bookkeeping", "kernel_changed": False})
            continue
        if disposition == "complete_retirement_records":
            _record_retirement(journal_path, token, item["lifecycle_state"])
            if item["action"] == "retire":
                resolution(token, "completed")
            else:
                resolution(token, "failed")
            actions.append({**item, "action": "resolved_records", "kernel_changed": False})
            continue
        if disposition == "resolve_create_failed":
            _record_retirement(journal_path, token, item["lifecycle_state"])
            resolution(token, "failed")
            actions.append({**item, "action": "resolved_create_failed", "kernel_changed": False})
            continue
        if disposition == "rollback_creation":
            binding = _binding_for_item(item, bindings_path)
            _delete_namespace(token, item, binding, helpers, resolvers, deletions)
            _record_retirement(journal_path, token, item["lifecycle_state"])
            _retire_namespace_generation(item, journal_path)
            resolution(token, "failed")
            actions.append({**item, "action": "rollback_deleted", "kernel_changed": True})
            continue
        if disposition == "resume_retirement":
            if boot:
                continue
            binding = _binding_for_item(item, bindings_path)
            if item["kind"] == "namespace":
                _delete_namespace(token, item, binding, helpers, resolvers, deletions)
            elif binding["scope"] == "host":
                _delete_host_interface(token, item, binding, helpers, deletions)
            _record_retirement(journal_path, token, item["lifecycle_state"])
            resolution(token, "completed")
            actions.append({**item, "action": "retirement_completed", "kernel_changed": True})
            continue
    return actions


def _retire_namespace_generation(item: dict, journal_path: str | Path) -> None:
    """Retire every allocation in the same profile generation as the item."""
    from nord_tools_internal.nordvpn_cleanup_executor import _observed_links  # noqa: F401

    journal = validate_journal(_read_document(journal_path))
    allocations = [
        resource for resource in journal["allocations"]["resources"] if resource["profile"] == item["profile"]
    ]
    states = {event["allocation_id"]: event["state"] for event in journal["events"]}
    for resource in sorted(allocations, key=lambda entry: (entry["kind"], entry["identifier"])):
        token = resource["allocation_id"]
        if states.get(token) == "active":
            continue
        for next_state in _retire_chain(states.get(token)):
            update_journal(journal_path, lambda raw: record_transition(raw, token, next_state))


def _record_retirement(journal_path: str | Path, token: str, state: str) -> None:
    """Record-only retirement: journal events only, no kernel action."""
    for next_state in _retire_chain(state):
        update_journal(journal_path, lambda raw: record_transition(raw, token, next_state))


def _binding_for_item(item: dict, bindings_path: str | Path) -> dict:
    bindings = _read_document(bindings_path)
    entry = next(
        (candidate for candidate in bindings["bindings"] if candidate["allocation_id"] == item["allocation_id"]),
        None,
    )
    if entry is None:
        raise RegistryError(f"the interrupted resource {item['identifier']} has no owner binding")
    return entry["binding"]
