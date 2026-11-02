"""Ownership-aware cleanup and reset of verified Nord Tools-owned resources.

This module turns the accepted read-only verification and reconciliation
foundations into the project's only destructive execution path. Classification is
entirely evidence-based: a resource is considered only when the Part 7.1
preflight classifies the allocation against its immutable creation-time owner
binding, and the plan distinguishes removable, already-gone, foreign-preserved
and review-required outcomes per allocation. Unclaimed observations are listed,
never touched, and host firewall or host routing configuration is never flushed.

Every kernel deletion is bracketed like every other executor path here: the
lifecycle state moves to ``retiring`` and a durable retire intent is recorded
before the mutation, the recorded owner identity is re-verified immediately
before the deletion, a fresh observation must confirm absence afterwards, and
only then does the journal record ``retired`` and the intent resolve as deleted.
The first failure leaves its own evidence uncertain for review and stops the
run, leaving later profiles exactly as observed. Repeat runs converge: a fully
retired ecosystem plans no actions and changes nothing.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import datetime
import fcntl
import json
import os
from pathlib import Path
import stat
from typing import Callable, Iterator

from nord_tools_internal.nordvpn_lifecycle import (
    record_transition,
    validate_journal,
    write_journal,
)
from nord_tools_internal.nordvpn_lifecycle_store import update_journal
from nord_tools_internal.nordvpn_startup import initialise_startup_runs, validate_startup_config
from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace, OwnershipError
from nord_tools_internal.nordvpn_operation_store import initialise_intents, read_intents, update_intent
from nord_tools_internal.nordvpn_ownership_verify import NETNS_MOUNT_DIR, initialise_bindings, preflight_ownership
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_state_reconcile import derive_actual_state, reconcile_desired


_ABSENT = "absent"
_REMOVABLE = "removable"
_PRESERVED = "preserved"
_REVIEW = "review_required"
_ABSENT_FINDINGS = frozenset({"resource_missing", "scope_missing"})
_RESOLVER_ROOT = Path("/etc/netns")


@dataclass(frozen=True)
class CleanupKernel:
    """The injected privileged surface; tests substitute their own kernel."""

    observe: Callable[[], dict]
    netns_identity: Callable[..., dict | None]
    delete_namespace: Callable[..., None]
    delete_host_interface: Callable[..., None]
    resolver_state: Callable[..., str]
    remove_resolver: Callable[..., None]


def _real_kernel() -> CleanupKernel:
    """Build the production kernel surface from the established primitives."""

    def observe() -> dict:
        from nord_tools_internal.nordvpn_discovery import discover

        return discover()

    def netns_identity(name: str, netns_dir: Path = NETNS_MOUNT_DIR) -> dict | None:
        try:
            info = os.stat(netns_dir / name, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            raise RegistryError(f"unexpected namespace mount type for {name}")
        return {"device": info.st_dev, "inode": info.st_ino}

    def delete_namespace(name: str, binding: dict, netns_dir: Path = NETNS_MOUNT_DIR) -> None:
        """Delete the namespace only while it matches the recorded owner binding."""
        try:
            descriptor = os.open(netns_dir / name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise ProvisioningUncertainError(f"namespace {name} is no longer openable: {exc}") from exc
        try:
            owned = OwnedNamespace(name, descriptor, binding["device"], binding["inode"])
            owned.verify()
            owned.retire()
        except OwnershipError as exc:
            raise ProvisioningUncertainError(
                f"namespace {name} does not match its recorded owner binding at the moment of deletion: {exc}"
            ) from exc

    def delete_host_interface(name: str, ifindex: int) -> None:
        import subprocess

        result = subprocess.run(
            ["ip", "link", "del", "dev", str(ifindex)], capture_output=True, timeout=15, check=False
        )
        if result.returncode:
            raise ProvisioningUncertainError(f"the recorded host interface {name} could not be deleted")

    def resolver_state(namespace: str, root: Path = _RESOLVER_ROOT) -> str:
        """Report whether the namespace resolver directory is clean to remove."""
        directory = root / namespace
        try:
            info = directory.lstat()
        except OSError:
            return _ABSENT
        if not stat.S_ISDIR(info.st_mode) or directory.is_symlink():
            return _REVIEW
        entries = list(directory.iterdir())
        if len(entries) != 1 or entries[0].name != "resolv.conf" or not entries[0].is_file() or entries[0].is_symlink():
            return _REVIEW
        return "clean"

    def remove_resolver(namespace: str, root: Path = _RESOLVER_ROOT) -> None:
        """Remove exactly the namespace resolver directory shape we created."""
        directory = root / namespace
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or directory.is_symlink():
            raise ProvisioningUncertainError(f"the resolver directory for {namespace} changed shape")
        entries = list(directory.iterdir())
        if len(entries) != 1 or entries[0].name != "resolv.conf" or not entries[0].is_file() or entries[0].is_symlink():
            raise ProvisioningUncertainError(f"the resolver directory for {namespace} contains unexpected state")
        entries[0].unlink()
        directory.rmdir()

    return CleanupKernel(
        observe=observe,
        netns_identity=netns_identity,
        delete_namespace=delete_namespace,
        delete_host_interface=delete_host_interface,
        resolver_state=resolver_state,
        remove_resolver=remove_resolver,
    )


@contextmanager
def _execution_lock(journal_path: str | Path) -> Iterator[None]:
    """Share the boot path's single-flight lock so cleanup and restore never race."""
    target = Path(journal_path).absolute()
    lock = target.with_name(target.name + ".restore.lock")
    for component in (target, *target.parents):
        if component.is_symlink():
            raise RegistryError("refusing symlinked cleanup lock path")
    if not target.parent.is_dir():
        raise RegistryError("cleanup requires an existing journal parent directory")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise RegistryError("unsafe cleanup execution lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        current = os.stat(lock, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RegistryError("cleanup execution lock identity changed")
        yield
    finally:
        os.close(fd)


def _read_document(path: str | Path) -> dict:
    try:
        with open(path, encoding="utf-8") as source:
            document = json.load(source)
    except (OSError, ValueError, UnicodeError) as exc:
        raise RegistryError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise RegistryError(f"{path} must contain a JSON object")
    return document


def _validate_shared_graph(graph: object, journal: dict) -> dict[str, list[str]]:
    """Validate the cleanup graph over the profiles the journal knows."""
    known = {resource["profile"] for resource in journal["allocations"]["resources"]}
    dependencies = {}
    for name, parents in graph["dependencies"].items():
        if not isinstance(name, str) or name not in known:
            raise RegistryError(f"cleanup graph names a profile outside the ownership journal: {name!r}")
        if (
            not isinstance(parents, list)
            or any(not isinstance(item, str) or item == name or item not in known for item in parents)
            or len(set(parents)) != len(parents)
        ):
            raise RegistryError(f"invalid cleanup dependencies for {name}")
        dependencies[name] = parents
    pending = {name: set(parents) for name, parents in dependencies.items()}
    while pending:
        ready = sorted(name for name, parents in pending.items() if not parents)
        if not ready:
            raise RegistryError("cleanup graph contains a dependency cycle")
        for name in ready:
            del pending[name]
        for parents in pending.values():
            parents.difference_update(ready)
    return dependencies


def _reverse_order(candidates: list[str], dependencies: dict[str, list[str]] | None) -> list[str]:
    """Order deletion dependents-first; prerequisites leave last."""
    member = set(candidates)
    if not dependencies:
        return sorted(candidates)
    waiting = {name: {dep for dep in dependencies.get(name, []) if dep in member} & member for name in candidates}
    forward: list[str] = []
    while waiting:
        ready = sorted(name for name, blocked in waiting.items() if not blocked)
        if not ready:
            raise RegistryError("cleanup candidates form a dependency cycle")
        for name in ready:
            del waiting[name]
        for blocked in waiting.values():
            blocked.difference_update(ready)
        forward.extend(ready)
    return list(reversed(forward))


def _classifications(
    journal: dict,
    preflight: dict,
    desired: dict,
    full_reset: bool,
) -> list[dict]:
    """Classify every allocation once; a disputed profile is never parted out.

    Profiles mix generations because retired history stays in the journal
    deliberately. A profile is actionable only when every finding in it is
    either verified current, consistently retired, or kernel-absent with the
    namespace scope gone. Any other finding classifies the whole profile for
    review, so partial deletion of an ambiguous namespace is impossible.
    """
    allocations = {resource["allocation_id"]: resource for resource in journal["allocations"]["resources"]}
    findings = {item["allocation_id"]: item for item in preflight["resources"]}
    actionable = frozenset({"verified_current", "consistent_retired"}) | _ABSENT_FINDINGS
    profile_findings: dict[str, dict[str, str]] = {}
    for token, allocation in allocations.items():
        profile_findings.setdefault(allocation["profile"], {})[token] = findings[token]["finding"]
    disputed = {
        profile
        for profile, per_token in profile_findings.items()
        if any(finding not in actionable for finding in per_token.values())
    }
    entries: list[dict] = []
    kind_rank = {"namespace": 0, "interface": 1}

    def by_id(token: str) -> tuple[str, int, str]:
        allocation = allocations[token]
        return (allocation["profile"], kind_rank[allocation["kind"]], allocation["identifier"])

    for token in sorted(allocations, key=by_id):
        allocation = allocations[token]
        finding = findings[token]["finding"]
        profile = allocation["profile"]
        resource = {
            "allocation_id": token,
            "profile": profile,
            "kind": allocation["kind"],
            "identifier": allocation["identifier"],
        }
        wanted = desired.get(profile)
        if profile in disputed:
            entries.append(
                {
                    **resource,
                    "action": _REVIEW,
                    "reason": "the profile has disputed ownership evidence; review before any deletion",
                }
            )
            continue
        if finding == "consistent_retired":
            entries.append(
                {
                    **resource,
                    "action": _PRESERVED,
                    "reason": "recorded and observed consistently retired; nothing to delete",
                }
            )
            continue
        if finding in _ABSENT_FINDINGS:
            if not wanted or full_reset:
                entries.append(
                    {
                        **resource,
                        "action": _REMOVABLE,
                        "reason": "kernel-absent owned record; retirement is bookkeeping only",
                    }
                )
            else:
                entries.append(
                    {
                        **resource,
                        "action": _REVIEW,
                        "reason": "kernel-absent allocations under a retained desired profile; review before recording",
                    }
                )
            continue
        if wanted and not full_reset:
            entries.append({**resource, "action": _PRESERVED, "reason": "a retained desired profile stays in place"})
        else:
            entries.append(
                {
                    **resource,
                    "action": _REMOVABLE,
                    "reason": "verified owned resource outside the retained desired scope"
                    if not wanted
                    else "the full reset removes every owned resource",
                }
            )
    return entries


def _dependency_refusals(
    classification: list[dict],
    dependencies: dict[str, list[str]],
    candidates: set[str],
) -> None:
    """A prerequisite is never deleted while a dependent profile remains."""
    dependents: dict[str, list[str]] = {}
    for name, parents in dependencies.items():
        for parent in parents:
            dependents.setdefault(parent, []).append(name)
    for entry in classification:
        profile = entry["profile"]
        if profile in candidates and entry["action"] == _REMOVABLE:
            for child in dependents.get(profile, ()):
                if child in candidates:
                    continue
                entry["action"] = _REVIEW
                entry["reason"] = f"the dependent profile {child} remains in place and requires it"


def plan_cleanup(
    journal_path: str | Path,
    bindings_path: str | Path,
    *,
    intent_path: str | Path | None = None,
    graph_path: str | Path | None = None,
    desired_policy: object | None = None,
    resolvers: bool = False,
    execute: bool = False,
    kernel: CleanupKernel | None = None,
    recorded_at: str | None = None,
) -> dict:
    """Produce the exact cleanup plan, or execute it under explicit confirmation.

    The desired policy grounds preservation: verified resources of a retained
    profile are preserved, everything verified outside it is removable. A kernel
    and journal without a desired policy is a full reset where every owned
    resource is removable, because nothing is retained. Any disputed profile is
    reviewed rather than partially deleted, and foreign observations are
    preserved by construction. A missing intent store is allowed for planning
    and refused for execution, so uncertain prior attempts stay visible.
    """
    desired_profiles = None
    if desired_policy is not None:
        if not isinstance(desired_policy, dict) or not isinstance(desired_policy.get("vpn_profiles"), dict):
            raise RegistryError("cleanup requires a validated desired policy for preservation decisions")
        desired_profiles = desired_policy["vpn_profiles"]
    if execute and intent_path is None:
        raise RegistryError(
            "executing cleanup requires the operation intent store; unresolved prior attempts must stay visible"
        )
    helpers = kernel or _real_kernel()
    restart_at = recorded_at or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    with _execution_lock(journal_path):
        journal = validate_journal(_read_document(journal_path))
        bindings = _read_document(bindings_path)
        intents = _read_document(intent_path) if intent_path else None
        observation = helpers.observe()
        preflight = preflight_ownership(journal, bindings, observation, intents)
        classifications = _classifications(journal, preflight, desired_profiles or {}, desired_policy is None)
        dependencies = _validate_shared_graph(_read_document(graph_path), journal) if graph_path else None
        candidate_profiles = {entry["profile"] for entry in classifications if entry["action"] == _REMOVABLE}
        _dependency_refusals(classifications, dependencies or {}, candidate_profiles)
        order = _reverse_order(sorted(candidate_profiles), dependencies)
        plan = [entry for entry in classifications if entry["action"] == _REMOVABLE]
        preserved = [entry for entry in classifications if entry["action"] == _PRESERVED]
        reviewed = [entry for entry in classifications if entry["action"] == _REVIEW]
        report = {
            "version": 1,
            "mode": "ownership_cleanup",
            "executed": False,
            "network_changes_applied": False,
            "operator_review_required": bool(reviewed)
            or any(item["outcome"] not in {"completed", "failed"} for item in (intents or {}).get("operations", [])),
            "plan": plan,
            "deletions": [],
            "preserved": preserved,
            "review_required": reviewed,
            "unclaimed": preflight["unclaimed"],
            "final_reconciliation": None,
            "recorded_at": restart_at,
            "limitations": (
                "Executes only when explicitly confirmed; deletes only resources whose creation-time binding still "
                "matches the live kernel at the moment of deletion, records observed absence and retires each "
                "allocation. Anything disputed is reviewed, never partially deleted; unclaimed observations are "
                "preserved; host firewall and routing configuration are never touched. Transient intent has no part "
                "in this path."
            ),
        }
        if not execute:
            return report
        if reviewed:
            raise ProvisioningUncertainError(
                "cleanup refuses to execute while uncertain ownership findings remain; review them first"
            )
        deletions = _execute_removals(
            plan, order, helpers, journal, bindings, journal_path, bindings_path, intent_path, resolvers
        )
        report["executed"] = True
        report["network_changes_applied"] = bool(deletions)
        final_preflight = _fresh_reconciliation(journal_path, bindings_path, intent_path, helpers, desired_policy)
        report["final_reconciliation"] = final_preflight["resources"]
        report["deletions"] = deletions
        report["operator_review_required"] = bool(final_preflight["operator_review_required"])
        return report


def _deletable_tokens(plan: list[dict]) -> dict[str, list[str]]:
    by_profile: dict[str, list[str]] = {}
    for entry in plan:
        by_profile.setdefault(entry["profile"], []).append(entry["allocation_id"])
    return by_profile


def _observed_links(observation: dict) -> dict[tuple[str, str], int]:
    links: dict[tuple[str, str], int] = {}
    for link in observation.get("host_interfaces", []):
        links[("host", link["name"])] = link["index"]
    for details in observation.get("namespace_details", []):
        for link in details.get("interfaces", []):
            links[(details["name"], link["name"])] = link["index"]
    return links


def _execute_removals(
    plan: list[dict],
    order: list[str],
    helpers: CleanupKernel,
    journal: dict,
    bindings: dict,
    journal_path: str | Path,
    bindings_path: str | Path,
    intent_path: str | Path | None,
    resolvers: bool,
) -> list[dict]:
    """Retire all planned allocations, each soldier behind a durable intent."""
    tokens = {entry["allocation_id"]: entry for entry in plan}
    bindings_by_token = {entry["allocation_id"]: entry for entry in bindings["bindings"]}
    by_profile = _deletable_tokens(plan)
    deletions: list[dict] = []
    operations: dict[str, str] = {}

    def begin_retire(token: str) -> str | None:
        document = update_journal(journal_path, lambda raw: record_transition(raw, token, "retiring"))
        if intent_path is None:
            return None
        started = update_intent(intent_path, document, allocation_id=token, action="retire")
        return started["operations"][-1]["operation_id"]

    def record_absent(token: str) -> None:
        document = update_journal(journal_path, lambda raw: record_transition(raw, token, "retired"))
        if intent_path is not None:
            update_intent(intent_path, document, operation_id=operations[token], outcome="completed")
        deletions.append(
            {
                "allocation_id": token,
                "profile": tokens[token]["profile"],
                "kind": tokens[token]["kind"],
                "identifier": tokens[token]["identifier"],
                "confirmed_absent": True,
            }
        )

    try:
        for profile in order:
            profile_tokens = by_profile[profile]
            namespace_tokens = [token for token in profile_tokens if tokens[token]["kind"] == "namespace"]
            interface_tokens = [token for token in profile_tokens if tokens[token]["kind"] == "interface"]
            nested_tokens = [
                token for token in interface_tokens if bindings_by_token[token]["binding"]["scope"] != "host"
            ]
            host_tokens = [
                token for token in interface_tokens if bindings_by_token[token]["binding"]["scope"] == "host"
            ]
            # All intents begin before any kernel change, so the first failure
            # leaves its own scope uncertain and nothing later is touched.
            operations.update(
                {token: begin_retire(token) for token in [*namespace_tokens, *nested_tokens, *host_tokens]}
            )
            for token in namespace_tokens:
                _delete_namespace(
                    token, tokens[token], bindings_by_token[token]["binding"], helpers, resolvers, deletions
                )
            deleted_namespaces = [tokens[token]["identifier"] for token in namespace_tokens]

            fresh = helpers.observe()
            survivors = [name for name in fresh.get("namespaces", []) if name in deleted_namespaces]
            if survivors:
                raise ProvisioningUncertainError(
                    f"the deleted namespaces still observe as present: {', '.join(survivors)}"
                )
            links = _observed_links(fresh)
            for token in nested_tokens:
                scope = bindings_by_token[token]["binding"]["scope"]
                if (scope, tokens[token]["identifier"]) in links:
                    raise ProvisioningUncertainError(
                        f"the namespace-local interface {tokens[token]['identifier']} is still observable"
                    )
            for token in host_tokens:
                _delete_host_interface(token, tokens[token], bindings_by_token[token]["binding"], helpers, deletions)
            for token in [*namespace_tokens, *nested_tokens, *host_tokens]:
                record_absent(token)
        return deletions
    except BaseException:
        # A failed attempt leaves its own evidence ambiguous; nothing further is
        # deleted. Pending intents become uncertain so the next run refuses.
        try:
            journal_now = validate_journal(_read_document(journal_path))
            if intent_path is not None:
                for operation in read_intents(intent_path, journal_now)["operations"]:
                    if operation["outcome"] == "pending":
                        update_intent(
                            intent_path, journal_now, operation_id=operation["operation_id"], outcome="uncertain"
                        )
        except Exception:
            pass
        raise


def _delete_namespace(
    token: str,
    resource: dict,
    binding: dict,
    helpers: CleanupKernel,
    resolvers: bool,
    deletions: list[dict],
) -> None:
    name = resource["identifier"]
    live = helpers.netns_identity(name)
    if live is None:
        # Already absent at the moment of action: record-only retirement.
        deletions.append(
            {
                "allocation_id": token,
                "profile": resource["profile"],
                "kind": "namespace",
                "identifier": name,
                "confirmed_absent": True,
            }
        )
        return
    if live != binding:
        raise ProvisioningUncertainError(f"namespace {name} no longer matches its recorded owner identity")
    if resolvers:
        shape = helpers.resolver_state(name)
        if shape not in ("clean", "absent"):
            raise ProvisioningUncertainError(f"the resolver directory for {name} contains unexpected state")
        if shape == "clean":
            helpers.remove_resolver(name)
    helpers.delete_namespace(name, binding)


def _delete_host_interface(
    token: str,
    resource: dict,
    binding: dict,
    helpers: CleanupKernel,
    deletions: list[dict],
) -> None:
    """Delete a host-scope interface only at its freshly re-observed index."""
    name = resource["identifier"]
    index = _observed_links(helpers.observe()).get(("host", name))
    if index is None:
        deletions.append(
            {
                "allocation_id": token,
                "profile": resource["profile"],
                "kind": "interface",
                "identifier": name,
                "confirmed_absent": True,
            }
        )
        return
    if index != binding["ifindex"]:
        raise ProvisioningUncertainError(f"host interface {name} no longer matches its recorded interface index")
    helpers.delete_host_interface(name, index)
    fresh = helpers.observe()
    if ("host", name) in _observed_links(fresh):
        raise ProvisioningUncertainError(f"the deleted host interface {name} is still observable")


def _fresh_reconciliation(
    journal_path: str | Path,
    bindings_path: str | Path,
    intent_path: str | Path | None,
    helpers: CleanupKernel,
    desired_policy: object | None,
) -> dict:
    """Fresh preflight after execution; reconcile again when a policy exists."""
    journal = validate_journal(_read_document(journal_path))
    bindings = _read_document(bindings_path)
    intents = _read_document(intent_path) if intent_path else None
    preflight = preflight_ownership(journal, bindings, helpers.observe(), intents)
    if desired_policy is not None and desired_policy.get("vpn_profiles"):
        actual = derive_actual_state(journal, bindings, preflight)
        reconcile_desired(desired_policy, actual)
    return preflight


def reset_ownership(
    config: object,
    *,
    graph_path: str | Path | None = None,
    resolvers: bool = False,
    execute: bool = False,
    kernel: CleanupKernel | None = None,
    recorded_at: str | None = None,
) -> dict:
    """Remove every verified owned resource and archive the ownership stores.

    This is the explicitly confirmed reset: full teardown regardless of the
    saved desired policy, followed by a byte-verified archive of the journal,
    bindings, intents and run record, and fresh empty stores. The retirement
    record survives in the archive so later name reuse stays detectable.
    """
    validated = validate_startup_config(config)
    if validated["intent"] is None:
        raise RegistryError("the ownership reset requires durable operation intents in the startup configuration")
    report = plan_cleanup(
        validated["journal"],
        validated["bindings"],
        intent_path=validated["intent"],
        graph_path=graph_path,
        desired_policy=None,
        resolvers=resolvers,
        execute=execute,
        kernel=kernel,
        recorded_at=recorded_at,
    )
    report["mode"] = "ownership_reset"
    if not execute:
        return report
    if report["review_required"]:
        raise ProvisioningUncertainError(
            "the reset refuses to archive while review obligations remain; inspect the report first"
        )
    journal = validate_journal(_read_document(validated["journal"]))
    states = {event["allocation_id"]: event["state"] for event in journal["events"]}
    if states and any(state != "retired" for state in states.values()):
        raise ProvisioningUncertainError("the reset archives only when every allocation is consistently retired")
    archive = _archive_and_reinitialise(validated, recorded_at)
    report["stores_reset"] = {"archive": str(archive), "stores": ["journal", "bindings", "intents", "run_record"]}
    return report


def _archive_and_reinitialise(validated: dict, recorded_at: str | None) -> Path:
    """Archive the four stores, verify each copy, then re-create empty state."""
    base = Path(validated["run_record"]).parent
    stamp = (recorded_at or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))[:19].replace(
        ":", ""
    )
    archive_dir = base / "ownership-reset-archive" / f"reset-{stamp}"
    if archive_dir.exists() or archive_dir.is_symlink():
        raise RegistryError(f"the ownership reset archive directory already exists: {archive_dir}")
    archive_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, member in (
        ("journal", validated["journal"]),
        ("bindings", validated["bindings"]),
        ("intents", validated["intent"]),
        ("run_record", validated["run_record"]),
    ):
        source = Path(member).absolute()
        payload = source.read_bytes()
        archived = archive_dir / f"{name}.json"
        with open(archived, "wb", opener=lambda path, flags: os.open(path, flags, mode=0o600)) as sink:
            sink.write(payload)
            sink.flush()
            os.fsync(sink.fileno())
        if archived.read_bytes() != payload:
            raise ProvisioningUncertainError(f"the archived copy of {name} failed verification")
        os.unlink(source)
    empty = _empty_journal()
    write_journal(validated["journal"], empty)
    initialise_bindings(validated["bindings"])
    initialise_intents(validated["intent"], empty)
    initialise_startup_runs(validated["run_record"])
    return archive_dir


def _empty_journal() -> dict:
    return {"version": 1, "allocations": {"version": 2, "resources": []}, "events": []}
