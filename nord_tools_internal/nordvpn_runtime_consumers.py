"""Linux process-bound consumer leases for cooperating lifecycle operations.

A lease is never evidence that a tunnel was provisioned. Its allocation key must
be independently matched to creation-time resource bindings before routing or
retirement. A missing or unreadable process is not silently released.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from nord_tools_internal.nordvpn_consumer_reference_store import (
    ConsumerReferenceError,
    locked_consumer_references,
)
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_allocation_profiles import kernel_profile_for_allocation
from nord_tools_internal.nordvpn_execution_lock import lifecycle_execution_lock
from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups


def _identity(pid: int) -> tuple[str, str, str]:
    """Obtain a boot-scoped process identity without trusting the PID alone."""
    if type(pid) is not int or pid <= 0:
        raise ConsumerReferenceError("consumer PID must be positive")
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        # comm is parenthesised and may itself contain spaces and parentheses.
        end = raw.rfind(")")
        if end < 0:
            raise ValueError("invalid process stat")
        start = raw[end + 2 :].split()[19]
        executable = os.readlink(f"/proc/{pid}/exe")
        # A process which exits while being inspected cannot be acquired.
        repeated = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        repeated_end = repeated.rfind(")")
        if repeated_end < 0 or repeated[repeated_end + 2 :].split()[19] != start:
            raise ValueError("process changed during inspection")
        return boot, start, executable
    except (OSError, UnicodeError, IndexError, ValueError) as exc:
        raise ConsumerReferenceError(f"cannot establish consumer process identity: {exc}") from exc


def _fingerprint(policy: dict) -> str:
    checked = validate_policy(policy)
    return hashlib.sha256(json.dumps(checked, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _validate(policy: dict, document: object) -> dict:
    checked = validate_policy(policy)
    expected = {
        app: (group.profile, group.allocation_key)
        for group in resolve_ownership_groups(checked)
        for app in group.consumers
    }
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "policy_sha256", "leases"}
        or document["version"] not in (1, 2)
        or document["policy_sha256"] != _fingerprint(checked)
        or not isinstance(document["leases"], list)
    ):
        raise ConsumerReferenceError("invalid runtime consumer lease document or policy fingerprint")
    seen = set()
    leases = []
    version = document["version"]
    legacy_fields = {
        "application",
        "profile",
        "allocation_key",
        "pid",
        "boot_id",
        "start_time",
        "executable",
    }
    generation_fields = legacy_fields | {"generation_id", "kernel_profile"}
    for lease in document["leases"]:
        if not isinstance(lease, dict) or set(lease) != (legacy_fields if version == 1 else generation_fields):
            raise ConsumerReferenceError("invalid runtime consumer lease fields")
        name = lease["application"]
        if (
            not isinstance(name, str)
            or name not in expected
            or name in seen
            or (lease["profile"], lease["allocation_key"]) != expected[name]
        ):
            raise ConsumerReferenceError("duplicate, unknown or mismatched runtime consumer")
        if (
            type(lease["pid"]) is not int
            or lease["pid"] <= 0
            or any(not isinstance(lease[key], str) or not lease[key] for key in ("boot_id", "start_time", "executable"))
        ):
            raise ConsumerReferenceError("invalid runtime process identity")
        if lease["executable"] != checked["applications"][name]["executable"]:
            raise ConsumerReferenceError("runtime executable does not match registered application")
        if version == 2 and any(
            not isinstance(lease[key], str) or not lease[key] for key in ("generation_id", "kernel_profile")
        ):
            raise ConsumerReferenceError("invalid runtime allocation generation")
        seen.add(name)
        leases.append(dict(lease))
    return {
        "version": version,
        "policy_sha256": _fingerprint(checked),
        "leases": sorted(leases, key=lambda item: item["application"]),
    }


def initialise_runtime_consumers(path: str | Path, policy: dict) -> dict:
    """Create a fresh, empty store; never replace existing or unknown evidence."""
    document = {"version": 2, "policy_sha256": _fingerprint(policy), "leases": []}
    with locked_consumer_references(path):
        if Path(path).exists() or Path(path).is_symlink():
            raise ConsumerReferenceError("runtime lease store already exists")
        # Exclusive placeholder prevents accidental initialisation over a live store.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        try:
            _write(path, policy, document)
        except BaseException:
            # Retain the placeholder: an interrupted initialisation requires review.
            raise
    return document


def _read(path: str | Path, policy: dict) -> dict:
    # Reuse the same private, no-follow reader and its size limits by validating
    # the file shape ourselves after descriptor-safe reading.
    from nord_tools_internal.nordvpn_consumer_reference_store import read_private_json

    return _validate(policy, read_private_json(path))


def _write(path: str | Path, policy: dict, document: dict) -> None:
    from nord_tools_internal.nordvpn_consumer_reference_store import write_private_json

    write_private_json(path, _validate(policy, document))


def read_runtime_consumers(path: str | Path, policy: dict) -> dict:
    with locked_consumer_references(path):
        return _read(path, policy)


def acquire_runtime_consumer(
    path: str | Path,
    policy: dict,
    application: str,
    pid: int,
    *,
    generation_id: str = "unversioned",
    kernel_profile: str | None = None,
) -> dict:
    """Acquire only for a live, registered executable with stable process identity."""
    checked = validate_policy(policy)
    if application not in checked["applications"]:
        raise ConsumerReferenceError("application is not registered")
    with locked_consumer_references(path):
        document = _read(path, checked)
        if any(lease["application"] == application for lease in document["leases"]):
            raise ConsumerReferenceError("consumer already has a lease; release or recover it first")
        before = _identity(pid)
        if before[2] != checked["applications"][application]["executable"]:
            raise ConsumerReferenceError("running executable does not match registered application")
        if _identity(pid) != before:
            raise ConsumerReferenceError("consumer process changed during acquisition")
        group = next(group for group in resolve_ownership_groups(checked) if application in group.consumers)
        effective_kernel_profile = kernel_profile or kernel_profile_for_allocation(
            group.allocation_key, group.profile, group.sharing
        )
        if document["version"] != 2:
            raise ConsumerReferenceError("legacy lease store must be explicitly reconciled before acquisition")
        if not generation_id or not effective_kernel_profile:
            raise ConsumerReferenceError("consumer lease requires an exact allocation generation")
        document["leases"].append(
            {
                "application": application,
                "profile": group.profile,
                "allocation_key": group.allocation_key,
                "pid": pid,
                "boot_id": before[0],
                "start_time": before[1],
                "executable": before[2],
                "generation_id": generation_id,
                "kernel_profile": effective_kernel_profile,
            }
        )
        _write(path, checked, document)
        return _validate(checked, document)


def release_exited_consumer(
    path: str | Path, policy: dict, application: str, *, expected_generation_id: str | None = None
) -> dict:
    """Release only when the original process has ceased to exist.

    An inaccessible /proc entry fails closed. PID reuse is safe because the
    original boot identity and process start time are checked together.
    """
    with locked_consumer_references(path):
        document = _read(path, policy)
        matches = [lease for lease in document["leases"] if lease["application"] == application]
        if len(matches) != 1:
            raise ConsumerReferenceError("consumer has no recorded runtime lease")
        lease = matches[0]
        if expected_generation_id is not None and (
            document["version"] != 2 or lease.get("generation_id") != expected_generation_id
        ):
            raise ConsumerReferenceError("consumer lease belongs to a different or ambiguous generation")
        try:
            identity = _identity(lease["pid"])
        except ConsumerReferenceError:
            # A vanished /proc entry can mean process exit or a permissions
            # failure. Only an unambiguous ESRCH/ENOENT is safe to release.
            try:
                os.stat(f"/proc/{lease['pid']}")
            except FileNotFoundError:
                identity = None
            except OSError as exc:
                raise ConsumerReferenceError(f"cannot establish whether leased process exited: {exc}") from exc
            else:
                raise ConsumerReferenceError("cannot establish whether leased process exited") from None
        if identity is not None and identity[:2] == (lease["boot_id"], lease["start_time"]):
            raise ConsumerReferenceError("consumer process remains alive")
        document["leases"] = [item for item in document["leases"] if item["application"] != application]
        _write(path, policy, document)
        return _validate(policy, document)


def assert_allocation_unreferenced(
    path: str | Path, policy: dict, allocation_key: str, *, generation_id: str | None = None
) -> None:
    """Fail closed when a durable lease still names the allocation."""
    with locked_consumer_references(path):
        document = _read(path, policy)
        if any(
            item["allocation_key"] == allocation_key
            and (generation_id is None or document["version"] != 2 or item.get("generation_id") == generation_id)
            for item in document["leases"]
        ):
            raise ConsumerReferenceError("allocation retains a durable runtime consumer lease")


def reserve_staged_consumer(
    path: str | Path,
    policy: dict,
    application: str,
    pid: int,
    *,
    namespace: str,
    staging_executable: str,
    journal_path: str | Path,
    bindings_path: str | Path,
    intent_path: str | Path,
    observe,
    generation_id: str = "unversioned",
    kernel_profile: str | None = None,
    already_locked: bool = False,
) -> dict:
    """Reserve a stopped launch gate before it can execute the registered program.

    The gate must already be inside the verified namespace and blocked on its
    private release pipe. The caller owns that pipe and must close it on every
    failure. This is cooperating-process authority, not hostile-root isolation.
    """
    from nord_tools_internal.nordvpn_consumer_reference_store import read_private_json
    from nord_tools_internal.nordvpn_application_plan import plan_application

    checked = validate_policy(policy)
    plan = plan_application(checked, application)
    selected_kernel_profile = kernel_profile or kernel_profile_for_allocation(
        plan.allocation_key, plan.profile, plan.sharing
    )
    from contextlib import nullcontext

    lifecycle_lock = nullcontext() if already_locked else lifecycle_execution_lock(journal_path)
    consumer_lock = nullcontext() if already_locked else locked_consumer_references(path)
    with lifecycle_lock, consumer_lock:
        journal = validate_journal(read_private_json(journal_path))
        bindings = read_private_json(bindings_path)
        intents = read_private_json(intent_path)
        preflight = preflight_ownership(journal, bindings, observe(), intents)
        resources = [item for item in journal["allocations"]["resources"] if item["profile"] == selected_kernel_profile]
        if len(resources) != 4 or sorted(item["kind"] for item in resources) != [
            "interface",
            "interface",
            "interface",
            "namespace",
        ]:
            raise ConsumerReferenceError("allocation does not have a complete provisioned resource set")
        states = {item["allocation_id"]: item["state"] for item in journal["events"]}
        findings = {item["allocation_id"]: item for item in preflight["resources"]}
        if any(
            states.get(item["allocation_id"]) != "active"
            or findings.get(item["allocation_id"], {}).get("finding") != "verified_current"
            for item in resources
        ):
            raise ConsumerReferenceError("allocation resources are not active and independently verified")
        owned_namespace = next(item["identifier"] for item in resources if item["kind"] == "namespace")
        if namespace != owned_namespace:
            raise ConsumerReferenceError("launch namespace differs from the verified allocation")
        try:
            expected = os.stat(f"/run/netns/{namespace}")
            actual = os.stat(f"/proc/{pid}/ns/net")
        except OSError as exc:
            raise ConsumerReferenceError(f"cannot verify staged process namespace: {exc}") from exc
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            raise ConsumerReferenceError("staged process is outside the verified namespace")
        document = _read(path, checked)
        if document["version"] != 2:
            raise ConsumerReferenceError("legacy lease store must be explicitly reconciled before launch")
        if any(lease["application"] == application for lease in document["leases"]):
            raise ConsumerReferenceError("consumer already has a lease; release or recover it first")
        before = _identity(pid)
        if before[2] != staging_executable or _identity(pid) != before:
            raise ConsumerReferenceError("staged process identity changed before lease reservation")
        document["leases"].append(
            {
                "application": application,
                "profile": plan.profile,
                "allocation_key": plan.allocation_key,
                "pid": pid,
                "boot_id": before[0],
                "start_time": before[1],
                "executable": checked["applications"][application]["executable"],
                "generation_id": generation_id,
                "kernel_profile": selected_kernel_profile,
            }
        )
        _write(path, checked, document)
        return _validate(checked, document)


def acquire_provisioned_consumer(
    path: str | Path,
    policy: dict,
    application: str,
    pid: int,
    *,
    journal_path: str | Path,
    bindings_path: str | Path,
    intent_path: str | Path,
    observe,
    generation_id: str = "unversioned",
    kernel_profile: str | None = None,
) -> dict:
    """Bind a live process to a fully verified, provisioned kernel allocation.

    The journal execution lock precedes the reference lock, matching cleanup.
    Fresh preflight evidence must cover exactly the allocation's namespace and
    three interfaces, all active and owner-verified. A missing or uncertain
    resource refuses acquisition. No network mutation occurs here.
    """
    from nord_tools_internal.nordvpn_consumer_reference_store import read_private_json
    from nord_tools_internal.nordvpn_application_plan import plan_application

    checked = validate_policy(policy)
    plan = plan_application(checked, application)
    selected_kernel_profile = kernel_profile or kernel_profile_for_allocation(
        plan.allocation_key, plan.profile, plan.sharing
    )
    with lifecycle_execution_lock(journal_path), locked_consumer_references(path):
        journal = validate_journal(read_private_json(journal_path))
        bindings = read_private_json(bindings_path)
        intents = read_private_json(intent_path)
        observation = observe()
        preflight = preflight_ownership(journal, bindings, observation, intents)
        resources = [item for item in journal["allocations"]["resources"] if item["profile"] == selected_kernel_profile]
        if len(resources) != 4 or sorted(item["kind"] for item in resources) != [
            "interface",
            "interface",
            "interface",
            "namespace",
        ]:
            raise ConsumerReferenceError("allocation does not have a complete provisioned resource set")
        states = {item["allocation_id"]: item["state"] for item in journal["events"]}
        findings = {item["allocation_id"]: item for item in preflight["resources"]}
        if any(
            states.get(item["allocation_id"]) != "active"
            or findings.get(item["allocation_id"], {}).get("finding") != "verified_current"
            for item in resources
        ):
            raise ConsumerReferenceError("allocation resources are not active and independently verified")
        document = _read(path, checked)
        if document["version"] != 2:
            raise ConsumerReferenceError("legacy lease store must be explicitly reconciled before acquisition")
        if any(lease["application"] == application for lease in document["leases"]):
            raise ConsumerReferenceError("consumer already has a lease; release or recover it first")
        before = _identity(pid)
        if before[2] != checked["applications"][application]["executable"] or _identity(pid) != before:
            raise ConsumerReferenceError("consumer executable or process identity changed during acquisition")
        document["leases"].append(
            {
                "application": application,
                "profile": plan.profile,
                "allocation_key": plan.allocation_key,
                "pid": pid,
                "boot_id": before[0],
                "start_time": before[1],
                "executable": before[2],
                "generation_id": generation_id,
                "kernel_profile": selected_kernel_profile,
            }
        )
        _write(path, checked, document)
        return _validate(checked, document)
