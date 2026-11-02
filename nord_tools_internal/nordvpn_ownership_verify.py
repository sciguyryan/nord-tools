"""Privileged ownership verification and interrupted-creation recovery preflight.

The owner-record store persists creation-time kernel identity bindings made while
the privileged creator still held authority: a namespace's ``/run/netns`` mount
device and inode pair, or an interface's creation-time scope and index. A later
process re-derives those identities from a fresh read-only discovery snapshot and
classifies every allocation as verified, conflicting, missing, unbound or
otherwise requiring review.

This is continuity evidence within one boot session, not an unforgeable
certificate. ``/run/netns`` is a tmpfs directory, so mount identities are
repopulated after a reboot, and a hostile process with directory access could
forge a record. A matching resource name never verifies anything by itself; the
recorded binding must match the live observation. Results are read-only
classifications: they never authorise modification or deletion, and execution
paths in later increments must re-verify ownership at the moment of mutation.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterator

from nord_tools_internal.nordvpn_lifecycle import validate_journal
from nord_tools_internal.nordvpn_operation_intent import validate_intents
from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_registry import IDENTIFIER, RegistryError

TOKEN = re.compile(r"[0-9a-f]{32}\Z")
# Bindings are only defined for resource kinds whose creation identity this
# layer can actually re-derive. Others remain explicitly unsupported.
KNOWN_KINDS = frozenset({"namespace", "interface"})
NETNS_MOUNT_DIR = Path("/run/netns")


def _validate_binding_shape(kind: str, binding: object) -> dict:
    """Validate the creation-time kernel identity evidence for one resource kind."""
    if not isinstance(binding, dict):
        raise RegistryError("binding must be an object")
    if kind == "namespace":
        if set(binding) != {"device", "inode"}:
            raise RegistryError("namespace binding requires device and inode")
        device, inode = binding["device"], binding["inode"]
        if type(device) is not int or device < 0 or type(inode) is not int or inode < 1:
            raise RegistryError("namespace binding requires a non-negative device and positive inode")
        return {"device": device, "inode": inode}
    if set(binding) != {"scope", "ifindex"}:
        raise RegistryError("interface binding requires scope and ifindex")
    scope, index = binding["scope"], binding["ifindex"]
    if not isinstance(scope, str) or not scope or type(index) is not int or index < 1:
        raise RegistryError("interface binding requires a scope and positive ifindex")
    return {"scope": scope, "ifindex": index}


def validate_recorded_configuration(configuration: object) -> dict:
    """Validate an optional provisioned-configuration snapshot as a profile shape.

    The recorded configuration is the provisioner's durable claim about what was
    configured when the binding was written. It is normalised exactly like the
    desired policy so later reconciliation can compare the two literally. A
    synthetic profile name is sufficient because validation does not depend on
    the profile name, only on the profile shape.
    """
    if not isinstance(configuration, dict) or set(configuration) != {"selection", "sharing"}:
        raise RegistryError("recorded configuration requires selection and sharing")
    try:
        checked = validate_policy(
            {
                "version": 1,
                "defaults": {"vpn": "recorded"},
                "vpn_profiles": {"recorded": {**configuration, "sharing": "shared"}},
                "applications": {},
            }
        )
    except (ValueError, TypeError) as exc:
        raise RegistryError(f"invalid recorded configuration: {exc}") from exc
    if configuration["sharing"] not in ("shared", "isolated"):
        raise RegistryError("recorded configuration sharing must be shared or isolated")
    return {**checked["vpn_profiles"]["recorded"], "sharing": configuration["sharing"]}


def _validate_document(document: object) -> dict:
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "bindings"}
        or type(document["version"]) is not int
        or document["version"] != 1
        or not isinstance(document["bindings"], list)
    ):
        raise RegistryError("owner bindings require version 1 and a bindings array")
    base = {"allocation_id", "kind", "identifier", "binding"}
    entries = []
    tokens = set()
    identities = set()
    for entry in document["bindings"]:
        if not isinstance(entry, dict) or not base <= set(entry) or set(entry) - base not in (set(), {"configuration"}):
            raise RegistryError("invalid owner binding fields")
        token, kind, identifier = entry["allocation_id"], entry["kind"], entry["identifier"]
        if not isinstance(token, str) or not TOKEN.fullmatch(token) or token in tokens:
            raise RegistryError("invalid or reused binding identity")
        if kind not in KNOWN_KINDS or not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            raise RegistryError("invalid binding resource identity")
        if (kind, identifier) in identities:
            raise RegistryError(f"duplicate binding resource identity: {kind}/{identifier}")
        tokens.add(token)
        identities.add((kind, identifier))
        record = {
            "allocation_id": token,
            "kind": kind,
            "identifier": identifier,
            "binding": _validate_binding_shape(kind, entry["binding"]),
        }
        if "configuration" in entry:
            record["configuration"] = validate_recorded_configuration(entry["configuration"])
        entries.append(record)
    return {"version": 1, "bindings": entries}


def _cross_check(bindings: dict, journal: dict) -> dict:
    """Require every binding to describe exactly one allocation in the journal."""
    allocations = {item["allocation_id"]: item for item in validate_journal(journal)["allocations"]["resources"]}
    for entry in bindings["bindings"]:
        allocation = allocations.get(entry["allocation_id"])
        if allocation is None or allocation["kind"] != entry["kind"] or allocation["identifier"] != entry["identifier"]:
            raise RegistryError("binding does not match the validated allocation ledger")
    return bindings


def validate_bindings(document: object, journal: object | None = None) -> dict:
    """Validate owner bindings and, when supplied, their allocation association."""
    bindings = _validate_document(document)
    return bindings if journal is None else _cross_check(bindings, journal)


def _check_components(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RegistryError("refusing symlinked ownership record path")


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialise cooperating writers on a stable sibling lock file."""
    _check_components(path)
    if not path.parent.is_dir():
        raise RegistryError("ownership record store parent must already exist")
    lock = path.with_name(path.name + ".lock")
    _check_components(lock)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise RegistryError("unsafe ownership record lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        _check_components(path)
        current = os.stat(lock, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RegistryError("ownership record lock identity changed")
        yield
    finally:
        os.close(fd)


def _load(path: Path, journal: object) -> dict:
    _check_components(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
                raise RegistryError("unsafe ownership record store")
            return validate_bindings(json.load(source), journal)
    except (OSError, ValueError, UnicodeError) as exc:
        raise RegistryError("cannot load existing ownership records") from exc


def _write(path: Path, document: dict) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".ownership-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(document, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def initialise_bindings(path: str | Path) -> dict:
    """Create an empty store only if absent; never overwrite existing state."""
    target = Path(path).absolute()
    with _locked(target):
        if target.exists() or target.is_symlink():
            raise RegistryError("ownership record store already exists")
        document = _validate_document({"version": 1, "bindings": []})
        # Exclusive creation avoids replacing a concurrently introduced file.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(document, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        return document


def record_binding(
    path: str | Path,
    journal: object,
    allocation_id: str,
    binding: object,
    configuration: object | None = None,
) -> dict:
    """Append one immutable creation-time binding under the stable lock.

    ``binding`` records the kernel identity observed while privileged authority
    was still live. ``configuration`` optionally records the provisioned
    profile configuration at that moment for later desired-state comparison.
    Bindings are never rewritten or removed. Retirement history is deliberately
    retained so that later name reuse is detected as an identity conflict rather
    than mistaken for continued ownership.
    """
    if not isinstance(allocation_id, str) or not TOKEN.fullmatch(allocation_id):
        raise RegistryError("invalid allocation identity")
    target = Path(path).absolute()
    validated = validate_journal(journal)
    allocations = {item["allocation_id"]: item for item in validated["allocations"]["resources"]}
    allocation = allocations.get(allocation_id)
    if allocation is None or allocation["kind"] not in KNOWN_KINDS:
        raise RegistryError("binding requires a supported allocation identity")
    entry = {
        "allocation_id": allocation_id,
        "kind": allocation["kind"],
        "identifier": allocation["identifier"],
        "binding": _validate_binding_shape(allocation["kind"], binding),
    }
    if configuration is not None:
        entry["configuration"] = validate_recorded_configuration(configuration)
    with _locked(target):
        existing = _load(target, validated)
        if any(item["allocation_id"] == allocation_id for item in existing["bindings"]):
            raise RegistryError("allocation is already bound; ownership records are immutable")
        revised = _cross_check(_validate_document({**existing, "bindings": [*existing["bindings"], entry]}), validated)
        _write(target, revised)
        return revised


def read_bindings(path: str | Path, journal: object) -> dict:
    """Load and validate the store against the supplied journal, read-only."""
    target = Path(path).absolute()
    validated = validate_journal(journal)
    with _locked(target):
        try:
            return _load(target, validated)
        except (OSError, ValueError, UnicodeError) as exc:
            raise RegistryError("cannot load existing ownership records") from exc


def _live_netns_identity(name: str) -> dict:
    """Observe the namespace mount identity; requires privileges where enforced."""
    target = NETNS_MOUNT_DIR / name
    try:
        info = os.stat(target, follow_symlinks=False)
    except OSError as exc:
        raise RegistryError(f"namespace mount {name} is not observable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise RegistryError(f"unexpected namespace mount type for {name}")
    return {"device": info.st_dev, "inode": info.st_ino}


def _resolve_netns_identity(name: str, provided: dict | None) -> dict:
    if provided is None:
        return _live_netns_identity(name)
    value = provided.get(name)
    if type(value) is not dict:
        raise RegistryError(f"netns identity evidence is incomplete for {name}")
    return _validate_binding_shape("namespace", value)


def _observation_scopes(observation: object) -> tuple[list[str], dict[tuple[str, str], int]]:
    """Validate a complete discovery snapshot and index observed interfaces."""
    if (
        not isinstance(observation, dict)
        or observation.get("mode") != "live_read_only"
        or observation.get("network_changes_applied") is not False
    ):
        raise RegistryError("ownership preflight requires complete read-only Linux discovery evidence")
    namespaces = observation.get("namespaces")
    host = observation.get("host_interfaces")
    details = observation.get("namespace_details")
    if not isinstance(namespaces, list) or not isinstance(host, list) or not isinstance(details, list):
        raise RegistryError("incomplete discovery evidence")
    if any(not isinstance(name, str) or not name for name in namespaces) or len(namespaces) != len(set(namespaces)):
        raise RegistryError("invalid or duplicate namespace observation")
    entries = []
    for item in details:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or not isinstance(item.get("interfaces"), list)
        ):
            raise RegistryError("invalid namespace detail observation")
        entries.append(item)
    if sorted(item["name"] for item in entries) != sorted(namespaces):
        raise RegistryError("incomplete or duplicate namespace details")
    links: dict[tuple[str, str], int] = {}
    for scope, observed in [
        ("host", host),
        *[(item["name"], item["interfaces"]) for item in entries],
    ]:
        for link in observed:
            if (
                not isinstance(link, dict)
                or not isinstance(link.get("name"), str)
                or not link["name"]
                or type(link.get("index")) is not int
                or link["index"] < 1
            ):
                raise RegistryError("invalid observed interface identity")
            key = (scope, link["name"])
            if key in links or any(
                index == link["index"] for (other_scope, _), index in links.items() if other_scope == scope
            ):
                raise RegistryError("duplicate observed interface identity")
            links[key] = link["index"]
    return namespaces, links


def _absence_finding(state: str | None) -> tuple[str, bool]:
    """A claimed resource may be absent only when retirement was recorded."""
    if state == "retired":
        return "consistent_retired", True
    return "resource_missing", False


def _state_finding(state: str | None) -> str:
    """Classify an observed, bound resource whose lifecycle state is not stable."""
    if state in {"creating", "retiring", "failed"}:
        return "interrupted_transition"
    return "uncertain_state"


def preflight_ownership(
    journal: object,
    bindings: object,
    observation: object,
    intents: object | None = None,
    *,
    netns_identity: dict[str, dict] | None = None,
) -> dict:
    """Classify allocations against durable bindings and fresh observations.

    Verified means a recorded creation-time binding still matches live kernel
    observation within the same boot session, with a stable lifecycle state and
    no unresolved operation intent. Name matches alone never verify anything.
    One unverified, foreign or uncertain resource fails the entire batch; the
    result classifies recovery obligations but performs no network changes.
    """
    validated = validate_journal(journal)
    validated_bindings = validate_bindings(bindings, validated)
    namespaces, links = _observation_scopes(observation)
    allocations = validated["allocations"]["resources"]
    bindings_by_token = {entry["allocation_id"]: entry for entry in validated_bindings["bindings"]}
    states = {event["allocation_id"]: event["state"] for event in validated["events"]}
    claimed = {(item["kind"], item["identifier"]) for item in allocations}
    claimed_namespaces = {item["identifier"] for item in allocations if item["kind"] == "namespace"}
    if netns_identity is not None:
        if not isinstance(netns_identity, dict) or any(
            name not in namespaces and name not in claimed_namespaces for name in netns_identity
        ):
            raise RegistryError("netns identity evidence covers an unobserved namespace")
    unresolved = set()
    unresolved_intents = []
    if intents is not None:
        intent_document = validate_intents(intents, validated)
        unresolved_intents = sorted(
            [
                {
                    "allocation_id": item["allocation_id"],
                    "operation_id": item["operation_id"],
                    "action": item["action"],
                    "outcome": item["outcome"],
                    "journal_sequence": item["journal_sequence"],
                }
                for item in intent_document["operations"]
                if item["outcome"] in {"pending", "uncertain"}
            ],
            key=lambda item: (item["allocation_id"], item["operation_id"]),
        )
        unresolved = {item["allocation_id"] for item in unresolved_intents}
    findings = []
    for allocation in sorted(allocations, key=lambda item: (item["kind"], item["identifier"])):
        token, kind, identifier = allocation["allocation_id"], allocation["kind"], allocation["identifier"]
        state = states.get(token)
        recorded = bindings_by_token[token]["binding"] if token in bindings_by_token else None
        observed_identity = None
        if kind not in KNOWN_KINDS:
            finding, verified = "unsupported_resource_kind", False
        elif token in unresolved:
            finding, verified = "uncertain_intent", False
        elif recorded is None:
            if state == "retired":
                # A recorded retirement without a binding: the lifecycle record
                # is the retirement evidence, and a still-observable name
                # surfaces through the unclaimed list instead of here.
                finding, verified = "consistent_retired", True
            else:
                finding, verified = "unbound_claim", False
        elif kind == "namespace":
            observed_identity = None
            if identifier not in namespaces:
                finding, verified = _absence_finding(state)
            else:
                identity = _resolve_netns_identity(identifier, netns_identity)
                observed_identity = identity
                if identity != recorded:
                    finding, verified = "identity_conflict", False
                elif state == "active":
                    finding, verified = "verified_current", True
                elif state == "retired":
                    finding, verified = "possible_name_reuse", False
                else:
                    finding, verified = _state_finding(state), False
        else:
            scope = recorded["scope"]
            observed_identity = {"scope": scope, "ifindex": links.get((scope, identifier))}
            if scope != "host" and scope not in namespaces:
                if state == "retired":
                    # The recorded namespace itself was retired; nothing about
                    # the interface should remain observable.
                    finding, verified = "consistent_retired", True
                else:
                    finding, verified = "scope_missing", False
            elif (scope, identifier) not in links:
                finding, verified = _absence_finding(state)
            elif links[(scope, identifier)] != recorded["ifindex"]:
                finding, verified = "identity_conflict", False
            elif state == "active":
                finding, verified = "verified_current", True
            elif state == "retired":
                finding, verified = "possible_name_reuse", False
            else:
                finding, verified = _state_finding(state), False
        findings.append(
            {
                "allocation_id": token,
                "kind": kind,
                "identifier": identifier,
                "lifecycle_state": state if state is not None else "unrecorded",
                "finding": finding,
                "verified": verified,
                "recorded_identity": recorded,
                "observed_identity": observed_identity,
            }
        )
    unclaimed = []
    for name in namespaces:
        if ("namespace", name) not in claimed:
            unclaimed.append({"kind": "namespace", "identifier": name})
    for scope, name in sorted(links, key=lambda item: (item[0], item[1])):
        if ("interface", name) not in claimed:
            unclaimed.append({"kind": "interface", "scope": scope, "identifier": name})
    unclaimed.sort(key=lambda item: (item["kind"], item.get("scope", ""), item["identifier"]))
    verified_ids = [item["allocation_id"] for item in findings if item["verified"]]
    every_verified = len(verified_ids) == len(allocations)
    return {
        "schema_version": 1,
        "mode": "read_only_ownership_preflight",
        "network_changes_applied": False,
        "ownership_verified": every_verified,
        "operator_review_required": not every_verified,
        "safe_to_modify": False,
        "safe_to_delete": False,
        "automatic_recovery_permitted": False,
        "requires_reverification_at_execution": True,
        "verified_resources": verified_ids,
        "unclaimed": unclaimed,
        "unresolved_intents": unresolved_intents,
        "resources": findings,
        "limitations": (
            "Creation-time binding continuity within one boot session only; /run/netns identities are "
            "repopulated after a reboot; a hostile process with store-directory access is not excluded. "
            "Results never authorise mutation or deletion; re-verify at the moment of execution."
        ),
    }
