"""Durable identity evidence for host-default protection operations."""

from __future__ import annotations

from contextlib import contextmanager
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterator

from nord_tools_internal.nordvpn_registry import RegistryError


_BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_OPERATIONS = {"activate", "deactivate"}
_OUTCOMES = {"preparing", "active", "protected_unavailable", "retiring", "retired", "uncertain"}
_STEP_STATES = {"pending", "observed", "absent", "uncertain"}
_MAX_HISTORY = 32
_CREATION_ORDER = ("barrier", "endpoint", "wireguard", "routes", "resolver")
_RETIREMENT_ORDER = ("remove_resolver", "remove_routes", "remove_wireguard", "remove_endpoint", "remove_barrier")


def empty_host_store() -> dict:
    return {"version": 1, "record": None, "history": []}


def validate_host_store(document: object) -> dict:
    """Validate the closed transaction schema without granting ownership."""
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "record", "history"}
        or document["version"] != 1
        or not isinstance(document["history"], list)
        or len(document["history"]) > _MAX_HISTORY
    ):
        raise RegistryError("host protection store requires version 1, one current record and bounded history")
    record = document["record"]
    if record is None:
        current = None
    else:
        current = _validate_record(record)
    history = [_validate_record(item) for item in document["history"]]
    return {"version": 1, "record": current, "history": history}


def _validate_record(record: object) -> dict:
    required = {
        "generation",
        "plan_sha256",
        "boot_id",
        "operation",
        "outcome",
        "ordinary_egress_blocked",
        "steps",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise RegistryError("invalid host protection transaction record")
    if not isinstance(record["generation"], str) or not record["generation"] or len(record["generation"]) > 64:
        raise RegistryError("invalid host protection generation record")
    if not isinstance(record["plan_sha256"], str) or not _FINGERPRINT.fullmatch(record["plan_sha256"]):
        raise RegistryError("invalid host protection plan fingerprint")
    if not isinstance(record["boot_id"], str) or not _BOOT_ID.fullmatch(record["boot_id"]):
        raise RegistryError("invalid host protection boot identity")
    if record["operation"] not in _OPERATIONS or record["outcome"] not in _OUTCOMES:
        raise RegistryError("invalid host protection operation state")
    if type(record["ordinary_egress_blocked"]) is not bool or not isinstance(record["steps"], list):
        raise RegistryError("invalid host protection barrier state")
    names: set[str] = set()
    steps = []
    for step in record["steps"]:
        if not isinstance(step, dict) or set(step) != {"name", "state", "intent", "evidence"}:
            raise RegistryError("invalid host protection step")
        if (
            not isinstance(step["name"], str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,47}", step["name"])
            or step["name"] in names
            or step["state"] not in _STEP_STATES
            or not isinstance(step["intent"], dict)
            or (step["evidence"] is not None and not isinstance(step["evidence"], dict))
        ):
            raise RegistryError("invalid host protection step evidence")
        names.add(step["name"])
        steps.append(copy.deepcopy(step))
    result = copy.deepcopy(record)
    result["steps"] = steps
    names_in_order = tuple(step["name"] for step in steps)
    if record["operation"] == "activate":
        permitted_orders = {_CREATION_ORDER[:index] for index in range(len(_CREATION_ORDER) + 1)}
    else:
        permitted_orders = {_CREATION_ORDER + _RETIREMENT_ORDER[:index] for index in range(len(_RETIREMENT_ORDER) + 1)}
    if names_in_order not in permitted_orders:
        raise RegistryError("host protection steps do not follow the lifecycle order")
    by_name = {step["name"]: step for step in steps}
    if record["outcome"] in {"active", "protected_unavailable"} and (
        not record["ordinary_egress_blocked"]
        or any(by_name.get(name, {}).get("state") != "observed" for name in _CREATION_ORDER)
    ):
        raise RegistryError("active host protection record lacks observed resources or its barrier")
    if record["outcome"] == "retired" and (
        record["ordinary_egress_blocked"]
        or any(by_name.get(name, {}).get("state") != "absent" for name in _RETIREMENT_ORDER)
    ):
        raise RegistryError("retired host protection record retains resources or its barrier")
    return result


def _check_path(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RegistryError("refusing symlinked host protection store path")


@contextmanager
def locked_host_store(path: str | Path) -> Iterator[Path]:
    """Lock a root-owned private store directory using a stable sibling inode."""
    target = Path(path).absolute()
    _check_path(target)
    try:
        parent_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise RegistryError("host protection store directory does not exist") from exc
    try:
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
            raise RegistryError("unsafe host protection store directory")
        lock_name = target.name + ".lock"
        fd = os.open(
            lock_name,
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise RegistryError("unsafe host protection store lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            current = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
            live_parent = os.stat(target.parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise RegistryError("host protection store lock identity changed")
            if (live_parent.st_dev, live_parent.st_ino) != (parent.st_dev, parent.st_ino):
                raise RegistryError("host protection store directory identity changed")
            yield target
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def read_host_store(path: str | Path) -> dict:
    target = Path(path).absolute()
    _check_path(target)
    try:
        fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise RegistryError("unsafe host protection store")
            return validate_host_store(json.load(source))
    except (OSError, ValueError, UnicodeError) as exc:
        raise RegistryError("cannot read host protection store") from exc


def write_host_store(path: str | Path, document: object) -> dict:
    """Atomically replace the store and durably update its directory entry."""
    target = Path(path).absolute()
    validated = validate_host_store(document)
    fd, temporary = tempfile.mkstemp(prefix=".host-protection-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(validated, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return validated


def initialise_host_store(path: str | Path) -> dict:
    with locked_host_store(path) as target:
        if target.exists() or target.is_symlink():
            raise RegistryError("host protection store already exists")
        return write_host_store(target, empty_host_store())


def record_step_intent(document: object, name: str, intent: dict) -> dict:
    validated = validate_host_store(document)
    if validated["record"] is None or any(step["name"] == name for step in validated["record"]["steps"]):
        raise RegistryError("host protection step is missing or already recorded")
    revised = copy.deepcopy(validated)
    revised["record"]["steps"].append({"name": name, "state": "pending", "intent": intent, "evidence": None})
    return validate_host_store(revised)


def record_step_evidence(document: object, name: str, state: str, evidence: dict | None) -> dict:
    validated = validate_host_store(document)
    if state not in {"observed", "absent", "uncertain"}:
        raise RegistryError("invalid host protection step resolution")
    record = validated["record"]
    matching = [step for step in record["steps"] if step["name"] == name] if record is not None else []
    if len(matching) != 1 or matching[0]["state"] not in {"pending", "uncertain"}:
        raise RegistryError("host protection step is not unresolved")
    revised = copy.deepcopy(validated)
    for step in revised["record"]["steps"]:
        if step["name"] == name:
            step["state"] = state
            step["evidence"] = evidence
    return validate_host_store(revised)


def reopen_absent_step(document: object, name: str, intent: dict) -> dict:
    """Begin a retry only after recovery independently certified absence."""
    validated = validate_host_store(document)
    record = validated["record"]
    matching = [step for step in record["steps"] if step["name"] == name] if record is not None else []
    if len(matching) != 1 or matching[0]["state"] != "absent":
        raise RegistryError("host protection retry requires recovered absence")
    revised = copy.deepcopy(validated)
    for step in revised["record"]["steps"]:
        if step["name"] == name:
            step["state"] = "pending"
            step["intent"] = intent
            step["evidence"] = None
    return validate_host_store(revised)


def reopen_present_retirement(document: object, name: str, intent: dict) -> dict:
    """Retry a removal after recovery certified that its resource remains."""
    validated = validate_host_store(document)
    record = validated["record"]
    matching = [step for step in record["steps"] if step["name"] == name] if record is not None else []
    if not name.startswith("remove_") or len(matching) != 1 or matching[0]["state"] != "observed":
        raise RegistryError("host protection retirement retry requires recovered presence")
    revised = copy.deepcopy(validated)
    for step in revised["record"]["steps"]:
        if step["name"] == name:
            step["state"] = "pending"
            step["intent"] = intent
            step["evidence"] = None
    return validate_host_store(revised)
