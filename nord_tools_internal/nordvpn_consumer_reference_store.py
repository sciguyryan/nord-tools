"""Conservative persisted consumer-reference evidence, without kernel authority.

The snapshot records declared consumers, not observed running processes. A stale
snapshot cannot prove absence, and callers must not use it to authorise deletion.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from nord_tools_internal.nordvpn_profiles import validate_policy
from nord_tools_internal.nordvpn_sharing_contract import resolve_ownership_groups


class ConsumerReferenceError(ValueError):
    """Reference evidence is invalid, incomplete or inconsistent."""


def validate_consumer_references(policy: dict, document: object) -> dict:
    """Validate a complete declared-reference snapshot against the policy.

    Every registered consumer must be represented, including inactive ones.
    This prevents a missing entry from being mistaken for a released reference.
    """
    checked = validate_policy(policy)
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "consumers"}
        or type(document["version"]) is not int
        or document["version"] != 1
    ):
        raise ConsumerReferenceError("invalid consumer reference document version or fields")
    entries = document["consumers"]
    if not isinstance(entries, list):
        raise ConsumerReferenceError("consumer reference entries must be a list")
    expected = {
        consumer: (group.profile, group.allocation_key)
        for group in resolve_ownership_groups(checked)
        for consumer in group.consumers
    }
    seen: dict[str, dict] = {}
    for item in entries:
        if not isinstance(item, dict) or set(item) != {"application", "profile", "allocation_key", "active"}:
            raise ConsumerReferenceError("invalid consumer reference entry")
        name = item["application"]
        if not isinstance(name, str) or name not in expected or name in seen:
            raise ConsumerReferenceError("unknown or duplicate consumer reference")
        if (item["profile"], item["allocation_key"]) != expected[name] or type(item["active"]) is not bool:
            raise ConsumerReferenceError("consumer reference conflicts with the validated policy")
        seen[name] = item
    if set(seen) != set(expected):
        raise ConsumerReferenceError("consumer reference snapshot is incomplete")
    return {"version": 1, "consumers": [dict(seen[name]) for name in sorted(seen)]}


def read_consumer_references(path: str | Path, policy: dict) -> dict:
    """Read and validate a private, regular reference document."""
    target = Path(path)
    try:
        fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            import stat

            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                raise ConsumerReferenceError("unsafe consumer reference file")
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                raw = json.load(stream)
        finally:
            os.close(fd)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ConsumerReferenceError(f"cannot read consumer reference evidence: {exc}") from exc
    return validate_consumer_references(policy, raw)


def write_consumer_references(path: str | Path, policy: dict, document: object) -> None:
    """Atomically replace a validated snapshot in an operator-controlled directory.

    This is a storage primitive, not a reference acquisition/release API. The
    caller must serialise writers and establish its own runtime evidence.
    """
    checked = validate_consumer_references(policy, document)
    target = Path(path)
    descriptor = None
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            json.dump(checked, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        temporary = None
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            os.unlink(temporary)
