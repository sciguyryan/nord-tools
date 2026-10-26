"""Validate proposed resource identities before any privileged provisioning exists.

An allocation record is not independent kernel evidence and grants no authority
for modification or deletion. Tokens are generated once, never from names.
"""

from __future__ import annotations

import re
import secrets

from nord_tools_internal.nordvpn_registry import RegistryError, validate_registry

TOKEN = re.compile(r"[0-9a-f]{32}\Z")


def allocate_identity(kind: str, identifier: str, profile: str) -> dict:
    """Create a candidate identity for a future provisioner, without side effects."""
    resource = {"kind": kind, "identifier": identifier, "profile": profile, "owner": "nord-tools"}
    validate_registry({"version": 1, "resources": [resource]})
    return {**resource, "allocation_id": secrets.token_hex(16)}


def validate_allocations(document: object) -> dict:
    """Validate a strict versioned allocation ledger and reject reused tokens."""
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "resources"}
        or type(document["version"]) is not int
        or document["version"] != 2
        or not isinstance(document["resources"], list)
    ):
        raise RegistryError("allocation ledger requires version 2 and a resources array")
    resources = []
    tokens = set()
    for item in document["resources"]:
        if not isinstance(item, dict) or set(item) != {"kind", "identifier", "profile", "owner", "allocation_id"}:
            raise RegistryError("invalid allocation resource fields")
        token = item["allocation_id"]
        if not isinstance(token, str) or not TOKEN.fullmatch(token) or token in tokens:
            raise RegistryError("invalid or reused allocation identity")
        tokens.add(token)
        resources.append({key: item[key] for key in ("kind", "identifier", "profile", "owner")})
    validate_registry({"version": 1, "resources": resources})
    return {
        "version": 2,
        "resources": [
            {**resource, "allocation_id": item["allocation_id"]}
            for resource, item in zip(resources, document["resources"], strict=True)
        ],
    }


def inspect_allocations(document: object) -> dict:
    """Report identity structure, without treating a ledger as ownership proof."""
    validated = validate_allocations(document)
    return {
        "schema_version": 1,
        "mode": "offline_identity_inspection",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_delete": False,
        "resources": validated["resources"],
    }
