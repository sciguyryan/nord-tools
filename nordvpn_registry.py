"""Validate an offline ownership ledger and compare it with simulated observations.

A ledger is evidence of intent, not authority to remove kernel resources.
No host resources are discovered or modified here.
"""

from __future__ import annotations

import json
from pathlib import Path
import re

from nordvpn_reconcile import ReconciliationError, validate_inventory


class RegistryError(ValueError):
    """An ownership ledger or observation is unsafe or inconsistent."""


KINDS = frozenset({"namespace", "interface", "route", "firewall", "dns", "service"})
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z")
PROFILE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


def read_json(path: str | Path) -> object:
    """Read a supplied fixture, refusing symlink redirection."""
    source = Path(path)
    if source.is_symlink():
        raise RegistryError(f"refusing symlinked fixture: {source}")
    try:
        return json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RegistryError(f"cannot read fixture {source}: {exc}") from exc


def validate_registry(document: object) -> dict:
    """Require a unique, strictly versioned set of Nord Tools resource claims."""
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "resources"}
        or type(document["version"]) is not int
        or document["version"] != 1
        or not isinstance(document["resources"], list)
    ):
        raise RegistryError("registry requires version 1 and a resources array")
    seen = set()
    records = []
    for entry in document["resources"]:
        if not isinstance(entry, dict) or set(entry) != {"kind", "identifier", "profile", "owner"}:
            raise RegistryError("invalid registry resource fields")
        kind, identifier, profile, owner = (entry[key] for key in ("kind", "identifier", "profile", "owner"))
        if (
            kind not in KINDS
            or not isinstance(identifier, str)
            or not IDENTIFIER.fullmatch(identifier)
            or not isinstance(profile, str)
            or not PROFILE.fullmatch(profile)
            or owner != "nord-tools"
        ):
            raise RegistryError("invalid registry resource identity or ownership")
        key = (kind, identifier)
        if key in seen:
            raise RegistryError(f"duplicate resource identity: {kind}/{identifier}")
        seen.add(key)
        records.append(dict(entry))
    return {"version": 1, "resources": records}


def audit_registry(registry: object, inventory: object) -> dict:
    """Flag unverified and conflicting claims without granting deletion authority."""
    ledger = validate_registry(registry)
    try:
        observed = validate_inventory(inventory)
    except ReconciliationError as exc:
        raise RegistryError(str(exc)) from exc
    findings = []
    recorded_profiles = {item["profile"] for item in ledger["resources"]}
    for item in sorted(ledger["resources"], key=lambda r: (r["profile"], r["kind"], r["identifier"])):
        profile = item["profile"]
        record = observed.get(profile)
        if record is None:
            status = "unobserved_profile"
        elif record["owner"] != "nord-tools":
            status = "ownership_conflict"
        elif record["state"] != "ready":
            status = "profile_" + record["state"]
        else:
            status = "unverified_resource"
        findings.append({**item, "finding": status})
    for profile in sorted(set(observed) - recorded_profiles):
        if observed[profile]["owner"] == "nord-tools":
            findings.append({"profile": profile, "finding": "unregistered_profile"})
    return {
        "schema_version": 1,
        "mode": "offline_audit",
        "network_changes_applied": False,
        "ownership_verified": False,
        "safe_to_delete": False,
        "findings": findings,
    }
