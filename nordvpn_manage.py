"""Offline desired-state management for future Nord Tools networking.

This module stores validated intent only. It does not create interfaces,
install services, change routes or assert that a VPN is connected.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from nordvpn_dependency_plan import plan_dependencies
from nordvpn_management_views import cleanup_plan, topology_graph
from nordvpn_discovery import DiscoveryError, discover
from nordvpn_evidence import correlate
from nordvpn_identity import inspect_allocations
from nordvpn_lifecycle import inspect_lifecycle
from nordvpn_identity_evidence import inspect_identity_evidence
from nordvpn_profiles import ProfileError, validate_policy
from nordvpn_reconcile import ReconciliationError, load_inventory, plan_reconciliation
from nordvpn_registry import RegistryError, audit_registry, read_json
from nordvpn_transaction_plan import plan_transactions


class ManagementError(ValueError):
    """An intent operation cannot be performed safely."""


def state_path(persist: bool) -> Path:
    """Choose persistent configuration or a login-session runtime directory."""
    if persist:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    else:
        runtime = os.environ.get("XDG_RUNTIME_DIR")
        if not runtime:
            raise ManagementError("transient intent requires XDG_RUNTIME_DIR; no persistent fallback is safe")
        base = Path(runtime)
    return base / "nord-tools" / "desired-policy.json"


def _read(path: Path) -> dict | None:
    if path.is_symlink():
        raise ManagementError(f"refusing symlinked intent file: {path}")
    if not path.exists():
        return None
    try:
        return validate_policy(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, ProfileError) as exc:
        raise ManagementError(f"cannot read valid intent from {path}: {exc}") from exc


def _write(path: Path, policy: dict) -> None:
    if path.is_symlink():
        raise ManagementError(f"refusing symlinked intent file: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ManagementError("refusing symlinked intent directory")
    # Atomic replacement avoids truncated policy on interruption. Never touch
    # host networking or another application's configuration.
    fd, temporary = tempfile.mkstemp(prefix=".desired-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(policy, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load_input(filename: str) -> dict:
    try:
        with open(filename, encoding="utf-8") as source:
            return validate_policy(json.load(source))
    except (OSError, ValueError, ProfileError) as exc:
        raise ManagementError(f"invalid policy {filename}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in (
        "plan",
        "configure",
        "status",
        "clear",
        "reconcile",
        "audit",
        "discover",
        "evidence",
        "identities",
        "identity-evidence",
        "dependency-plan",
        "transaction-plan",
        "graph",
        "cleanup-plan",
        "lifecycle",
    ):
        command = commands.add_parser(name)
        command.add_argument(
            "--transient", action="store_true", help="Use session-only configuration instead of the persistent default"
        )
        if name in ("identities", "identity-evidence"):
            command.add_argument("--registry", required=True, help="Explicit version 2 allocation ledger JSON")
        if name == "lifecycle":
            command.add_argument("--journal", required=True, help="Explicit offline lifecycle journal JSON")
            command.add_argument("--observed", help="Optional simulated observation fixture JSON")
        if name == "evidence":
            command.add_argument("--registry", required=True, help="Explicit offline ownership ledger JSON")
        if name == "audit":
            command.add_argument("--registry", required=True, help="Explicit offline resource ledger JSON")
            command.add_argument("--inventory", required=True, help="Explicit simulated profile inventory JSON")
        if name in ("dependency-plan", "transaction-plan"):
            command.add_argument("--inventory", required=True, help="Explicit simulated profile inventory JSON")
            command.add_argument("--graph", required=True, help="Explicit dependency graph JSON")
        if name == "graph":
            command.add_argument(
                "--ascii", action="store_true", help="Use ASCII characters instead of Unicode box drawing"
            )
        if name == "cleanup-plan":
            command.add_argument(
                "--inventory", required=True, help="Explicit simulated inventory JSON (no host discovery)"
            )
        if name == "reconcile":
            command.add_argument(
                "--inventory", required=True, help="Explicit simulated inventory JSON (no host discovery)"
            )
        if name in ("plan", "configure"):
            command.add_argument("--policy", required=True, help="JSON policy to validate")
    args = parser.parse_args(argv)
    try:
        if args.action == "lifecycle":
            observations = read_json(args.observed) if args.observed else None
            print(json.dumps(inspect_lifecycle(read_json(args.journal), observations), indent=2, sort_keys=True))
            return 0
        if args.action == "cleanup-plan":
            print(json.dumps(cleanup_plan(load_inventory(args.inventory)), indent=2, sort_keys=True))
            return 0
        if args.action == "identity-evidence":
            print(json.dumps(inspect_identity_evidence(read_json(args.registry), discover()), indent=2, sort_keys=True))
            return 0
        if args.action == "identities":
            print(json.dumps(inspect_allocations(read_json(args.registry)), indent=2, sort_keys=True))
            return 0
        if args.action == "evidence":
            print(json.dumps(correlate(read_json(args.registry), discover()), indent=2, sort_keys=True))
            return 0
        if args.action == "discover":
            print(json.dumps(discover(), indent=2, sort_keys=True))
            return 0
        path = state_path(not args.transient)
        previous = _read(path)
        if args.action == "graph":
            if previous is None:
                raise ManagementError("no saved policy in selected scope; configure one first")
            print(
                topology_graph(previous, ascii_only=args.ascii, scope="transient" if args.transient else "persistent")
            )
            return 0
        if args.action in ("plan", "configure"):
            desired = _load_input(args.policy)
            change = "create" if previous is None else "unchanged" if previous == desired else "replace"
            result = {
                "scope": "transient" if args.transient else "persistent",
                "action": change,
                "intent_only": True,
                "path": str(path),
            }
            if args.action == "configure" and change != "unchanged":
                _write(path, desired)
        elif args.action == "audit":
            result = audit_registry(read_json(args.registry), load_inventory(args.inventory))
            result["scope"] = "transient" if args.transient else "persistent"
        elif args.action in ("dependency-plan", "transaction-plan", "graph", "cleanup-plan"):
            if previous is None:
                raise ManagementError("no saved policy in selected scope; configure one first")
            planner = plan_transactions if args.action == "transaction-plan" else plan_dependencies
            result = planner(previous, load_inventory(args.inventory), read_json(args.graph))
            result["scope"] = "transient" if args.transient else "persistent"
        elif args.action == "reconcile":
            if previous is None:
                raise ManagementError("no saved policy in selected scope; configure one first")
            result = plan_reconciliation(previous, load_inventory(args.inventory))
            result["scope"] = "transient" if args.transient else "persistent"
        elif args.action == "status":
            result = {
                "scope": "transient" if args.transient else "persistent",
                "configured": previous is not None,
                "intent_only": True,
                "path": str(path),
            }
            if previous is not None:
                result["profiles"] = sorted(previous["vpn_profiles"])
        else:
            result = {
                "scope": "transient" if args.transient else "persistent",
                "action": "remove" if previous is not None else "unchanged",
                "intent_only": True,
                "path": str(path),
            }
            if previous is not None:
                path.unlink()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ManagementError, ReconciliationError, RegistryError, DiscoveryError, OSError) as exc:
        print(f"manage: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
