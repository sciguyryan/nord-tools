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

from nord_tools_internal.nordvpn_dependency_plan import plan_dependencies
from nord_tools_internal.nordvpn_management_views import cleanup_plan, topology_graph
from nord_tools_internal.nordvpn_discovery import DiscoveryError, discover
from nord_tools_internal.nordvpn_evidence import correlate
from nord_tools_internal.nordvpn_identity import inspect_allocations
from nord_tools_internal.nordvpn_lifecycle import inspect_lifecycle
from nord_tools_internal.nordvpn_lifecycle_evidence import inspect_live_lifecycle
from nord_tools_internal.nordvpn_identity_evidence import inspect_identity_evidence
from nord_tools_internal.nordvpn_namespace_ownership import OwnershipError
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_restore_executor import (
    ProvisioningUncertainError,
    restore_boot_state,
)
from nord_tools_internal.nordvpn_state_reconcile import derive_actual_state, reconcile_desired
from nord_tools_internal.nordvpn_profiles import ProfileError, validate_policy
from nord_tools_internal.nordvpn_reconcile import ReconciliationError, load_inventory, plan_reconciliation
from nord_tools_internal.nordvpn_registry import RegistryError, audit_registry, read_json
from nord_tools_internal.nordvpn_startup import (
    install_startup_unit,
    plan_install,
    validate_startup_config,
)
from nord_tools_internal.nordvpn_underlay_install import UnderlayError
from nord_tools_internal.nordvpn_transaction_plan import plan_transactions


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
        "ownership-preflight",
        "reconcile-live",
        "startup-plan",
        "startup-install",
        "restore-startup",
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
            command.add_argument(
                "--live",
                action="store_true",
                help="Correlate against read-only Linux discovery (never proves ownership)",
            )
        if name == "evidence":
            command.add_argument("--registry", required=True, help="Explicit offline ownership ledger JSON")
        if name == "ownership-preflight":
            command.add_argument("--journal", required=True, help="Explicit lifecycle journal JSON")
            command.add_argument("--bindings", required=True, help="Explicit owner-record store JSON")
            command.add_argument(
                "--intents", help="Optional operation intent store JSON (unresolved intents block verification)"
            )
        if name == "reconcile-live":
            command.add_argument("--journal", required=True, help="Explicit lifecycle journal JSON")
            command.add_argument("--bindings", required=True, help="Explicit owner-record store JSON")
            command.add_argument(
                "--intents", help="Optional operation intent store JSON (unresolved intents block verification)"
            )
            command.add_argument("--graph", help="Optional profile dependency graph JSON")
        if name in ("startup-plan", "startup-install", "restore-startup"):
            command.add_argument("--config", required=True, help="Explicit startup configuration JSON")
        if name in ("startup-plan", "startup-install"):
            command.add_argument(
                "--unit-dir", default="/etc/systemd/system", help="Directory receiving nord-tools-restore.service"
            )
            command.add_argument("--python", help="Interpreter path recorded in the unit (default: this interpreter)")
        if name == "startup-install":
            command.add_argument(
                "--execute", action="store_true", help="Write the rendered unit; the default invocation only plans"
            )
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
            if args.live and args.observed:
                raise ManagementError("--live and --observed are mutually exclusive")
            journal = read_json(args.journal)
            if args.live:
                result = inspect_live_lifecycle(journal, discover())
            else:
                observations = read_json(args.observed) if args.observed else None
                result = inspect_lifecycle(journal, observations)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "ownership-preflight":
            journal = read_json(args.journal)
            bindings = read_json(args.bindings)
            intents = read_json(args.intents) if args.intents else None
            result = preflight_ownership(journal, bindings, discover(), intents)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "reconcile-live":
            if args.transient:
                raise ManagementError(
                    "reconcile-live uses the persistent saved policy; transient intent is never reconciled"
                )
            persistent = _read(state_path(True))
            if persistent is None:
                raise ManagementError("no saved persistent policy; configure one first")
            journal = read_json(args.journal)
            bindings = read_json(args.bindings)
            intents = read_json(args.intents) if args.intents else None
            preflight = preflight_ownership(journal, bindings, discover(), intents)
            # Derivation and reconciliation read files only; neither stores nor
            # the host change as a result of running this command.
            actual = derive_actual_state(journal, bindings, preflight)
            graph = read_json(args.graph) if args.graph else None
            result = reconcile_desired(persistent, actual, graph)
            result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action in ("startup-plan", "startup-install", "restore-startup"):
            if args.transient:
                raise ManagementError(
                    "startup management is persistent-only; transient intent is never restored or installed"
                )
            config = validate_startup_config(read_json(args.config))
            if args.action == "startup-plan":
                result = plan_install(
                    config, args.config, args.unit_dir, python_executable=args.python or sys.executable
                )
                result["scope"] = "persistent"
            elif args.action == "startup-install":
                result = install_startup_unit(
                    config,
                    args.config,
                    args.unit_dir,
                    python_executable=args.python or sys.executable,
                    execute=args.execute,
                )
                result["scope"] = "persistent"
            else:
                result = restore_boot_state(config)
                result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
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
    except (
        ManagementError,
        ReconciliationError,
        RegistryError,
        DiscoveryError,
        OwnershipError,
        ProvisioningUncertainError,
        UnderlayError,
        OSError,
    ) as exc:
        print(f"manage: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
