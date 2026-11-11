"""Inspect routing intent and run explicit Nord Tools lifecycle operations.

Planning and status commands are read-only. Commands that install files, launch
applications or change networking require an explicit execution flag, except
for service-internal restoration and boot-barrier entry points.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError
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
from nord_tools_internal.nordvpn_recovery_executor import plan_recovery
from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup, reset_ownership
from nord_tools_internal.nordvpn_restore_executor import (
    ProvisioningUncertainError,
    restore_boot_state,
)
from nord_tools_internal.nordvpn_state_reconcile import derive_actual_state, reconcile_desired
from nord_tools_internal.nordvpn_profiles import ProfileError, validate_policy
from nord_tools_internal.nordvpn_provider import import_provider_configuration, read_provider_configuration
from nord_tools_internal.nordvpn_reconcile import ReconciliationError, load_inventory, plan_reconciliation
from nord_tools_internal.nordvpn_registry import RegistryError, audit_registry, read_json
from nord_tools_internal.nordvpn_startup import (
    install_startup_unit,
    plan_install,
    validate_startup_config,
)
from nord_tools_internal.nordvpn_underlay_install import UnderlayError
from nord_tools_internal.nordvpn_host_executor import HostProtectionError
from nord_tools_internal.nordvpn_transaction_plan import plan_transactions


class ManagementError(ValueError):
    """An intent operation cannot be performed safely."""


COMMAND_HELP = {
    "plan": "Preview a saved-policy change without writing it",
    "configure": "Validate and save desired routing intent",
    "status": "Show saved desired routing intent",
    "clear": "Remove saved desired routing intent",
    "reconcile": "Compare intent with a simulated inventory",
    "audit": "Audit an offline resource ledger against a simulated inventory",
    "discover": "Inspect supported live Linux resources without mutation",
    "evidence": "Correlate an offline ledger with live observations",
    "identities": "Validate allocation identities in an offline ledger",
    "identity-evidence": "Compare allocation identities with live observations",
    "dependency-plan": "Plan dependency-ordered changes from simulated state",
    "transaction-plan": "Expand simulated changes into non-executable stages",
    "graph": "Render the saved routing topology",
    "cleanup-plan": "Preview cleanup from a simulated inventory",
    "lifecycle": "Inspect a lifecycle journal and optional observations",
    "ownership-preflight": "Check live ownership evidence without authorising mutation",
    "operational-preflight": "Check the supported production environment without mutation",
    "reconcile-live": "Classify desired state from fresh live observations",
    "apply-live": "Preview or create verified-absent immutable allocations",
    "replacement-readiness": "Check whether a generation replacement may begin",
    "replace-profile": "Preview or execute immutable generation replacement",
    "replacement-status": "Inspect a generation replacement from fresh evidence",
    "retire-generation": "Preview or retire an unreferenced old generation",
    "recover-generation": "Inspect or execute evidence-certified generation recovery",
    "startup-plan": "Render the namespace restoration unit without installing it",
    "startup-install": "Preview or install the namespace restoration unit",
    "restore-startup": "Service entry point for configured startup restoration",
    "provision": "Preview or execute production namespace provisioning",
    "retire-consumers": "Preview or retire allocations for released consumers",
    "consumer-leases": "Inspect durable application leases",
    "acquire-consumer": "Preview or reserve a lease for an existing process",
    "launch-consumer": "Preview or launch a registered application",
    "release-exited-consumer": "Inspect or release a verified exited-process lease",
    "cleanup": "Preview or execute ownership-verified resource cleanup",
    "clear-ownership": "Preview or execute full teardown and evidence reset",
    "recovery": "Inspect or execute evidence-certified lifecycle recovery",
    "host-plan": "Preview the host-default protection plan",
    "host-status": "Inspect host-default protection from fresh evidence",
    "host-activate": "Preview or activate host-default protection",
    "host-deactivate": "Preview or retire host-default protection",
    "host-recovery": "Inspect or execute evidence-certified host recovery",
    "host-boot-barrier": "Service entry point that establishes the early deny barrier",
    "host-startup-plan": "Render host-default systemd units without installing them",
    "host-startup-install": "Preview or install host-default systemd units",
    "provider-import": "Preview or import an official WireGuard configuration",
}

TRANSIENT_COMMANDS = {
    "plan",
    "configure",
    "status",
    "clear",
    "reconcile",
    "audit",
    "dependency-plan",
    "transaction-plan",
    "graph",
}

PERSISTENT_ONLY_COMMANDS = {
    "reconcile-live",
    "apply-live",
    "replacement-readiness",
    "replace-profile",
    "replacement-status",
    "retire-generation",
    "recover-generation",
    "startup-plan",
    "startup-install",
    "restore-startup",
    "provision",
    "retire-consumers",
    "consumer-leases",
    "acquire-consumer",
    "launch-consumer",
    "release-exited-consumer",
    "cleanup",
    "clear-ownership",
    "recovery",
    "host-plan",
    "host-status",
    "host-activate",
    "host-deactivate",
    "host-recovery",
    "host-boot-barrier",
    "host-startup-plan",
    "host-startup-install",
    "provider-import",
}


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
        "operational-preflight",
        "reconcile-live",
        "apply-live",
        "replacement-readiness",
        "replace-profile",
        "replacement-status",
        "retire-generation",
        "recover-generation",
        "startup-plan",
        "startup-install",
        "restore-startup",
        "provision",
        "retire-consumers",
        "consumer-leases",
        "acquire-consumer",
        "launch-consumer",
        "release-exited-consumer",
        "cleanup",
        "clear-ownership",
        "recovery",
        "host-plan",
        "host-status",
        "host-activate",
        "host-deactivate",
        "host-recovery",
        "host-boot-barrier",
        "host-startup-plan",
        "host-startup-install",
        "provider-import",
    ):
        command = commands.add_parser(name, help=COMMAND_HELP[name], description=COMMAND_HELP[name])
        command.set_defaults(transient=False)
        if name in TRANSIENT_COMMANDS:
            command.add_argument(
                "--transient",
                action="store_true",
                help="Use session-only configuration instead of the persistent default",
            )
        elif name in PERSISTENT_ONLY_COMMANDS:
            command.add_argument(
                "--transient",
                action="store_true",
                help="Unsupported compatibility option; this operation is persistent-only",
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
        if name == "operational-preflight":
            command.add_argument(
                "--mode",
                required=True,
                choices=("namespace", "host-default"),
                help="Supported production operating mode to inspect",
            )
            command.add_argument("--host-plan", help="Host protection plan JSON required by host-default mode")
        if name == "apply-live":
            command.add_argument("--config", required=True, help="Pinned persistent startup configuration JSON")
            command.add_argument(
                "--execute", action="store_true", help="Create verified-absent profiles; default is read-only"
            )
        if name == "replacement-readiness":
            command.add_argument("--config", required=True, help="Pinned persistent startup configuration JSON")
            command.add_argument("--profile", required=True, help="Effective kernel profile identity")
            command.add_argument("--runtime-consumers", required=True, help="Existing durable consumer lease store")
        if name in ("replace-profile", "replacement-status", "retire-generation", "recover-generation"):
            command.add_argument("--config", required=True, help="Pinned persistent startup configuration JSON")
            command.add_argument("--profile", required=True, help="Logical VPN profile")
            command.add_argument("--runtime-consumers", required=True, help="Durable generation-specific lease store")
            command.add_argument("--allocation-key", help="Logical allocation key (defaults to shared profile key)")
        if name == "replace-profile":
            command.add_argument("--old-generation", required=True, help="Current generation identity")
            command.add_argument("--replacement-generation", required=True, help="New unique generation identity")
            command.add_argument("--execute", action="store_true", help="Provision, verify and activate replacement")
        if name == "retire-generation":
            command.add_argument("--generation", required=True, help="Exact old generation to retire")
            command.add_argument("--execute", action="store_true", help="Retire verified unreferenced resources")
        if name == "recover-generation":
            command.add_argument("--execute", action="store_true", help="Perform only evidence-certified recovery")
            command.add_argument(
                "--reprovision-absent",
                action="store_true",
                help="With --execute, explicitly permit verified-absent replacement reprovisioning",
            )
        if name == "reconcile-live":
            command.add_argument("--journal", required=True, help="Explicit lifecycle journal JSON")
            command.add_argument("--bindings", required=True, help="Explicit owner-record store JSON")
            command.add_argument(
                "--intents", help="Optional operation intent store JSON (unresolved intents block verification)"
            )
            command.add_argument("--graph", help="Optional profile dependency graph JSON")
        if name == "recovery":
            command.add_argument("--journal", required=True, help="Explicit lifecycle journal JSON")
            command.add_argument("--bindings", required=True, help="Explicit owner-record store JSON")
            command.add_argument(
                "--intents",
                required=True,
                help="Operation intent store JSON (recovery exists for exactly that evidence)",
            )
            command.add_argument(
                "--resolvers",
                action="store_true",
                help="Also remove namespace resolver directories under /etc/netns during rollback retirement",
            )
            command.add_argument(
                "--execute", action="store_true", help="Resolve what the evidence certifies; the default only plans"
            )
        if name == "cleanup":
            command.add_argument("--journal", required=True, help="Explicit lifecycle journal JSON")
            command.add_argument("--bindings", required=True, help="Explicit owner-record store JSON")
            command.add_argument(
                "--intents",
                help="Operation intent store JSON (required for --execute so uncertain attempts stay visible)",
            )
            command.add_argument("--graph", help="Optional profile dependency graph JSON")
            command.add_argument(
                "--resolvers",
                action="store_true",
                help="Also remove namespace resolver directories under /etc/netns for verified namespaces",
            )
            command.add_argument(
                "--execute", action="store_true", help="Perform deletions; the default invocation only plans"
            )
        if name == "clear-ownership":
            command.add_argument("--config", required=True, help="Startup configuration JSON pinning every store")
            command.add_argument("--graph", help="Optional profile dependency graph JSON")
            command.add_argument(
                "--resolvers",
                action="store_true",
                help="Also remove namespace resolver directories under /etc/netns for verified namespaces",
            )
            command.add_argument(
                "--execute",
                action="store_true",
                help="Full teardown plus store archive and reset; the default only plans",
            )
        if name in ("startup-plan", "startup-install", "restore-startup", "provision", "retire-consumers"):
            command.add_argument("--config", required=True, help="Explicit startup configuration JSON")
        if name == "provider-import":
            command.add_argument("--configuration", required=True, help="Private NordVPN WireGuard configuration")
            command.add_argument("--server", required=True, help="Canonical NordVPN server identity")
            command.add_argument("--catalogue", required=True, help="Absolute provider catalogue path")
            command.add_argument("--credential", required=True, help="Absolute private-key destination")
            command.add_argument("--rotate", action="store_true", help="Authorise replacement of this server key")
            command.add_argument("--execute", action="store_true", help="Write the key and catalogue; default previews")
        if name == "provision":
            command.add_argument(
                "--execute",
                action="store_true",
                help="Run production restoration; without this flag no kernel mutation occurs",
            )
        if name in ("consumer-leases", "release-exited-consumer", "acquire-consumer", "launch-consumer"):
            command.add_argument("--config", required=True, help="Startup configuration pinning the registered policy")
            command.add_argument(
                "--runtime-consumers", required=True, help="Durable process-bound consumer lease store"
            )
        if name == "acquire-consumer":
            command.add_argument("--consumer", required=True, help="Registered application to bind")
            command.add_argument("--pid", required=True, type=int, help="Existing process ID to verify")
            command.add_argument(
                "--execute", action="store_true", help="Verify provisioned resources and acquire the lease"
            )
        if name == "launch-consumer":
            command.add_argument("--consumer", required=True, help="Registered application to execute")
            command.add_argument("--uid", required=True, type=int, help="Non-root application user ID")
            command.add_argument("--gid", required=True, type=int, help="Non-root application group ID")
            command.add_argument(
                "--desktop-session",
                action="store_true",
                help="Forward a validated Wayland/X11 and user D-Bus session environment",
            )
            command.add_argument(
                "--execute", action="store_true", help="Launch after verified namespace and lease reservation"
            )
            command.add_argument("arguments", nargs="*", help="Application arguments (no shell expansion)")
        if name == "release-exited-consumer":
            command.add_argument("--consumer", required=True, help="Registered consumer whose process has exited")
            command.add_argument(
                "--execute", action="store_true", help="Verify exit and release the lease; default is read-only"
            )
        if name == "retire-consumers":
            command.add_argument(
                "--consumer", action="append", required=True, help="Registered consumer to release (repeatable)"
            )
            command.add_argument(
                "--runtime-consumers", required=True, help="Durable process-bound consumer lease store"
            )
            command.add_argument("--consumer-references", help="Optional persisted declared consumer reference store")
            command.add_argument(
                "--resolvers", action="store_true", help="Retire verified namespace resolver directories"
            )
            command.add_argument(
                "--execute", action="store_true", help="Retire verified allocations; default is read-only"
            )
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
        if name in (
            "host-plan",
            "host-status",
            "host-activate",
            "host-deactivate",
            "host-recovery",
            "host-boot-barrier",
            "host-startup-plan",
            "host-startup-install",
        ):
            command.add_argument("--host-plan", required=True, help="Version 1 executable host protection plan JSON")
            command.add_argument("--host-store", required=True, help="Durable host protection transaction store")
        if name == "host-activate":
            command.add_argument("--private-key", required=True, help="Root-readable WireGuard private-key file")
            command.add_argument("--execute", action="store_true", help="Install and verify host protection")
        if name == "host-deactivate":
            command.add_argument("--execute", action="store_true", help="Retire verified host protection objects")
            command.add_argument(
                "--expose-host-egress",
                action="store_true",
                help="Confirm removal of the final deny barrier and restoration of ordinary host egress",
            )
        if name == "host-recovery":
            command.add_argument("--execute", action="store_true", help="Persist only evidence-certified recovery")
        if name in ("host-startup-plan", "host-startup-install"):
            command.add_argument("--private-key", required=True, help="Root-readable WireGuard private-key file")
            command.add_argument("--unit-dir", default="/etc/systemd/system", help="Existing systemd unit directory")
            command.add_argument("--python", default="/usr/bin/python3", help="Absolute Python interpreter path")
        if name == "host-startup-install":
            command.add_argument("--execute", action="store_true", help="Install both generated systemd units")
    args = parser.parse_args(argv)
    try:
        if args.action in (
            "host-plan",
            "host-status",
            "host-activate",
            "host-deactivate",
            "host-recovery",
            "host-boot-barrier",
            "host-startup-plan",
            "host-startup-install",
        ):
            if args.transient:
                raise ManagementError("host protection is persistent-only")
            from nord_tools_internal.nordvpn_host_executor import (
                activate_host_protection,
                deactivate_host_protection,
                host_protection_status,
                prepare_host_boot_barrier,
                preview_host_protection,
                recover_host_protection,
            )
            from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan

            host_plan = HostProtectionPlan.from_mapping(read_json(args.host_plan))
            if args.action in ("host-startup-plan", "host-startup-install"):
                from nord_tools_internal.nordvpn_host_startup import install_host_startup

                result = install_host_startup(
                    host_plan,
                    plan_path=args.host_plan,
                    store_path=args.host_store,
                    private_key_path=args.private_key,
                    unit_dir=args.unit_dir,
                    python_executable=args.python,
                    execute=args.action == "host-startup-install" and args.execute,
                )
            elif args.action == "host-boot-barrier":
                result = prepare_host_boot_barrier(host_plan, args.host_store)
            elif args.action == "host-plan" or (args.action == "host-activate" and not args.execute):
                result = preview_host_protection(host_plan)
                result["host_store"] = args.host_store
            elif args.action == "host-status":
                result = host_protection_status(host_plan, args.host_store)
            elif args.action == "host-recovery":
                result = recover_host_protection(
                    host_plan,
                    args.host_store,
                    execute=args.execute,
                )
            elif args.action == "host-deactivate":
                if not args.execute:
                    result = host_protection_status(host_plan, args.host_store)
                    result["mode"] = "host_default_deactivation_preview"
                    result["retirement_order"] = [
                        "resolver",
                        "routes",
                        "wireguard",
                        "endpoint exception",
                        "deny barrier",
                    ]
                    result["requires_expose_host_egress_confirmation"] = True
                else:
                    result = deactivate_host_protection(
                        host_plan,
                        args.host_store,
                        expose_host_egress=args.expose_host_egress,
                    )
            else:
                key_fd = os.open(args.private_key, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    result = activate_host_protection(host_plan, args.host_store, key_fd)
                finally:
                    os.close(key_fd)
            result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
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
        if args.action == "operational-preflight":
            from nord_tools_internal.nordvpn_operational_preflight import verify_operational_preflight

            if args.mode == "host-default":
                if not args.host_plan:
                    raise ManagementError("host-default operational preflight requires --host-plan")
                from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan

                host_plan = HostProtectionPlan.from_mapping(read_json(args.host_plan))
            else:
                if args.host_plan:
                    raise ManagementError("--host-plan is valid only for host-default operational preflight")
                host_plan = None
            result = verify_operational_preflight(args.mode, host_plan=host_plan)
            result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "apply-live":
            if args.transient:
                raise ManagementError("live apply is persistent-only")
            from nord_tools_internal.nordvpn_live_apply import apply_live_state

            result = apply_live_state(read_json(args.config), execute=args.execute)
            result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "replacement-readiness":
            if args.transient:
                raise ManagementError("replacement readiness is persistent-only")
            from nord_tools_internal.nordvpn_replacement_readiness import assess_replacement_readiness

            result = assess_replacement_readiness(read_json(args.config), args.profile, args.runtime_consumers)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action in ("replace-profile", "replacement-status", "retire-generation", "recover-generation"):
            if args.transient:
                raise ManagementError("generation replacement is persistent-only")
            config = validate_startup_config(read_json(args.config))
            allocation_key = args.allocation_key or f"profile:{args.profile}"
            handover = config.get("handovers", {}).get(allocation_key) or config.get("handovers", {}).get(args.profile)
            if handover is None:
                raise ManagementError("profile has no pinned generation handover store")
            if args.action == "recover-generation":
                if args.reprovision_absent and not args.execute:
                    raise ManagementError("--reprovision-absent requires --execute")
                from nord_tools_internal.nordvpn_generation_recovery import recover_generation

                result = recover_generation(
                    config,
                    handover_path=handover,
                    runtime_consumers_path=args.runtime_consumers,
                    observe=discover,
                    execute=args.execute,
                    allow_reprovision=args.reprovision_absent,
                    expected_profile=args.profile,
                    expected_allocation_key=allocation_key,
                )
            elif args.action == "replacement-status":
                from nord_tools_internal.nordvpn_replacement_executor import replacement_status

                result = replacement_status(
                    config,
                    handover_path=handover,
                    runtime_consumers_path=args.runtime_consumers,
                    observe=discover,
                )
            elif args.action == "replace-profile":
                if not args.execute:
                    from nord_tools_internal.nordvpn_replacement_readiness import assess_replacement_readiness

                    result = assess_replacement_readiness(config, args.profile, args.runtime_consumers)
                    result["intent_only"] = True
                else:
                    from nord_tools_internal.nordvpn_replacement_executor import (
                        activate_replacement,
                        prepare_replacement,
                    )

                    prepared = prepare_replacement(
                        config,
                        profile=args.profile,
                        allocation_key=allocation_key,
                        old_generation_id=args.old_generation,
                        replacement_generation_id=args.replacement_generation,
                        handover_path=handover,
                        runtime_consumers_path=args.runtime_consumers,
                        observe=discover,
                    )
                    if prepared["phase"] in {"active", "draining"}:
                        result = prepared
                    else:
                        result = activate_replacement(
                            config,
                            handover_path=handover,
                            runtime_consumers_path=args.runtime_consumers,
                            observe=discover,
                        )
            else:
                from nord_tools_internal.nordvpn_replacement_executor import retire_old_generation

                result = retire_old_generation(
                    config,
                    handover_path=handover,
                    runtime_consumers_path=args.runtime_consumers,
                    observe=discover,
                    execute=args.execute,
                    expected_generation_id=args.generation,
                )
            result["scope"] = "persistent"
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
        if args.action == "recovery":
            if args.transient:
                raise ManagementError("recovery is persistent-only; transient intent has never owned anything")
            result = plan_recovery(
                args.journal,
                args.bindings,
                args.intents,
                resolvers=args.resolvers,
                execute=args.execute,
            )
            result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "provision":
            if args.transient:
                raise ManagementError("production provisioning is persistent-only")
            config = validate_startup_config(read_json(args.config))
            if not args.execute:
                result = {
                    "scope": "persistent",
                    "action": "provision",
                    "execute": False,
                    "intent_only": True,
                    "configuration": args.config,
                    "profiles": sorted(config["tunnels"]),
                    "message": "Preview only; no kernel state or ownership was inspected",
                }
            else:
                result = restore_boot_state(config)
                result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "launch-consumer":
            if args.transient:
                raise ManagementError("application launch is persistent-only")
            config = validate_startup_config(read_json(args.config))
            policy = validate_policy(read_json(config["policy"]))
            from nord_tools_internal.nordvpn_application_plan import plan_application

            plan = plan_application(policy, args.consumer, tuple(args.arguments))
            if not args.execute:
                print(
                    json.dumps(
                        {
                            "action": "launch-consumer",
                            "execute": False,
                            "intent_only": True,
                            "application": plan.application,
                            "profile": plan.profile,
                            "allocation_key": plan.allocation_key,
                            "argv": [plan.executable, *plan.arguments],
                            "routing_mode": "host" if plan.profile == "direct" else "vpn",
                            "host_vpn_may_apply": plan.profile == "direct",
                            "desktop_session": args.desktop_session,
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 0
            if plan.profile == "direct":
                from nord_tools_internal.nordvpn_application_executor import launch_direct_application

                return launch_direct_application(
                    policy,
                    args.consumer,
                    tuple(args.arguments),
                    uid=args.uid,
                    gid=args.gid,
                    desktop_session=args.desktop_session,
                )
            if not config["intent"]:
                raise ManagementError("application launch requires a pinned operation intent store")
            from nord_tools_internal.nordvpn_application_executor import launch_provisioned_application

            return launch_provisioned_application(
                policy,
                args.consumer,
                tuple(args.arguments),
                runtime_consumers=args.runtime_consumers,
                journal_path=config["journal"],
                bindings_path=config["bindings"],
                intent_path=config["intent"],
                observe=discover,
                uid=args.uid,
                gid=args.gid,
                desktop_session=args.desktop_session,
                handover_path=config.get("handovers", {}).get(plan.allocation_key)
                or config.get("handovers", {}).get(plan.profile),
                tunnel_plan=config["tunnels"].get(plan.profile),
            )
        if args.action in ("consumer-leases", "release-exited-consumer", "acquire-consumer"):
            if args.transient:
                raise ManagementError("runtime consumer management is persistent-only")
            config = validate_startup_config(read_json(args.config))
            policy = validate_policy(read_json(config["policy"]))
            from nord_tools_internal.nordvpn_runtime_consumers import (
                read_runtime_consumers,
                release_exited_consumer,
            )

            if args.action == "acquire-consumer":
                if args.consumer not in policy["applications"]:
                    raise ManagementError("consumer is not registered")
                if args.pid <= 0:
                    raise ManagementError("process ID must be positive")
                if not args.execute:
                    result = {
                        "scope": "persistent",
                        "action": "acquire-consumer",
                        "execute": False,
                        "consumer": args.consumer,
                        "pid": args.pid,
                        "intent_only": True,
                        "message": "Preview only; process and kernel ownership have not been verified",
                    }
                else:
                    if not config["intent"]:
                        raise ManagementError("consumer acquisition requires a pinned operation intent store")
                    from nord_tools_internal.nordvpn_runtime_consumers import acquire_provisioned_consumer

                    updated = acquire_provisioned_consumer(
                        args.runtime_consumers,
                        policy,
                        args.consumer,
                        args.pid,
                        journal_path=config["journal"],
                        bindings_path=config["bindings"],
                        intent_path=config["intent"],
                        observe=discover,
                    )
                    result = {
                        "scope": "persistent",
                        "action": "acquire-consumer",
                        "execute": True,
                        "consumer": args.consumer,
                        "pid": args.pid,
                        "lease_count": len(updated["leases"]),
                    }
            elif args.action == "consumer-leases":
                result = read_runtime_consumers(args.runtime_consumers, policy)
                result = {
                    "scope": "persistent",
                    "action": "consumer-leases",
                    "execute": False,
                    "leases": result["leases"],
                    "policy_sha256": result["policy_sha256"],
                }
            else:
                if args.consumer not in policy["applications"]:
                    raise ManagementError("consumer is not registered")
                current = read_runtime_consumers(args.runtime_consumers, policy)
                matching = [lease for lease in current["leases"] if lease["application"] == args.consumer]
                if len(matching) != 1:
                    raise ManagementError("consumer has no recorded runtime lease")
                if args.execute:
                    updated = release_exited_consumer(args.runtime_consumers, policy, args.consumer)
                    result = {
                        "scope": "persistent",
                        "action": "release-exited-consumer",
                        "execute": True,
                        "consumer": args.consumer,
                        "remaining_leases": len(updated["leases"]),
                    }
                else:
                    result = {
                        "scope": "persistent",
                        "action": "release-exited-consumer",
                        "execute": False,
                        "consumer": args.consumer,
                        "intent_only": True,
                        "message": "Preview only; process exit has not been verified",
                    }
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "retire-consumers":
            if args.transient:
                raise ManagementError("consumer retirement is persistent-only")
            config = validate_startup_config(read_json(args.config))
            policy = validate_policy(read_json(config["policy"]))
            from nord_tools_internal.nordvpn_application_plan import plan_application
            from nord_tools_internal.nordvpn_allocation_profiles import kernel_profile_for_allocation

            released = tuple(args.consumer)
            if len(set(released)) != len(released):
                raise ManagementError("consumer names must not be repeated")
            allocations = [plan_application(policy, name) for name in released]
            selected = tuple(
                sorted(
                    {
                        kernel_profile_for_allocation(item.allocation_key, item.profile, item.sharing)
                        for item in allocations
                    }
                )
            )
            if not config["intent"]:
                raise ManagementError("consumer retirement requires a pinned operation intent store")
            result = plan_cleanup(
                config["journal"],
                config["bindings"],
                intent_path=config["intent"],
                graph_path=config["graph"],
                desired_policy=None,
                selected_profiles=selected,
                consumer_policy=policy,
                released_consumers=released,
                runtime_consumers_path=args.runtime_consumers,
                consumer_references_path=args.consumer_references,
                resolvers=args.resolvers,
                execute=args.execute,
            )
            result["scope"] = "persistent"
            result["selected_profiles"] = list(selected)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "cleanup":
            if args.transient:
                raise ManagementError("cleanup is persistent-only; transient intent has never owned anything")
            persistent = _read(state_path(True))
            if persistent is None:
                raise ManagementError(
                    "cleanup requires a saved persistent policy to decide preservation; configure one first"
                )
            result = plan_cleanup(
                args.journal,
                args.bindings,
                intent_path=args.intents,
                graph_path=args.graph,
                desired_policy=persistent,
                resolvers=args.resolvers,
                execute=args.execute,
            )
            result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "clear-ownership":
            if args.transient:
                raise ManagementError("clear-ownership is persistent-only; transient intent has never owned anything")
            result = reset_ownership(
                read_json(args.config), graph_path=args.graph, resolvers=args.resolvers, execute=args.execute
            )
            result["scope"] = "persistent"
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.action == "provider-import":
            if args.transient:
                raise ManagementError("provider import is persistent-only")
            result = import_provider_configuration(
                read_provider_configuration(args.configuration),
                server=args.server,
                catalogue_path=args.catalogue,
                credential_path=args.credential,
                rotate=args.rotate,
                execute=args.execute,
            )
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
        ConsumerReferenceError,
        ProfileError,
        ReconciliationError,
        RegistryError,
        DiscoveryError,
        OwnershipError,
        ProvisioningUncertainError,
        UnderlayError,
        HostProtectionError,
        ValueError,
        OSError,
    ) as exc:
        print(f"manage: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
