#!/usr/bin/env python3
"""Integrated Part 7 acceptance: persistence, recovery, cleanup, convergence.

The dry run describes every stage without touching any store or the kernel. The
privileged run executes the full operational workflow on a disposable-capable
Linux test host: two pinned profiles restore while a deliberately different
transient policy exists and provably influences nothing; a real process death
mid-restore is converged through boot and operator recovery; one authored
profile is cleaned out while the shared profile and its generation survive
untouched; repeated operations converge without kernel changes; and the host's
IPv4/IPv6 routes, nftables rules and resolver contents are compared across every
stage boundary.
"""

from __future__ import annotations

import argparse
import ipaddress
import contextlib
import io
import json
import os
import shutil
import subprocess
import signal
import sys
import tempfile
import select
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nordvpn_manage


class ProbeError(RuntimeError):
    """The integrated acceptance matrix cannot complete safely."""


def _observe() -> dict:
    """Read-only host snapshot: routes, nftables rules and resolver contents."""
    observation = {}
    commands = {
        "ipv4_routes": ["ip", "-j", "route", "show"],
        "ipv6_routes": ["ip", "-j", "-6", "route", "show"],
        "nftables": ["nft", "-j", "list", "ruleset"],
    }
    for name, argv in commands.items():
        result = subprocess.run(argv, capture_output=True, check=False, timeout=15)
        if result.returncode:
            raise ProbeError(f"the host snapshot could not read {name}: is nftables available?")
        observation[name] = result.stdout
    resolver = Path("/etc/resolv.conf")
    observation["resolver"] = resolver.read_text(encoding="utf-8", errors="replace")
    return observation


def _expected_underlay_routes(matrix: Matrix) -> dict[tuple[str, str, str, str | None], bool]:
    """Map verified host underlay interfaces to their exact fixture routes.

    Never exempt a route on the strength of its interface name alone.
    """
    if not matrix.bindings.exists():
        return {}
    bindings = json.loads(matrix.bindings.read_text(encoding="utf-8"))
    config = json.loads((matrix.temporary / "startup.json").read_text(encoding="utf-8"))
    expected = {}
    for tunnel in config["tunnels"].values():
        address = ipaddress.ip_interface(tunnel["underlay"]["host_address"])
        expected[str(address.network)] = str(address.ip)
    result = {}
    for entry in bindings["bindings"]:
        if entry["kind"] != "interface" or entry["binding"].get("scope") != "host":
            continue
        # A binding alone does not authorise a route exception: the live
        # interface index must still agree with the recorded creation identity.
        name = entry["identifier"]
        observed = subprocess.run(
            ["ip", "-j", "link", "show", "dev", name], capture_output=True, check=False, timeout=15
        )
        if observed.returncode:
            continue
        links = json.loads(observed.stdout)
        if len(links) != 1 or links[0]["ifindex"] != entry["binding"]["ifindex"]:
            continue
        for prefix, source in expected.items():
            result[("ipv4", name, prefix, source)] = True
        # Linux automatically installs this route when IPv6 link-local
        # addressing is enabled on the newly created veth.  It is as much a
        # fixture route as the configured IPv4 underlay route, but exempt it
        # only after the live interface has matched its recorded ifindex.
        result[("ipv6", name, "fe80::/64", None)] = True
    return result


def _normalised_routes(raw: bytes, allowed: dict, family: str) -> list[dict]:
    """Exclude fixture routes and normalise only volatile route lifetimes."""
    routes = json.loads(raw)
    result = []
    for route in routes:
        key = (family, route.get("dev"), route.get("dst"), route.get("prefsrc"))
        common_fixture_route = (
            key in allowed
            and route.get("protocol") == "kernel"
            and route.get("type", "unicast") == "unicast"
            and route.get("gateway") is None
            and route.get("table", "main") == "main"
        )
        ipv4_underlay = family == "ipv4" and route.get("scope") == "link"
        ipv6_link_local = (
            family == "ipv6"
            and route.get("dst") == "fe80::/64"
            and route.get("prefsrc") is None
            and route.get("metric") == 256
            and route.get("scope") in (None, "link")
        )
        if common_fixture_route and (ipv4_underlay or ipv6_link_local):
            continue
        # Router-advertisement lifetimes count down independently of this
        # experiment.  Preserve the presence of the lifetime field, while
        # ignoring only its live numeric reading.
        if "expires" in route:
            route = {**route, "expires": 0}
        result.append(route)
    return result


def _normalised_nftables(raw: bytes) -> dict:
    """Compare firewall configuration, not live packet/byte counter readings.

    Retain counter expressions and all other fields, including rule order,
    handles, policies, matches, verdicts and named counter objects.
    """
    document = json.loads(raw)
    if not isinstance(document, dict) or not isinstance(document.get("nftables"), list):
        raise ProbeError("the host nftables snapshot has an invalid JSON structure")

    def normalise(value):
        if isinstance(value, list):
            return [normalise(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if key == "counter" and isinstance(child, dict) and {"packets", "bytes"} <= child.keys():
                    result[key] = {
                        field: (0 if field in {"packets", "bytes"} else normalise(content))
                        for field, content in child.items()
                    }
                else:
                    result[key] = normalise(child)
            return result
        return value

    return normalise(document)


def _assert_no_host_drift(before_name: str, after_name: str, before: dict, after: dict, allowed: dict) -> None:
    for label in before:
        if label not in after:
            raise ProbeError(f"the host snapshot is missing {label} at {after_name}")
        old, new = before[label], after[label]
        if label in {"ipv4_routes", "ipv6_routes"}:
            family = label.removesuffix("_routes")
            old = _normalised_routes(old, allowed, family)
            new = _normalised_routes(new, allowed, family)
        elif label == "nftables":
            old = _normalised_nftables(old)
            new = _normalised_nftables(new)
        if old != new:
            raise ProbeError(
                f"the host's {label} changed from {before_name} to {after_name}; inspect retained snapshots"
            )


def interrupted_evidence(root: Path) -> list[str]:
    findings = []
    intents = json.loads((root / "operation-intents.json").read_text(encoding="utf-8"))
    for operation in intents["operations"]:
        if operation["outcome"] in {"pending", "uncertain"}:
            findings.append(f"operation {operation['operation_id']}: {operation['outcome']}")
    journal = json.loads((root / "lifecycle.json").read_text(encoding="utf-8"))
    states = {}
    for event in journal["events"]:
        states[event["allocation_id"]] = event["state"]
    if any(state not in {"active", "retired"} for state in states.values()):
        findings.append("interrupted lifecycle states present")
    return findings


def _active_namespaces_by_profile(journal_path: Path) -> dict[str, str]:
    """Return only this matrix's currently active namespace allocations."""
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    states = {event["allocation_id"]: event["state"] for event in journal["events"]}
    active = {}
    for resource in journal["allocations"]["resources"]:
        if resource["kind"] != "namespace" or states.get(resource["allocation_id"]) != "active":
            continue
        profile = resource["profile"]
        if profile in active:
            raise ProbeError(f"profile {profile} has multiple active namespace allocations")
        active[profile] = resource["identifier"]
    return active


def _retain_startup_profiles(config_path: Path, profiles: set[str]) -> None:
    """Keep the startup provider data aligned with the reduced saved policy."""
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["tunnels"] = {name: plan for name, plan in config["tunnels"].items() if name in profiles}
    config["credentials"] = {name: path for name, path in config["credentials"].items() if name in profiles}
    config_path.write_text(json.dumps(config), encoding="utf-8")


class Matrix:
    """One integrated acceptance run; helpers keep the stage order readable."""

    def __init__(self, temporary: Path):
        self.temporary = temporary
        self.config_home = temporary / "config"
        (self.config_home / "nord-tools").mkdir(mode=0o700, parents=True)
        os.environ["XDG_CONFIG_HOME"] = str(self.config_home)
        os.environ.pop("XDG_RUNTIME_DIR", None)
        self.policy = self.config_home / "nord-tools" / "desired-policy.json"
        self.transient_policy = self.config_home.parent / "runtime" / "nord-tools" / "desired-policy.json"
        self.journal = temporary / "lifecycle.json"
        self.bindings = temporary / "owner-bindings.json"
        self.intents = temporary / "operation-intents.json"
        self.run_record = temporary / "startup-runs.json"
        self.previous_snapshot = _observe()
        self.previous_underlay_routes = {}
        self.report: dict[str, dict] = {}

    def write_policy(self, profiles: dict[str, dict], applications: dict = None, *, default: str = "primary") -> None:
        if applications is None:
            applications = {}
        self.policy.write_text(
            json.dumps(
                {"version": 1, "defaults": {"vpn": default}, "vpn_profiles": profiles, "applications": applications}
            ),
            encoding="utf-8",
        )

    def call(self, *args: str) -> dict:
        buffer = io.StringIO()
        error = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(error):
            code = nordvpn_manage.main([*args])
        if code != 0:
            detail = error.getvalue().strip()
            suffix = f": {detail[:500]}" if detail else ""
            raise ProbeError(f"the {' '.join(args)} invocation reported failure{suffix}")
        return json.loads(buffer.getvalue())

    def cleanup_args(self, execute: bool = False) -> list[str]:
        arguments = [
            "cleanup",
            "--journal",
            str(self.journal),
            "--bindings",
            str(self.bindings),
            "--intents",
            str(self.intents),
        ]
        return arguments + (["--execute"] if execute else [])

    def recovery_args(self, execute: bool = False) -> list[str]:
        arguments = [
            "recovery",
            "--journal",
            str(self.journal),
            "--bindings",
            str(self.bindings),
            "--intents",
            str(self.intents),
        ]
        return arguments + (["--execute"] if execute else [])

    def reconcile(self) -> dict:
        return self.call("reconcile-live", "--journal", str(self.journal), "--bindings", str(self.bindings))

    def interrupt_at_durable_intent(self) -> None:
        """Kill a child only after a durable pending intent, before kernel creation."""
        read_fd, write_fd = os.pipe()
        child = None
        try:
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parent / "probe_recovery.py"),
                    "--checkpoint-child",
                    str(self.temporary / "startup.json"),
                    str(write_fd),
                ],
                cwd=str(Path(__file__).resolve().parent.parent),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                pass_fds=(write_fd,),
                start_new_session=True,
            )
            os.close(write_fd)
            write_fd = -1
            ready, _, _ = select.select([read_fd], [], [], 30)
            if not ready or os.read(read_fd, 1) != b"R":
                raise ProbeError("restore child did not reach the durable creation-intent checkpoint")
            if not interrupted_evidence(self.temporary):
                raise ProbeError("checkpoint was reached without durable interrupted evidence")
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
            if child is not None:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=30)
        if not interrupted_evidence(self.temporary):
            raise ProbeError("the terminated child left no pending intent")

    def restore(self) -> dict:
        buffer = io.StringIO()
        error = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(error):
            code = nordvpn_manage.main(["restore-startup", "--config", str(self.temporary / "startup.json")])
        if code != 0:
            raise ProbeError(f"the restoration reported failure: {error.getvalue().strip()[:300]}")
        return json.loads(buffer.getvalue())


def stage_persistence(matrix: Matrix) -> None:
    """Two pinned profiles restore; a deliberately different transient policy is inert."""
    matrix.transient_policy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    matrix.transient_policy.write_text(
        json.dumps(
            {
                "version": 1,
                "defaults": {"vpn": "elsewhere"},
                "vpn_profiles": {
                    "elsewhere": {"selection": {"mode": "pinned", "server": "us1234"}, "sharing": "shared"}
                },
                "applications": {},
            }
        ),
        encoding="utf-8",
    )
    report = matrix.restore()
    if sorted(report["restored"]) != ["other", "primary"]:
        raise ProbeError(f"the pinned profiles did not both converge: {report['restored']}")
    if not report["reconciled"]:
        raise ProbeError(f"the first convergence failed: {report['blocked']}")
    with_transient = matrix.reconcile()
    matrix.transient_policy.unlink()
    without_transient = matrix.reconcile()
    if with_transient["decisions"] != without_transient["decisions"]:
        raise ProbeError("removing the transient policy changed the persistent reconciliation")
    print("PASS A: both pinned profiles restored; the transient policy influenced nothing", flush=True)


def stage_recovery(matrix: Matrix) -> None:
    """Create a real missing generation, then interrupt its recreation at a durable boundary."""
    # A repeat restore of two already-active profiles is a no-op. Earlier
    # random-delay SIGKILL attempts could never guarantee an in-flight write.
    # Retire only the other profile through the ordinary verified cleanup,
    # preserving the primary profile and its application bindings.
    policy = json.loads(matrix.policy.read_text(encoding="utf-8"))
    reduced = {**policy, "vpn_profiles": {"primary": policy["vpn_profiles"]["primary"]}}
    matrix.policy.write_text(json.dumps(reduced), encoding="utf-8")
    matrix.call(*matrix.cleanup_args(execute=True))
    remaining = matrix.reconcile()
    if not remaining["reconciled"]:
        raise ProbeError("the primary profile did not survive recovery fixture retirement")
    matrix.policy.write_text(json.dumps(policy), encoding="utf-8")

    matrix.interrupt_at_durable_intent()
    print("  PASS: durable pending creation intent observed before SIGKILL", flush=True)
    recovered = False
    failures = []
    for _ in range(4):
        try:
            matrix.restore()
            recovered = True
            break
        except ProbeError as exc:
            failures.append(str(exc))
            try:
                matrix.call(*matrix.recovery_args(execute=True))
            except ProbeError as exc:
                failures.append(str(exc))
                break
    if not recovered:
        detail = "; ".join(failures[-2:])
        raise ProbeError(f"the recovery stage did not converge the interrupted stores: {detail}")
    report = matrix.reconcile()
    if not report["reconciled"]:
        raise ProbeError("recovery did not reach the pinned desired state")
    print("PASS B: deterministic interrupted generation recovered; both profiles converge", flush=True)


def stage_cleanup(matrix: Matrix) -> None:
    """Authorised cleanup; the shared profile and its application stay intact."""
    # One application is removed: pure bookkeeping, with reconciliation intact.
    matrix.write_policy(
        {
            "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"},
            "other": {"selection": {"mode": "pinned", "server": "us1234"}, "sharing": "shared"},
        },
        {"app-b": {"executable": "/usr/bin/app-b", "vpn": "primary"}},
    )
    reconciled = matrix.reconcile()
    if not reconciled["reconciled"]:
        raise ProbeError("removing one application reference disturbed reconciliation")
    active_before = _active_namespaces_by_profile(matrix.journal)
    if set(active_before) != {"primary", "other"}:
        raise ProbeError(f"cleanup fixture does not have exactly both active profiles: {sorted(active_before)}")
    # The other profile leaves the retained scope; cleanup retires it only.
    matrix.write_policy(
        {
            "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"},
        },
        {"app-b": {"executable": "/usr/bin/app-b", "vpn": "primary"}},
    )
    matrix.call(*matrix.cleanup_args(execute=True))
    _retain_startup_profiles(matrix.temporary / "startup.json", {"primary"})
    listing = subprocess.run(["ip", "-j", "netns", "list"], capture_output=True, check=False, timeout=15)
    if listing.returncode:
        raise ProbeError("the namespace listing could not complete")
    survived = {namespace.get("name") for namespace in json.loads(listing.stdout.decode("utf-8"))}
    if active_before["primary"] not in survived or active_before["other"] in survived:
        raise ProbeError(
            "cleanup did not preserve this run's shared namespace and retire its other namespace: "
            f"primary={active_before['primary']!r}, other={active_before['other']!r}, observed={sorted(survived)}"
        )
    final = matrix.reconcile()
    if not final["reconciled"]:
        raise ProbeError("the shared profile no longer converges after the authorised cleanup")
    print("PASS C: confirmed cleanup retired only the verified owned resources", flush=True)


def stage_convergence(matrix: Matrix) -> None:
    """Repeated operations converge without kernel changes."""
    first = matrix.reconcile()
    second = matrix.reconcile()
    if first["decisions"] != second["decisions"]:
        raise ProbeError("the reconciliation decisions moved between repeat runs")
    plan = matrix.call(*matrix.cleanup_args())
    if plan["plan"]:
        raise ProbeError("the cleanup plan is not empty after convergence")
    recovery = matrix.call(*matrix.recovery_args())
    if recovery["items"]:
        raise ProbeError("recovery still reports unresolved items after convergence")
    restored = matrix.restore()
    if restored["network_changes_applied"]:
        raise ProbeError("a converged repeat restoration mutated the kernel again")
    print("PASS D: repeat operations converge without further kernel changes", flush=True)


def stage_final_teardown(matrix: Matrix) -> None:
    """Retire the surviving fixture before its ownership evidence is removed."""
    active_before = _active_namespaces_by_profile(matrix.journal)
    if set(active_before) != {"primary"}:
        raise ProbeError(f"final teardown expected only the primary fixture: {sorted(active_before)}")
    matrix.write_policy(
        {"teardown": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
        default="teardown",
    )
    matrix.call(*matrix.cleanup_args(execute=True))
    listing = subprocess.run(["ip", "-j", "netns", "list"], capture_output=True, check=False, timeout=15)
    if listing.returncode:
        raise ProbeError("the final namespace listing could not complete")
    remaining = {namespace.get("name") for namespace in json.loads(listing.stdout.decode("utf-8"))}
    if active_before["primary"] in remaining:
        raise ProbeError(f"the final fixture namespace remains: {active_before['primary']}")
    if _active_namespaces_by_profile(matrix.journal):
        raise ProbeError("the final teardown left an active fixture allocation")
    print("PASS E: final verified teardown retired the surviving fixture", flush=True)


def run_matrix() -> dict:
    """Execute the full matrix once; return the summary of what remains open."""
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg", "nft"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    temporary = Path(tempfile.mkdtemp(prefix="nt-part7-acceptance-"))
    print(f"Creating a disposable ecosystem under {temporary}; inspect /run/netns if interrupted", flush=True)
    all_findings = []
    try:
        matrix = Matrix(temporary)
        matrix.write_policy(
            {
                "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"},
                "other": {"selection": {"mode": "pinned", "server": "us1234"}, "sharing": "shared"},
            },
            {
                "app-a": {"executable": "/usr/bin/app-a", "vpn": "primary"},
                "app-b": {"executable": "/usr/bin/app-b", "vpn": "primary"},
            },
        )
        _write_startup_config(matrix)
        stage_persistence(matrix)
        _snapshot_gate(matrix, "persistence", "recovery")
        stage_recovery(matrix)
        all_findings.extend(interrupted_evidence(matrix.temporary))
        _snapshot_gate(matrix, "recovery", "cleanup")
        stage_cleanup(matrix)
        _snapshot_gate(matrix, "cleanup", "convergence")
        stage_convergence(matrix)
        stage_final_teardown(matrix)
        _snapshot_gate(matrix, "convergence", "final-cleanup")
        print("PASS F: the host routes, nftables rules and resolver contents never moved", flush=True)
        unresolved = [
            "provider credentials acquisition and fastest/country selection at boot remain operator-pinned plans",
            "the default profile's host-domain protective routing and the kill switch are not implemented",
            "real-tunnel DNS confinement, IPv6 conformance and leak prevention remain unverified",
            "live replacement cut-over with verified rollback stays administrative work",
            "adversarial ownership testing of the stores under racing privileged actors is outstanding",
            "per-application launch execution and desktop integration remain disabled",
        ]
        print("--- remaining production work after lifecycle acceptance ---", flush=True)
        for line in unresolved:
            print(f"  {line}", flush=True)
        return {"interrupted_evidence": all_findings, "unresolved": unresolved}
    except BaseException:
        print(f"Retained matrix evidence for review: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary, ignore_errors=True)


def _write_startup_config(matrix: Matrix) -> None:
    """Pin both tunnel plans; credentials are generated in the temp directory."""
    keys = {}
    for name, server in (("primary", "uk715"), ("other", "us1234")):
        result = subprocess.run(["wg", "genkey"], capture_output=True, check=False, timeout=15)
        if result.returncode:
            raise ProbeError("the WireGuard key generation failed")
        private_key = result.stdout.strip()
        peer_generated = subprocess.run(["wg", "genkey"], capture_output=True, check=False, timeout=15)
        peer_result = subprocess.run(
            ["wg", "pubkey"], input=peer_generated.stdout.strip(), capture_output=True, check=False, timeout=15
        )
        if peer_result.returncode:
            raise ProbeError("the peer public key derivation failed")
        credential = matrix.temporary / f"{name}.key"
        credential.write_bytes(private_key + b"\n")
        os.chmod(credential, 0o600)
        keys[name] = {
            "peer_public_key": peer_result.stdout.strip().decode("ascii"),
            "credential": str(credential),
        }
    matrix.temporary.joinpath("startup.json").write_text(
        json.dumps(
            {
                "version": 1,
                "policy": str(matrix.policy),
                "journal": str(matrix.journal),
                "bindings": str(matrix.bindings),
                "intent": str(matrix.intents),
                "run_record": str(matrix.run_record),
                "tunnels": {
                    name: {
                        "peer_public_key": data["peer_public_key"],
                        "endpoint_address": "198.51.100.10" if name == "primary" else "203.0.113.10",
                        "endpoint_port": 51820,
                        "tunnel_address": f"10.213.{240 + index}.2/32",
                        "peer_allowed_ips": [f"10.213.{240 + index}.1/32"],
                        "underlay": {
                            "namespace_address": f"10.214.{index}.2/30",
                            "host_address": f"10.214.{index}.1/30",
                        },
                    }
                    for index, (name, data) in enumerate(sorted(keys.items()))
                },
                "credentials": {name: data["credential"] for name, data in keys.items()},
            }
        ),
        encoding="utf-8",
    )


def _snapshot_gate(matrix: Matrix, before_name: str, after_name: str) -> None:
    fresh = _observe()
    current_underlay_routes = _expected_underlay_routes(matrix)
    snapshots = matrix.temporary / "host-snapshots"
    snapshots.mkdir(exist_ok=True)
    for name, observation in ((before_name, matrix.previous_snapshot), (after_name, fresh)):
        for label, value in observation.items():
            target = snapshots / f"{name}-{label}.json" if label != "resolver" else snapshots / f"{name}-resolver.txt"
            target.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))
    # A cleanup boundary legitimately removes an exact fixture route together
    # with its identity-bound interface.  Accept routes verified in either
    # endpoint snapshot, while continuing to compare every other host route.
    allowed_routes = {**matrix.previous_underlay_routes, **current_underlay_routes}
    _assert_no_host_drift(before_name, after_name, matrix.previous_snapshot, fresh, allowed_routes)
    matrix.previous_snapshot = fresh
    matrix.previous_underlay_routes = current_underlay_routes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise the disposable privileged matrix")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print(
            "DRY RUN: the Part 7 acceptance matrix would restore two pinned profiles while a transient policy "
            "deliberately differs, interrupt a missing generation at a durable creation-intent checkpoint, converge "
            "through boot and operator recovery, clean one profile while the shared one survives to exact "
            "deletions, repeat operations to prove convergence, and compare host routes, nftables rules and "
            "resolver contents across every stage. No changes made."
        )
        return 0
    try:
        run_matrix()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
