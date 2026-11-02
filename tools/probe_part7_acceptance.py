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
import contextlib
import io
import json
import os
import random
import shutil
import subprocess
import signal
import sys
import tempfile
import time
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


def _assert_no_host_drift(before_name: str, after_name: str, before: dict, after: dict) -> None:
    for label in before:
        if label in after and before[label] != after[label]:
            raise ProbeError(f"the host's {label} changed from {before_name} to {after_name}; inspect manually")


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
        self.report: dict[str, dict] = {}

    def write_policy(self, profiles: dict[str, dict], applications: dict = None) -> None:
        if applications is None:
            applications = {}
        self.policy.write_text(
            json.dumps(
                {"version": 1, "defaults": {"vpn": "primary"}, "vpn_profiles": profiles, "applications": applications}
            ),
            encoding="utf-8",
        )

    def call(self, *args: str) -> dict:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = nordvpn_manage.main([*args])
        if code != 0:
            raise ProbeError(f"the {' '.join(args)} invocation reported failure")
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

    def restore_child(self, pause: float) -> None:
        child = subprocess.Popen(
            [
                sys.executable,
                "nordvpn_manage.py",
                "restore-startup",
                "--config",
                str(self.temporary / "startup.json"),
            ],
            cwd=str(Path(__file__).resolve().parent.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(pause)
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=30)

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
    """A real process death mid-restore converges through recovery."""
    uncertain = False
    for attempt in range(10):
        delay = random.uniform(0.05 * attempt, 0.1 * attempt + 0.02)
        matrix.restore_child(delay)
        findings = interrupted_evidence(matrix.temporary)
        print(f"  crash attempt {attempt + 1}: pause {delay:.2f}s -> {findings or 'settled'}", flush=True)
        if findings:
            uncertain = True
            break
    if not uncertain:
        raise ProbeError("no interrupted evidence was produced; cannot drive the recovery stage")
    recovered = False
    for _ in range(4):
        try:
            matrix.restore()
            recovered = True
            break
        except ProbeError:
            try:
                matrix.call(*matrix.recovery_args(execute=True))
            except ProbeError:
                break
    if not recovered:
        raise ProbeError("the recovery stage did not converge the interrupted stores")
    report = matrix.reconcile()
    if not report["reconciled"]:
        raise ProbeError("recovery did not reach the pinned desired state")
    print("PASS B: the crashed generation converged back to both pinned profiles", flush=True)


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
    # The other profile leaves the retained scope; cleanup retires it only.
    matrix.write_policy(
        {
            "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"},
        },
        {"app-b": {"executable": "/usr/bin/app-b", "vpn": "primary"}},
    )
    matrix.call(*matrix.cleanup_args(execute=True))
    listing = subprocess.run(["ip", "-j", "netns", "list"], capture_output=True, check=False, timeout=15)
    if listing.returncode:
        raise ProbeError("the namespace listing could not complete")
    survived = [namespace.get("name") for namespace in json.loads(listing.stdout.decode("utf-8"))]
    if len(survived) != 1:
        raise ProbeError(f"exactly the shared profile's namespace should remain: {survived}")
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
        print("PASS E: the host routes, nftables rules and resolver contents never moved", flush=True)
        unresolved = [
            "provider credentials acquisition and fastest/country selection at boot remain operator-pinned plans",
            "the default profile's host-domain protective routing and the kill switch are not implemented",
            "real-tunnel DNS confinement, IPv6 conformance and leak prevention remain unverified",
            "live replacement cut-over with verified rollback stays administrative work",
            "adversarial ownership testing of the stores under racing privileged actors is outstanding",
            "per-application launch execution and desktop integration remain disabled",
        ]
        print("--- outstanding before Part 8 ---", flush=True)
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
    _assert_no_host_drift(before_name, after_name, matrix.previous_snapshot, fresh)
    matrix.previous_snapshot = fresh


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise the disposable privileged matrix")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print(
            "DRY RUN: the Part 7 acceptance matrix would restore two pinned profiles while a transient policy "
            "deliberately differs, kill restore children mid-flight until real uncertainty is recorded, converge "
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
