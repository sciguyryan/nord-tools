#!/usr/bin/env python3
"""Opt-in privileged acceptance for isolated consumer allocation retirement.

This test provisions two owned WireGuard ecosystems through the production restoration executor, retires one through the ownership-aware cleanup executor, verifies the other remains bound and observable, then retires the second. It does not modify host routing, DNS or firewall configuration. Failed runs retain private diagnostic material for operator review.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nordvpn_manage
from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup
from nord_tools_internal.nordvpn_discovery import discover
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership
from nord_tools_internal.nordvpn_allocation_profiles import kernel_profile_for_allocation
from nord_tools_internal.nordvpn_runtime_consumers import initialise_runtime_consumers, read_runtime_consumers
from nord_tools_internal.nordvpn_consumer_reference_store import write_private_json
from nord_tools_internal.nordvpn_registry import RegistryError


class ProbeError(RuntimeError):
    """The selected-profile acceptance could not establish a safe result."""


def command(*argv: str, input_data: bytes | None = None) -> bytes:
    result = subprocess.run(argv, input=input_data, capture_output=True, check=False, timeout=15)
    if result.returncode:
        raise ProbeError(f"prerequisite command failed: {argv[0]}")
    return result.stdout.strip()


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run_probe() -> None:
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    temporary = Path(tempfile.mkdtemp(prefix="nt-isolated-retirement-"))
    print(
        f"Creating two disposable isolated consumer allocations under {temporary}; inspect /run/netns if interrupted",
        flush=True,
    )
    try:
        policy = temporary / "policy.json"
        journal = temporary / "lifecycle.json"
        bindings = temporary / "owner-bindings.json"
        intents = temporary / "operation-intents.json"
        names = ("alpha", "beta")
        identities = {
            name: kernel_profile_for_allocation(f"application:{name}:profile:isolated", "isolated", "isolated")
            for name in names
        }
        policy_doc = {
            "version": 1,
            "defaults": {"vpn": "default"},
            "vpn_profiles": {
                "default": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"},
                "isolated": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "isolated"},
            },
            "applications": {name: {"executable": "/bin/true", "vpn": "isolated"} for name in names},
        }
        policy.write_text(json.dumps(policy_doc), encoding="utf-8")
        tunnels = {}
        credentials = {}
        for index, name in enumerate(names):
            credential = temporary / f"{name}-key"
            credential.write_bytes(command("wg", "genkey") + b"\n")
            credential.chmod(0o600)
            peer_key = command("wg", "genkey")
            tunnels[identities[name]] = {
                "peer_public_key": command("wg", "pubkey", input_data=peer_key).decode("ascii"),
                "endpoint_address": "198.51.100.10",
                "endpoint_port": 51820,
                "tunnel_addresses": [f"10.213.{240 + index}.2/32"],
                "peer_allowed_ips": [f"10.213.{240 + index}.1/32"],
                "underlay": {
                    "namespace_address": f"10.214.{index}.2/30",
                    "host_address": f"10.214.{index}.1/30",
                },
            }
            credentials[identities[name]] = str(credential)
        startup = temporary / "startup.json"
        startup.write_text(
            json.dumps(
                {
                    "version": 1,
                    "policy": str(policy),
                    "journal": str(journal),
                    "bindings": str(bindings),
                    "intent": str(intents),
                    "run_record": str(temporary / "startup-runs.json"),
                    "tunnels": tunnels,
                    "credentials": credentials,
                }
            ),
            encoding="utf-8",
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nordvpn_manage.main(["restore-startup", "--config", str(startup)])
        if status != 0 or sorted(json.loads(output.getvalue())["restored"]) != sorted(identities.values()):
            raise ProbeError("both profiles were not restored")
        original = read(bindings)["bindings"]
        if len(original) != 8:
            raise ProbeError("expected four recorded resources per profile")
        namespaces = {entry["identifier"] for entry in original if entry["kind"] == "namespace"}
        if len(namespaces) != 2:
            raise ProbeError("two distinct namespace identities were not recorded")
        print("PASS: two independently owned isolated consumer allocations restored", flush=True)
        runtime = temporary / "runtime-consumers.json"
        initialise_runtime_consumers(runtime, policy_doc)

        def verify_state() -> dict:
            return preflight_ownership(read(journal), read(bindings), discover(), read(intents))

        before = verify_state()
        if before["operator_review_required"]:
            raise ProbeError("initial ownership preflight requires review")
        # A syntactically valid but outstanding lease must block kernel deletion,
        # even when the caller claims that the consumer has been released.
        empty_evidence = read_runtime_consumers(runtime, policy_doc)
        occupied = dict(empty_evidence)
        occupied["leases"] = [
            {
                "application": "alpha",
                "profile": "isolated",
                "allocation_key": "application:alpha:profile:isolated",
                "pid": os.getpid(),
                "boot_id": "probe-boot",
                "start_time": "probe-start",
                "executable": "/bin/true",
                "generation_id": "acceptance-generation-alpha",
                "kernel_profile": identities["alpha"],
            }
        ]
        write_private_json(runtime, occupied)
        try:
            plan_cleanup(
                journal,
                bindings,
                intent_path=intents,
                selected_profiles=(identities["alpha"],),
                consumer_policy=policy_doc,
                released_consumers=("alpha",),
                runtime_consumers_path=runtime,
                execute=True,
            )
        except RegistryError as exc:
            if "runtime consumer leases retain" not in str(exc):
                raise ProbeError(f"unexpected outstanding-lease refusal: {exc}") from exc
        else:
            raise ProbeError("outstanding alpha lease permitted kernel retirement")
        if verify_state()["operator_review_required"]:
            raise ProbeError("lease refusal disturbed resource ownership")
        # The separate beta allocation must not be eligible for alpha's release.
        try:
            plan_cleanup(
                journal,
                bindings,
                intent_path=intents,
                selected_profiles=(identities["beta"],),
                consumer_policy=policy_doc,
                released_consumers=("alpha",),
                runtime_consumers_path=runtime,
                execute=True,
            )
        except RegistryError:
            pass
        else:
            raise ProbeError("alpha release authorised beta retirement")
        write_private_json(runtime, empty_evidence)
        print("PASS: outstanding leases and cross-allocation release attempts refused", flush=True)

        first = plan_cleanup(
            journal,
            bindings,
            intent_path=intents,
            selected_profiles=(identities["alpha"],),
            consumer_policy=policy_doc,
            released_consumers=("alpha",),
            runtime_consumers_path=runtime,
            execute=True,
        )
        if not first["executed"] or len(first["deletions"]) != 4:
            raise ProbeError("first selected retirement did not remove exactly four resources")
        after = verify_state()
        if after["operator_review_required"]:
            raise ProbeError("ownership preflight after first retirement requires review")
        profile_by_id = {
            entry["allocation_id"]: entry["profile"] for entry in read(journal)["allocations"]["resources"]
        }
        preserved = [
            entry for entry in after["resources"] if profile_by_id.get(entry["allocation_id"]) == identities["beta"]
        ]
        if len(preserved) != 4 or any(entry["finding"] != "verified_current" for entry in preserved):
            raise ProbeError("the unselected profile was not preserved as verified")
        print("PASS: retiring isolated alpha preserved all four verified beta resources", flush=True)

        repeat = plan_cleanup(
            journal,
            bindings,
            intent_path=intents,
            selected_profiles=(identities["alpha"],),
            consumer_policy=policy_doc,
            released_consumers=("alpha",),
            runtime_consumers_path=runtime,
            execute=True,
        )
        if repeat["deletions"]:
            raise ProbeError("repeated selected retirement changed resources")
        final = plan_cleanup(
            journal,
            bindings,
            intent_path=intents,
            selected_profiles=(identities["beta"],),
            consumer_policy=policy_doc,
            released_consumers=("beta",),
            runtime_consumers_path=runtime,
            execute=True,
        )
        if len(final["deletions"]) != 4:
            raise ProbeError("second selected retirement did not remove exactly four resources")
        remaining = {line.split()[0] for line in command("ip", "netns", "list").decode().splitlines() if line.strip()}
        if namespaces & remaining or any(Path("/run/netns", name).exists() for name in namespaces):
            raise ProbeError("an owned namespace remains after final retirement")
        print("PASS: isolated repeat retirement was idempotent and final retirement removed beta", flush=True)
    except BaseException:
        print(f"Retained privileged evidence for review: {temporary}", file=sys.stderr)
        raise
    shutil.rmtree(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise disposable privileged testing")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print(
            "DRY RUN: would provision two isolated consumer allocations, retire one while verifying the other, then retire the second. No changes made."
        )
        return 0
    try:
        run_probe()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
