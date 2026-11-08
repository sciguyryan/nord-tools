#!/usr/bin/env python3
"""Opt-in acceptance of boot restoration through the journal-gated executor.

The dry run describes the full restoration cycle without touching any store.
The privileged run restores one pinned profile on a disposable-capable Linux
test system through the real production kernel primitives, verifies the
lifecycle, bindings and convergence, repeats the run to show idempotency, and
finally retires the created namespace only after re-verifying its recorded
creation-time binding. Do not run it on a critical host.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nordvpn_manage
from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace


class ProbeError(RuntimeError):
    """The controlled restoration acceptance probe cannot complete safely."""


def command(*argv: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(argv, input=input_data, capture_output=True, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("a prerequisite command could not complete") from exc
    if result.returncode:
        raise ProbeError("a prerequisite command failed")
    return result.stdout.strip()


def verify_retired_resources(namespace_name: str, host_end: str, host_ifindex: int | None = None) -> None:
    """Verify retirement without deleting a potentially unrelated host interface.

    Deleting a namespace destroys its veth endpoint, which normally removes the
    paired host interface as well. A second unconditional ``ip link del`` would
    therefore fail even when retirement succeeded. If the host interface still
    exists, leave it untouched for operator review rather than using a stale
    name as deletion authority.
    """
    remaining = command("ip", "netns", "list")
    names = {line.split()[0] for line in remaining.decode("utf-8").splitlines() if line.strip()}
    if namespace_name in names or Path("/run/netns", namespace_name).exists():
        raise ProbeError("the retired namespace remains observable")
    # Enumerate the host link table successfully instead of interpreting
    # version-dependent iproute2 error wording for a missing device.
    try:
        observed = json.loads(command("ip", "-j", "link", "show"))
    except (ProbeError, ValueError, TypeError) as exc:
        raise ProbeError("host underlay absence could not be established") from exc
    if not isinstance(observed, list) or any(
        not isinstance(link, dict) or not isinstance(link.get("ifname"), str) for link in observed
    ):
        raise ProbeError("host underlay absence could not be established")
    # A removed namespace mount can briefly retain its network namespace while
    # the kernel releases the final reference and the veth peer. Wait for
    # observed absence, never deleting the host link by name.
    deadline = time.monotonic() + 2.0
    while True:
        matches = [link for link in observed if link["ifname"] == host_end]
        if not matches:
            return
        if len(matches) != 1 or (host_ifindex is not None and matches[0].get("ifindex") != host_ifindex):
            raise ProbeError("host underlay identity changed; refusing unverified deletion")
        if time.monotonic() >= deadline:
            raise ProbeError("the host underlay remains; refusing unverified deletion")
        time.sleep(0.1)
        try:
            observed = json.loads(command("ip", "-j", "link", "show"))
        except (ProbeError, ValueError, TypeError) as exc:
            raise ProbeError("host underlay absence could not be established") from exc
        if not isinstance(observed, list) or any(
            not isinstance(link, dict) or not isinstance(link.get("ifname"), str) for link in observed
        ):
            raise ProbeError("host underlay absence could not be established")


def run_probe() -> str:
    """Restore one pinned profile, verify, then retire only what this run created."""
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    private_key = command("wg", "genkey")
    peer_private_key = command("wg", "genkey")
    peer_public = command("wg", "pubkey", input_data=peer_private_key).decode("ascii")
    temporary = Path(tempfile.mkdtemp(prefix="nt-restore-acceptance-"))
    print(f"Creating a disposable ecosystem under {temporary}; inspect /run/netns if interrupted", flush=True)
    try:
        policy = temporary / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {"vpn": "accepted"},
                    "vpn_profiles": {
                        "accepted": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}
                    },
                    "applications": {},
                }
            ),
            encoding="utf-8",
        )
        credential = temporary / "probe-key"
        credential.write_bytes(private_key + b"\n")
        os.chmod(credential, 0o600)
        config = temporary / "startup.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "policy": str(policy),
                    "journal": str(temporary / "lifecycle.json"),
                    "bindings": str(temporary / "owner-bindings.json"),
                    "intent": str(temporary / "operation-intents.json"),
                    "run_record": str(temporary / "startup-runs.json"),
                    "tunnels": {
                        "accepted": {
                            "peer_public_key": peer_public,
                            "endpoint_address": "198.51.100.10",
                            "endpoint_port": 51820,
                            "tunnel_addresses": ["10.213.240.2/32"],
                            "peer_allowed_ips": ["10.213.240.1/32"],
                            "underlay": {
                                "namespace_address": "10.214.0.2/30",
                                "host_address": "10.214.0.1/30",
                            },
                        }
                    },
                    "credentials": {"accepted": str(credential)},
                }
            ),
            encoding="utf-8",
        )

        def call_restore() -> dict:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = nordvpn_manage.main(["restore-startup", "--config", str(config)])
            if code != 0:
                raise ProbeError("restore-startup reported failure")
            return json.loads(buffer.getvalue())

        report = call_restore()
        bindings = json.loads((temporary / "owner-bindings.json").read_text(encoding="utf-8"))
        namespace_record = next((entry for entry in bindings["bindings"] if entry["kind"] == "namespace"), None)
        if report["restored"] != ["accepted"] or namespace_record is None:
            raise ProbeError(f"unexpected restoration report: {report['restored']}")
        namespace_name = namespace_record["identifier"]
        print(f"PASS: journal-gated restoration created and bound {namespace_name}", flush=True)

        journal = json.loads((temporary / "lifecycle.json").read_text(encoding="utf-8"))
        states = {event["allocation_id"]: event["state"] for event in journal["events"]}
        if not states or any(state != "active" for state in states.values()):
            raise ProbeError(f"unexpected lifecycle states: {states}")
        host_record = next(entry for entry in bindings["bindings"] if entry["binding"].get("scope") == "host")
        host_end = host_record["identifier"]
        with open(f"/run/netns/{namespace_name}") as descriptor:
            metadata = os.fstat(descriptor.fileno())
            if (metadata.st_dev, metadata.st_ino) != (
                namespace_record["binding"]["device"],
                namespace_record["binding"]["inode"],
            ):
                raise ProbeError("recorded namespace binding does not match the observed mount identity")
            OwnedNamespace(namespace_name, descriptor.fileno(), metadata.st_dev, metadata.st_ino).verify()
        print(f"PASS: the creation-time owner binding still matches {namespace_name} within this boot", flush=True)

        repeat = call_restore()
        if repeat["network_changes_applied"]:
            raise ProbeError("the repeat run must not provision again within the same boot")
        if not repeat["reconciled"]:
            raise ProbeError(f"the repeat run did not converge: {repeat['blocked']}")
        print("PASS: repeat restoration is idempotent and converges", flush=True)

        # Identity-verified retirement of the single resource this probe created.
        with open(f"/run/netns/{namespace_name}") as descriptor:
            metadata = os.fstat(descriptor.fileno())
            # retire() closes its authority descriptor. Retain a separate descriptor
            # so the surrounding file context can close its own descriptor safely.
            owned = OwnedNamespace(namespace_name, os.dup(descriptor.fileno()), metadata.st_dev, metadata.st_ino)
            try:
                owned.verify()
                owned.retire()
            finally:
                owned.release()
        verify_retired_resources(namespace_name, host_end, host_record["binding"]["ifindex"])
        print("PASS: the verified namespace and the host underlay were removed", flush=True)
    except BaseException:
        print(f"Retained restoration evidence for review: {temporary}", file=sys.stderr)
        raise
    shutil.rmtree(temporary)
    return namespace_name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise a disposable privileged probe")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print(
            "DRY RUN: would restore one pinned profile through durable intents, "
            "record creation-time owner bindings, verify convergence, repeat, then retire "
            "the created namespace after re-verifying its recorded binding. No changes made."
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
