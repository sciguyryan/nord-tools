#!/usr/bin/env python3
"""Opt-in end-to-end acceptance of journal-gated disposable WireGuard execution.

The test uses one temporary namespace and an isolated operation store. It does
not create a persistent tunnel, change host routing or authorise live cleanup.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nord_tools_internal.nordvpn_disposable_execution import execute_disposable_session
from nord_tools_internal.nordvpn_identity import allocate_identity
from nord_tools_internal.nordvpn_lifecycle import record_transition
from nord_tools_internal.nordvpn_operation_store import initialise_intents, read_intents
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification


class ProbeError(RuntimeError):
    """The integrated disposable acceptance probe cannot complete safely."""


def command(*argv: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(argv, input=input_data, capture_output=True, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("required WireGuard command could not complete") from exc
    if result.returncode:
        raise ProbeError("required WireGuard command failed")
    return result.stdout.strip()


def run_probe() -> str:
    """Run one isolated creation, verification and retirement transaction."""
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    namespace = f"nt-{secrets.token_hex(8)}"
    interface = f"ntwg{secrets.token_hex(4)}"
    private_key = command("wg", "genkey")
    peer_private_key = command("wg", "genkey")
    public_key = command("wg", "pubkey", input_data=private_key).decode("ascii")
    peer_public_key = command("wg", "pubkey", input_data=peer_private_key).decode("ascii")
    spec = TunnelSpecification(
        namespace, interface, peer_public_key, "198.51.100.2", 51820, "10.213.240.2/32", ("10.213.240.1/32",)
    )
    allocation = allocate_identity("interface", interface, "default")
    token = allocation["allocation_id"]
    journal = {"version": 1, "allocations": {"version": 2, "resources": [allocation]}, "events": []}
    journal = record_transition(record_transition(journal, token, "reserved"), token, "creating")

    temporary = Path(tempfile.mkdtemp(prefix="nt-disposable-acceptance-"))
    succeeded = False
    try:
        store = temporary / "operations.json"
        initialise_intents(store, journal)
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, private_key)
        finally:
            os.close(write_fd)

        def verify(_spec: TunnelSpecification) -> bool:
            actual_key = command("ip", "netns", "exec", namespace, "wg", "show", interface, "public-key")
            peers = command("ip", "netns", "exec", namespace, "wg", "show", interface, "peers").splitlines()
            return actual_key == public_key.encode("ascii") and peers == [peer_public_key.encode("ascii")]

        print(f"Creating disposable namespace {namespace}; inspect /run/netns if interrupted", flush=True)
        try:
            result = execute_disposable_session(store, journal, token, spec, read_fd, verify)
            if result != namespace:
                raise ProbeError("unexpected disposable execution result")
            outcomes = [item["outcome"] for item in read_intents(store, journal)["operations"]]
            if outcomes != ["completed"]:
                raise ProbeError("operation intent did not complete")
            print(f"PASS: journal-gated WireGuard configuration and verification in {namespace}", flush=True)
            print(f"PASS: disposable namespace retired and intent completed: {namespace}", flush=True)
            succeeded = True
        except BaseException:
            # Preserve unresolved intent evidence for manual review if the test
            # cannot establish that all kernel resources were retired.
            try:
                evidence = read_intents(store, journal)
                print(
                    f"Operation outcomes on failure: {[item['outcome'] for item in evidence['operations']]}",
                    file=sys.stderr,
                )
            except Exception:
                print("Operation intent inspection failed", file=sys.stderr)
            raise
        finally:
            os.close(read_fd)
    finally:
        if succeeded:
            shutil.rmtree(temporary)
        else:
            print(f"Retained operation evidence for review: {temporary}", file=sys.stderr)
    return namespace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise a disposable privileged test")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print(
            "DRY RUN: would record an intent, create one disposable WireGuard namespace, verify its peer, retire it and complete the intent. No changes made."
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
