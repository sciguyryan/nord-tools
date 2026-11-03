#!/usr/bin/env python3
"""Opt-in acceptance of crash recovery under deliberate process death.

The dry run describes the cycle without touching any store. The privileged run
restores one pinned profile in a child process on a disposable-capable Linux
test system, kills the child at a deterministic durable-intent checkpoint before any
kernel creation, then converges the ecosystem through
the boot recovery path and explicit operator recovery before the confirmed
cleanup retires everything. Verify with sudo ip netns list afterwards.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import signal
import select
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nordvpn_manage


class ProbeError(RuntimeError):
    """The controlled recovery acceptance probe cannot complete safely."""


def interrupted_evidence(root: Path) -> list[str]:
    """Report the uncertainty evidence recorded by an interrupted run."""
    findings: list[str] = []
    intent_file = root / "operation-intents.json"
    if not intent_file.exists():
        # A killed child may not yet have reached the first durable write.
        # Absence is not evidence of a partial transaction.
        return findings
    intents = json.loads(intent_file.read_text(encoding="utf-8"))
    for operation in intents["operations"]:
        if operation["outcome"] in {"pending", "uncertain"}:
            findings.append(f"operation {operation['operation_id']}: {operation['outcome']}")
    journal_file = root / "lifecycle.json"
    if not journal_file.exists():
        return findings
    journal = json.loads(journal_file.read_text(encoding="utf-8"))
    states: dict[str, str] = {}
    for event in journal["events"]:
        states[event["allocation_id"]] = event["state"]
    if any(state not in {"active", "retired"} for state in states.values()):
        findings.append("interrupted lifecycle states: " + " ".join(sorted(set(states.values()))))
    return findings


def uncertain_stores(root: Path) -> bool:
    return bool(interrupted_evidence(root))


def run_probe() -> str:
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    temporary = Path(tempfile.mkdtemp(prefix="nt-recovery-acceptance-"))
    print(f"Creating a disposable ecosystem under {temporary}; inspect /run/netns if interrupted", flush=True)
    all_findings: list[str] = []
    try:
        config_home = temporary / "config"
        (config_home / "nord-tools").mkdir(mode=0o700, parents=True)
        os.environ["XDG_CONFIG_HOME"] = str(config_home)
        policy = config_home / "nord-tools" / "desired-policy.json"

        def call(*args: str) -> dict:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = nordvpn_manage.main([*args])
            if code != 0:
                raise ProbeError(f"{args[0]} reported failure")
            return json.loads(buffer.getvalue())

        def command(*argv: list[str], input_data: bytes | None = None):
            return subprocess.run(argv, input=input_data, capture_output=True, check=False, timeout=30)

        generated = command("wg", "genkey")
        if generated.returncode:
            raise ProbeError("the prerequisite WireGuard commands failed")
        private_key = generated.stdout.strip()
        peer_private = command("wg", "genkey")
        peer = command("wg", "pubkey", input_data=peer_private.stdout.strip())
        if peer.returncode:
            raise ProbeError("the WireGuard public key derivation failed")
        peer_public = peer.stdout.strip().decode("ascii")
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
        startup = temporary / "startup.json"
        startup.write_text(
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
                            "tunnel_address": "10.213.240.2/32",
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

        # The child pauses at the exact operation callback boundary. The
        # production adapter has already fsynced its pending intent, but no
        # kernel resource creation callback has been entered. This checkpoint
        # exists only in the probe child; production modules are unchanged.
        read_fd, write_fd = os.pipe()
        try:
            child = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--checkpoint-child", str(startup), str(write_fd)],
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
                raise ProbeError("checkpoint child did not reach the durable intent boundary")
            findings = interrupted_evidence(temporary)
            if not findings:
                raise ProbeError("checkpoint fired without a durable pending intent")
            print("PASS: checkpoint reached after durable intent, before kernel creation", flush=True)
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
            if "child" in locals() and child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=30)
        all_findings.extend(interrupted_evidence(temporary))
        if not all_findings:
            raise ProbeError("interrupted child did not retain durable uncertainty")
        print("PASS: SIGKILL retained a real pending operation for recovery", flush=True)

        # Boot recovery first: the boot wall refuses uncertain evidence, but the
        # operator's explicit recovery resolves exactly what is certified.
        boot_recovered = False
        for _ in range(3):
            buffer = io.StringIO()
            error = io.StringIO()
            with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(error):
                code = nordvpn_manage.main(["restore-startup", "--config", str(startup)])
            if code == 0:
                boot_recovered = True
                break
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = nordvpn_manage.main(
                    [
                        "recovery",
                        "--journal",
                        str(temporary / "lifecycle.json"),
                        "--bindings",
                        str(temporary / "owner-bindings.json"),
                        "--intents",
                        str(temporary / "operation-intents.json"),
                        "--execute",
                    ]
                )
            if code != 0:
                break
        if not boot_recovered:
            raise ProbeError("recovery did not converge the interrupted ecosystem")
        print("PASS: the recovery converged the interrupted stores to the pinned desired state", flush=True)

        # Final full teardown through the confirmed cleanup for a clean host.
        other = {
            "version": 1,
            "defaults": {"vpn": "other"},
            "vpn_profiles": {"other": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
            "applications": {},
        }
        policy.write_text(json.dumps(other), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            code = nordvpn_manage.main(
                [
                    "cleanup",
                    "--journal",
                    str(temporary / "lifecycle.json"),
                    "--bindings",
                    str(temporary / "owner-bindings.json"),
                    "--intents",
                    str(temporary / "operation-intents.json"),
                    "--execute",
                ]
            )
        if code != 0:
            raise ProbeError("the final settled cleanup reported failure")
        remaining = command("ip", "netns", "list")
        if remaining.returncode or remaining.stdout.strip():
            raise ProbeError(f"unexpected namespaces remain: {remaining.stdout!r}")
        print("PASS: the confirmed cleanup retired the restored generation; the host shows none left", flush=True)
        result = ",".join(all_findings)
    except BaseException:
        print(f"Retained recovery evidence for review: {temporary}", file=sys.stderr)
        raise
    shutil.rmtree(temporary)
    return result


def checkpoint_child(startup: str, ready_fd: int) -> int:
    """Probe-only wrapper: stop after intent persistence, before kernel mutation."""
    from nord_tools_internal import nordvpn_restore_executor as restore

    original = restore.execute_recorded_creation

    def intercepted(store_path, journal, allocation_id, operation, verify):
        def paused_operation():
            os.write(ready_fd, b"R")
            # The parent must kill this process; do not enter kernel mutation.
            while True:
                signal.pause()

        return original(store_path, journal, allocation_id, paused_operation, verify)

    restore.execute_recorded_creation = intercepted
    try:
        return nordvpn_manage.main(["restore-startup", "--config", startup])
    finally:
        os.close(ready_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint-child", nargs=2, metavar=("STARTUP", "FD"), help=argparse.SUPPRESS)
    parser.add_argument("--run-privileged", action="store_true", help="authorise a disposable privileged probe")
    args = parser.parse_args(argv)
    if args.checkpoint_child is not None:
        return checkpoint_child(args.checkpoint_child[0], int(args.checkpoint_child[1]))
    if not args.run_privileged:
        print(
            "DRY RUN: would restore one pinned profile inside child processes, stop them at a durable intent checkpoint until real "
            "uncertainty is recorded, converge via boot and operator recovery, and then clean everything. "
            "No changes made."
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
