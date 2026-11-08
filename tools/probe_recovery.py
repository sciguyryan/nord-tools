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
from dataclasses import replace
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


def _namespace_names(raw: bytes) -> set[str]:
    """Parse the names from ``ip netns list`` without claiming other entries."""
    return {line.split(maxsplit=1)[0].decode("utf-8") for line in raw.splitlines() if line.strip()}


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


def run_probe(*, after_binding: bool = False, checkpoint: str | None = None) -> str:
    if checkpoint is not None and after_binding:
        raise ProbeError("select only one interruption checkpoint")
    if checkpoint not in (None, "underlay", "wireguard", "routing"):
        raise ProbeError("unsupported interruption checkpoint")
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

        # The child pauses at the exact operation callback boundary. The
        # production adapter has already fsynced its pending intent, but no
        # kernel resource creation callback has been entered. This checkpoint
        # exists only in the probe child; production modules are unchanged.
        read_fd, write_fd = os.pipe()
        try:
            child = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--checkpoint-child",
                    str(startup),
                    str(write_fd),
                    *(["--after-binding"] if after_binding else []),
                    *(["--checkpoint", checkpoint] if checkpoint else []),
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
                raise ProbeError("checkpoint child did not reach the durable intent boundary")
            findings = interrupted_evidence(temporary)
            if not findings:
                raise ProbeError("checkpoint fired without a durable pending intent")
            if after_binding or checkpoint:
                binding_file = temporary / "owner-bindings.json"
                bindings = json.loads(binding_file.read_text(encoding="utf-8"))
                namespace_bindings = [entry for entry in bindings["bindings"] if entry["kind"] == "namespace"]
                if len(namespace_bindings) != 1:
                    raise ProbeError("partial creation checkpoint lacks one durable namespace binding")
                live = command("ip", "netns", "list")
                if live.returncode or namespace_bindings[0]["identifier"] not in _namespace_names(live.stdout):
                    raise ProbeError("partial creation checkpoint lacks its live namespace")
                if checkpoint in {"underlay", "wireguard", "routing"}:
                    underlay_bindings = [
                        entry
                        for entry in bindings["bindings"]
                        if entry["kind"] == "interface" and entry["binding"].get("scope") == "host"
                    ]
                    if len(underlay_bindings) != 1:
                        raise ProbeError("later checkpoint lacks a durable host underlay binding")
                    host = command("ip", "-j", "link", "show")
                    if host.returncode:
                        raise ProbeError("cannot observe host underlay at interruption")
                    host_links = json.loads(host.stdout)
                    if not any(
                        link.get("ifindex") == underlay_bindings[0]["binding"]["ifindex"] for link in host_links
                    ):
                        raise ProbeError("later checkpoint lacks its identity-bound host underlay")
                print(f"PASS: checkpoint retained live bound resources ({checkpoint or 'namespace'})", flush=True)
            else:
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

        bindings_doc = json.loads((temporary / "owner-bindings.json").read_text(encoding="utf-8"))
        namespace_name = next(entry["identifier"] for entry in bindings_doc["bindings"] if entry["kind"] == "namespace")

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
        if remaining.returncode:
            raise ProbeError("the final namespace inventory failed")
        if namespace_name in _namespace_names(remaining.stdout):
            raise ProbeError(f"the recovered generation's namespace remains: {namespace_name}")
        print("PASS: the confirmed cleanup retired the recovered generation", flush=True)
        result = ",".join(all_findings)
    except BaseException:
        print(f"Retained recovery evidence for review: {temporary}", file=sys.stderr)
        raise
    shutil.rmtree(temporary)
    return result


def checkpoint_child(startup: str, ready_fd: int, *, after_binding: bool = False, checkpoint: str | None = None) -> int:
    """Probe-only wrapper: pause after the selected durable or kernel boundary."""
    from nord_tools_internal import nordvpn_restore_executor as restore

    if checkpoint not in (None, "underlay", "wireguard", "routing") or (checkpoint and after_binding):
        raise ProbeError("invalid checkpoint selection")
    original = restore.execute_recorded_creation
    original_kernel = restore._real_kernel

    def pause():
        os.write(ready_fd, b"R")
        while True:
            signal.pause()

    if checkpoint:

        def checkpoint_kernel():
            kernel = original_kernel()
            if checkpoint == "underlay":
                # The host underlay binding is written after prepare_underlay.
                return kernel
            field = "configure_wireguard" if checkpoint == "wireguard" else "route_tunnel"
            original_step = getattr(kernel, field)

            def stopped_step(*args, **kwargs):
                result = original_step(*args, **kwargs)
                pause()
                return result

            return replace(kernel, **{field: stopped_step})

        restore._real_kernel = checkpoint_kernel

    def intercepted(store_path, journal, allocation_id, operation, verify):
        def paused_operation():
            os.write(ready_fd, b"R")
            # The parent must kill this process; do not enter kernel mutation.
            while True:
                signal.pause()

        return original(store_path, journal, allocation_id, paused_operation, verify)

    if after_binding or checkpoint == "underlay":
        original_binding = restore.record_binding

        def intercepted_binding(store_path, journal, allocation_id, binding, *, configuration=None):
            result = original_binding(store_path, journal, allocation_id, binding, configuration=configuration)
            is_namespace = "device" in binding and "inode" in binding
            is_underlay = binding.get("scope") == "host" and "ifindex" in binding
            if (after_binding and is_namespace) or (checkpoint == "underlay" and is_underlay):
                # Pause only after the selected creation-time identity is durable.
                pause()
            return result

        restore.record_binding = intercepted_binding
    elif checkpoint is None:
        restore.execute_recorded_creation = intercepted
    try:
        return nordvpn_manage.main(["restore-startup", "--config", startup])
    finally:
        restore.execute_recorded_creation = original
        if after_binding or checkpoint == "underlay":
            restore.record_binding = original_binding
        restore._real_kernel = original_kernel
        os.close(ready_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint-child", nargs=2, metavar=("STARTUP", "FD"), help=argparse.SUPPRESS)
    parser.add_argument("--run-privileged", action="store_true", help="authorise a disposable privileged probe")
    parser.add_argument(
        "--after-binding", action="store_true", help="interrupt after the namespace owner binding is durable"
    )
    parser.add_argument(
        "--checkpoint",
        choices=("underlay", "wireguard", "routing"),
        help="interrupt after a later kernel provisioning step",
    )
    args = parser.parse_args(argv)
    if args.after_binding and args.checkpoint:
        parser.error("--after-binding and --checkpoint cannot be combined")
    if args.checkpoint_child is not None:
        return checkpoint_child(
            args.checkpoint_child[0],
            int(args.checkpoint_child[1]),
            after_binding=args.after_binding,
            checkpoint=args.checkpoint,
        )
    if not args.run_privileged:
        boundary = (
            f"after {args.checkpoint} installation"
            if args.checkpoint
            else "after a live namespace is created and bound"
            if args.after_binding
            else "before kernel creation"
        )
        print(
            "DRY RUN: would restore a pinned profile, kill the child at a durable checkpoint "
            f"{boundary}, recover through the production authority paths and clean up. No changes made."
        )
        return 0
    try:
        run_probe(after_binding=args.after_binding, checkpoint=args.checkpoint)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
