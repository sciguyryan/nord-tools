#!/usr/bin/env python3
"""Opt-in acceptance of ownership-aware cleanup through the real executors.

The dry run describes the cycle without touching any store or the kernel. The
privileged run restores one pinned profile on a disposable-capable Linux test
system through the production restoration path, clears the saved desired state
for that profile, executes the ownership-aware cleanup, verifies that every
resource journal was retired and that nothing remains in the kernel.
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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nordvpn_manage


class ProbeError(RuntimeError):
    """The controlled cleanup acceptance probe cannot complete safely."""


def command(*argv: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(argv, input=input_data, capture_output=True, check=False, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("a prerequisite command could not complete") from exc
    if result.returncode:
        raise ProbeError("a prerequisite command failed")
    return result.stdout.strip()


def run_probe() -> str:
    """Restore one pinned profile, then clean it through verified ownership."""
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    temporary = Path(tempfile.mkdtemp(prefix="nt-cleanup-acceptance-"))
    print(f"Creating a disposable ecosystem under {temporary}; inspect /run/netns if interrupted", flush=True)
    try:
        config_home = temporary / "config"
        os.environ["XDG_CONFIG_HOME"] = str(config_home)
        (config_home / "nord-tools").mkdir(mode=0o700, parents=True)
        policy = config_home / "nord-tools" / "desired-policy.json"
        credential = temporary / "probe-key"
        journal = temporary / "lifecycle.json"
        bindings = temporary / "owner-bindings.json"
        intents = temporary / "operation-intents.json"
        run_record = temporary / "startup-runs.json"
        namespace_name = None

        def call(*args: str) -> dict:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = nordvpn_manage.main([*args])
            if code != 0:
                raise ProbeError(f"{args[0]} reported failure")
            return json.loads(buffer.getvalue())

        private_key = command("wg", "genkey")
        peer_private_key = command("wg", "genkey")
        peer_public = command("wg", "pubkey", input_data=peer_private_key).decode("ascii")
        desired = {
            "version": 1,
            "defaults": {"vpn": "accepted"},
            "vpn_profiles": {"accepted": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
            "applications": {},
        }
        policy.write_text(json.dumps(desired), encoding="utf-8")
        credential.write_bytes(private_key + b"\n")
        os.chmod(credential, 0o600)
        startup = temporary / "startup.json"
        startup.write_text(
            json.dumps(
                {
                    "version": 1,
                    "policy": str(policy),
                    "journal": str(journal),
                    "bindings": str(bindings),
                    "intent": str(intents),
                    "run_record": str(run_record),
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

        restored = call("restore-startup", "--config", str(startup))
        bindings_doc = json.loads(bindings.read_text(encoding="utf-8"))
        namespace_record = next(entry for entry in bindings_doc["bindings"] if entry["kind"] == "namespace")
        namespace_name = namespace_record["identifier"]
        if restored["restored"] != ["accepted"]:
            raise ProbeError("the restoration step did not converge on the pinned profile")
        print(f"PASS: restoration created and verified {namespace_name}", flush=True)

        # Move the profile outside the retained desired scope; the cleanup then
        # classifies it for removal through its recorded ownership evidence.
        other = {
            "version": 1,
            "defaults": {"vpn": "other"},
            "vpn_profiles": {"other": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
            "applications": {},
        }
        policy.write_text(json.dumps(other), encoding="utf-8")

        report = call(
            "cleanup",
            "--journal",
            str(journal),
            "--bindings",
            str(bindings),
            "--intents",
            str(intents),
            "--execute",
        )
        if report["executed"] is not True or len(report["deletions"]) != 4:
            raise ProbeError(f"unexpected cleanup report: {report['deletions']}")
        print("PASS: the cleanup executed only the four verified owned resources", flush=True)
        remaining = command("ip", "netns", "list")
        if namespace_name.encode() in remaining or any(part for part in [remaining]):
            raise ProbeError(f"unexpected namespaces remain: {remaining!r}")
        print("PASS: the namespace and the host underlay are gone after the verified cleanup", flush=True)
        return namespace_name
    except BaseException:
        print(f"Retained cleanup evidence for review: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true", help="authorise a disposable privileged probe")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print(
            "DRY RUN: would restore one pinned profile through the boot executor, then clean every "
            "resource it owns through the ownership-verified cleanup after clearing the desired state. "
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
