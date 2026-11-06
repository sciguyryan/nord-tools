#!/usr/bin/env python3
"""Privileged concurrent direct-application and real-WireGuard confinement probe.

Uses a disposable WireGuard namespace with the production nftables policy,
resolver and IPv4/IPv6 routes, while a registered direct application runs in
parallel. This does not impersonate the production VPN lease/launch gate.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nord_tools_internal.nordvpn_application_executor import launch_direct_application
from tools.probe_wireguard_dns_acceptance import experiment
from tools.probe_wireguard_host_integrity import observe, verify


class ApplicationNetworkAcceptanceError(RuntimeError):
    """A required application network isolation observation failed."""


def _direct_policy() -> dict:
    return {
        "version": 1,
        "defaults": {"vpn": "primary"},
        "vpn_profiles": {"primary": {"selection": {"mode": "country", "country": "GB"}}},
        "applications": {"direct_probe": {"executable": sys.executable, "vpn": "direct"}},
    }


def concurrent_experiment(uid: int, gid: int) -> None:
    """Keep a registered direct child alive throughout the WireGuard experiment."""
    with tempfile.TemporaryDirectory(prefix="nt-application-network-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        script = root / "direct_child.py"
        marker = root / "identity.json"
        stop = root / "stop"
        marker.touch(mode=0o600)
        os.chown(marker, uid, gid)
        script.write_text(
            "import json, os, sys, time\n"
            "with open(sys.argv[1], 'w', encoding='utf-8') as stream:\n"
            "    json.dump({'uid': os.geteuid(), 'gid': os.getegid(), "
            "'netns': os.stat('/proc/self/ns/net').st_ino}, stream)\n"
            "for _ in range(200):\n"
            "    if os.path.exists(sys.argv[2]):\n"
            "        sys.exit(0)\n"
            "    time.sleep(0.1)\n"
            "sys.exit(3)\n",
            encoding="utf-8",
        )
        script.chmod(0o644)
        outcome: list[object] = []

        def run_direct() -> None:
            try:
                outcome.append(
                    launch_direct_application(
                        _direct_policy(),
                        "direct_probe",
                        (str(script), str(marker), str(stop)),
                        uid=uid,
                        gid=gid,
                    )
                )
            except Exception as exc:
                outcome.append(exc)

        thread = threading.Thread(target=run_direct, daemon=True)
        host_netns = os.stat("/proc/self/ns/net").st_ino
        thread.start()
        try:
            for _ in range(100):
                if marker.stat().st_size:
                    break
                if not thread.is_alive():
                    raise ApplicationNetworkAcceptanceError("direct child exited before the VPN experiment")
                time.sleep(0.05)
            else:
                raise ApplicationNetworkAcceptanceError("direct child did not report its identity")
            child = json.loads(marker.read_text(encoding="utf-8"))
            if child != {"uid": uid, "gid": gid, "netns": host_netns}:
                raise ApplicationNetworkAcceptanceError("direct child identity or host namespace differed")
            experiment(secrets.token_hex(3))
            if not thread.is_alive():
                raise ApplicationNetworkAcceptanceError("direct child exited while VPN confinement was exercised")
            if os.stat("/proc/self/ns/net").st_ino != host_netns:
                raise ApplicationNetworkAcceptanceError("host namespace changed")
            print("PASS: registered direct application remained in the host namespace during WireGuard confinement")
        finally:
            stop.touch()
            thread.join(timeout=5)
        if thread.is_alive() or outcome != [0]:
            raise ApplicationNetworkAcceptanceError("direct application did not exit cleanly")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument("--uid", type=int, help="Existing non-root test account UID")
    parser.add_argument("--gid", type=int, help="Existing non-root test account GID")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: concurrent direct application and production-policy WireGuard DNS acceptance")
        return 0
    if os.geteuid() != 0 or sys.platform != "linux" or not args.uid or not args.gid or args.uid <= 0 or args.gid <= 0:
        parser.error("Linux root and explicit non-root --uid/--gid are required")
    missing = [name for name in ("ip", "wg", "nft", "ping") if shutil.which(name) is None]
    if missing:
        parser.error("Missing prerequisites: " + ", ".join(missing))
    if not Path("/etc/netns").is_dir():
        parser.error("/etc/netns must exist before the disposable probe")
    try:
        before = observe()
        concurrent_experiment(args.uid, args.gid)
        verify(before, observe())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("PASS: concurrent application and WireGuard confinement acceptance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
