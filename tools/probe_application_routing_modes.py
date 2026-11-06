#!/usr/bin/env python3
"""Privileged, non-network-mutating host-routing and VPN refusal acceptance."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nord_tools_internal.nordvpn_application_executor import (  # noqa: E402
    launch_direct_application,
    launch_provisioned_application,
)
from nord_tools_internal.nordvpn_consumer_reference_store import ConsumerReferenceError  # noqa: E402
from nord_tools_internal.nordvpn_application_plan import plan_application  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument("--uid", type=int, help="Existing non-root user ID for disposable child")
    parser.add_argument("--gid", type=int, help="Existing non-root group ID for disposable child")
    args = parser.parse_args()
    if not args.run_privileged:
        print("PREVIEW: explicit direct host routing, non-root child, no VPN fallback; no changes")
        return 0
    if os.geteuid() != 0 or args.uid is None or args.gid is None or args.uid <= 0 or args.gid <= 0:
        parser.error("privileged acceptance requires root and explicit non-root --uid and --gid")
    with tempfile.TemporaryDirectory(prefix="nt-app-routing-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        script = root / "inspect.py"
        output = root / "result.json"
        output.touch(mode=0o600)
        os.chown(output, args.uid, args.gid)
        script.write_text(
            "import json, os, sys\n"
            'with open(sys.argv[1], "w", encoding="utf-8") as out:\n'
            '    json.dump({"uid": os.geteuid(), "gid": os.getegid(), '
            '"namespace": os.stat("/proc/self/ns/net").st_ino}, out)\n',
            encoding="utf-8",
        )
        script.chmod(0o644)
        policy = {
            "version": 1,
            "defaults": {"vpn": "primary"},
            "vpn_profiles": {"primary": {"selection": {"mode": "country", "country": "GB"}}},
            "applications": {
                "host_test": {"executable": sys.executable, "vpn": "direct"},
                "vpn_test": {"executable": sys.executable},
            },
        }
        assert plan_application(policy, "host_test").profile == "direct"
        assert plan_application(policy, "vpn_test").profile == "primary"
        before = os.stat("/proc/self/ns/net").st_ino
        result = launch_direct_application(
            policy,
            "host_test",
            (str(script), str(output)),
            uid=args.uid,
            gid=args.gid,
        )
        if result != 0:
            raise RuntimeError(f"direct child returned {result}")
        child = json.loads(output.read_text(encoding="utf-8"))
        if child != {"uid": args.uid, "gid": args.gid, "namespace": before}:
            raise RuntimeError("direct child did not retain host network namespace or drop privileges")
        if os.stat("/proc/self/ns/net").st_ino != before:
            raise RuntimeError("host network namespace changed")
        try:
            launch_provisioned_application(
                policy,
                "vpn_test",
                (),
                runtime_consumers="unused",
                journal_path="unused",
                bindings_path="unused",
                intent_path="",
                observe=lambda: {},
                uid=args.uid,
                gid=args.gid,
            )
        except ConsumerReferenceError:
            pass
        else:
            raise RuntimeError("VPN-bound application unexpectedly launched without authority")
    print("PASS: direct child used host namespace with explicit non-root identity")
    print("PASS: VPN-bound application refused missing authority without direct fallback")
    print("PASS: disposable host-routing acceptance completed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
