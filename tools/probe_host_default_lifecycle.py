#!/usr/bin/env python3
"""Exercise the host-default lifecycle on a disposable console-access VM."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nord_tools_internal.nordvpn_host_executor import (  # noqa: E402
    activate_host_protection,
    deactivate_host_protection,
    preview_host_protection,
)
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan  # noqa: E402


def _read(path: str) -> dict:
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _command(*argv: str) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=15)
    if result.returncode:
        raise RuntimeError(f"baseline command {argv[0]!r} failed with exit {result.returncode}")
    return result.stdout


def _snapshot() -> dict:
    return {
        "links": json.loads(_command("ip", "-j", "link", "show")),
        "ipv4_routes": json.loads(_command("ip", "-4", "-j", "route", "show", "table", "all")),
        "ipv6_routes": json.loads(_command("ip", "-6", "-j", "route", "show", "table", "all")),
        "ipv4_rules": json.loads(_command("ip", "-4", "-j", "rule", "show")),
        "ipv6_rules": json.loads(_command("ip", "-6", "-j", "rule", "show")),
        "nftables": json.loads(_command("nft", "-j", "list", "ruleset")),
        "resolv_conf": Path("/etc/resolv.conf").read_text(encoding="utf-8"),
    }


def _without_counters(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _without_counters(item)
            for key, item in value.items()
            if key not in {"packets", "bytes", "handle", "metainfo"}
        }
    if isinstance(value, list):
        return [_without_counters(item) for item in value]
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, help="Executable host plan JSON")
    parser.add_argument("--store", required=True, help="Fresh durable host transaction store path")
    parser.add_argument("--private-key", help="WireGuard private-key file; required for privileged execution")
    parser.add_argument("--evidence-dir", help="Existing private directory receiving before/after evidence")
    parser.add_argument("--run-privileged", action="store_true", help="Run the host-mutating lifecycle")
    parser.add_argument(
        "--allow-host-egress-on-success",
        action="store_true",
        help="Permit verified deactivation to remove the deny barrier after a successful probe",
    )
    args = parser.parse_args(argv)
    try:
        plan = HostProtectionPlan.from_mapping(_read(args.plan))
    except (OSError, ValueError) as exc:
        parser.error(f"cannot read a valid host plan from {args.plan}: {exc}")
    if not args.run_privileged:
        print(json.dumps(preview_host_protection(plan), indent=2, sort_keys=True))
        return 0
    if os.geteuid() != 0:
        parser.error("--run-privileged requires root")
    if not args.private_key or not args.evidence_dir or not args.allow_host_egress_on_success:
        parser.error("privileged execution requires --private-key, --evidence-dir and --allow-host-egress-on-success")
    for filename, label in ((args.private_key, "private key"), (args.plan, "host plan")):
        if not Path(filename).is_file() or Path(filename).is_symlink():
            parser.error(f"{label} must be an existing ordinary file: {filename}")
    evidence_dir = Path(args.evidence_dir).absolute()
    info = evidence_dir.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        parser.error("evidence directory must be an existing root-owned mode 0700 directory")
    store = Path(args.store).absolute()
    if store.exists():
        parser.error("the lifecycle probe requires a fresh host store path")
    before = _snapshot()
    (evidence_dir / "before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    key_fd = os.open(args.private_key, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        active = activate_host_protection(plan, store, key_fd)
    finally:
        os.close(key_fd)
    (evidence_dir / "active.json").write_text(json.dumps(active, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if active["state"] != "active_verified":
        raise RuntimeError("tunnel did not become active; the verified deny barrier has been retained")
    retired = deactivate_host_protection(plan, store, expose_host_egress=True)
    after = _snapshot()
    (evidence_dir / "retired.json").write_text(json.dumps(retired, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (evidence_dir / "after.json").write_text(json.dumps(after, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if _without_counters(before) != _without_counters(after):
        raise RuntimeError("host state differs after verified retirement; evidence has been preserved")
    print(json.dumps({"result": "passed", "evidence_dir": str(evidence_dir)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
