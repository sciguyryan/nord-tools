#!/usr/bin/env python3
"""Verify disposable namespace resolver visibility without changing host DNS.

Requires root and iproute2 only with --execute. Does not contact a DNS server.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

# Direct invocation from the repository root should find the project package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nord_tools_internal.nordvpn_resolver_install import (  # noqa: E402
    install_namespace_resolver,
    remove_namespace_resolver,
)
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy  # noqa: E402


class ProbeError(RuntimeError):
    """A namespace resolver invariant could not be verified."""


def digest(path: Path) -> str:
    """Hash host resolver bytes without interpreting its configuration."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=check)


def probe(name: str, *, root: Path = Path("/etc/netns"), host_resolver: Path = Path("/etc/resolv.conf")) -> None:
    """Install and observe a namespace-only resolver; always attempt owned cleanup."""
    policy = NamespaceResolverPolicy(("1.1.1.1", "2606:4700:4700::1111"))
    expected = policy.render_resolv_conf()
    before = digest(host_resolver)
    namespace_created = False
    installed = None
    failure: BaseException | None = None
    try:
        run(["ip", "netns", "add", name])
        namespace_created = True
        installed = install_namespace_resolver(name, policy, root=root)
        # ip netns exec bind-mounts /etc/netns/NAME/resolv.conf over /etc/resolv.conf.
        observed = run(["ip", "netns", "exec", name, "cat", "/etc/resolv.conf"]).stdout
        if observed != expected:
            raise ProbeError("namespace process did not observe the configured resolver")
        if digest(host_resolver) != before:
            raise ProbeError("host resolver content changed during namespace execution")
        print("PASS: namespace process sees only its configured resolver file")
        print("PASS: host resolver content unchanged during namespace execution")
    except BaseException as exc:
        failure = exc
    finally:
        if installed is not None:
            try:
                remove_namespace_resolver(installed)
            except BaseException as exc:
                print(f"WARNING: resolver cleanup failed: {exc}", file=sys.stderr)
                if failure is None:
                    failure = exc
        if namespace_created:
            result = run(["ip", "netns", "del", name], check=False)
            if result.returncode:
                print(f"WARNING: namespace cleanup failed: {result.stderr.strip()}", file=sys.stderr)
                if failure is None:
                    failure = ProbeError("namespace cleanup failed")
        if digest(host_resolver) != before:
            failure = ProbeError("host resolver content changed")
    if failure is not None:
        raise failure
    if (root / name).exists():
        raise ProbeError("namespace resolver directory remains after cleanup")
    print("PASS: owned namespace resolver and network namespace cleaned up")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="Run disposable privileged namespace verification")
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: would create a disposable network namespace, install its own resolver,")
        print("verify process-visible DNS configuration and unchanged host resolver, then clean up.")
        print("Does not test DNS connectivity, tunnel routing, or leak prevention.")
        return 0
    if os.geteuid() != 0:
        parser.error("--execute requires root")
    if shutil.which("ip") is None:
        parser.error("iproute2 is required")
    if not Path("/etc/netns").is_dir():
        parser.error("/etc/netns must exist and be a trusted root-owned directory")
    name = "vpnres-" + secrets.token_hex(4)
    try:
        probe(name)
    except (OSError, ProbeError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
