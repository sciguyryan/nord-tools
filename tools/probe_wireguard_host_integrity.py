#!/usr/bin/env python3
"""Opt-in real WireGuard regression with read-only host-network integrity checks.

This reuses the disposable two-pair experiment. It is not a DNS delivery test,
production firewall integration, or proof of leak-free VPN operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import difflib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.probe_two_wireguard import HarnessError, experiment  # noqa: E402


class IntegrityError(RuntimeError):
    """Host state changed or an integrity observation could not be completed."""


OBSERVATIONS = (
    ("IPv4 host routes", ("ip", "-4", "route", "show", "table", "all")),
    ("IPv6 host routes", ("ip", "-6", "route", "show", "table", "all")),
    ("host nftables ruleset", ("nft", "-j", "-a", "list", "ruleset")),
)


def normalise_nft(value: object) -> object:
    """Remove volatile kernel metadata without discarding firewall policy.

    JSON counter expressions contain live packet/byte statistics. Retain the
    counter expression itself, and preserve all other expression attributes.
    Handles are kernel-assigned object identifiers, not policy definitions.
    """
    if isinstance(value, list):
        return [normalise_nft(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == "handle":
                continue
            if key == "counter" and isinstance(item, dict):
                result[key] = {
                    name: normalise_nft(entry) for name, entry in item.items() if name not in {"packets", "bytes"}
                }
            else:
                result[key] = normalise_nft(item)
        return result
    return value


def nft_policy(raw: str) -> str:
    """Produce deterministic, order-preserving policy evidence from nft JSON."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"Cannot parse host nftables JSON: {exc}") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("nftables"), list):
        raise IntegrityError("Unexpected host nftables JSON structure")
    return json.dumps(normalise_nft(parsed), sort_keys=True, indent=2, ensure_ascii=True)


def observe() -> dict[str, str]:
    """Read host state without changing any host network configuration."""
    evidence: dict[str, str] = {}
    for label, command in OBSERVATIONS:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode:
            raise IntegrityError(f"Cannot inspect {label}: {result.stderr.strip()}")
        if label == "host nftables ruleset":
            evidence[label] = nft_policy(result.stdout)
        else:
            evidence[label] = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
    resolver = Path("/etc/resolv.conf")
    try:
        evidence["host resolver contents"] = hashlib.sha256(resolver.read_bytes()).hexdigest()
    except OSError as exc:
        raise IntegrityError(f"Cannot inspect host resolver: {exc}") from exc
    return evidence


def verify(before: dict[str, str], after: dict[str, str]) -> None:
    """Fail if any required observation differs or is absent."""
    if before.keys() != after.keys():
        raise IntegrityError("Host observation set changed")
    for label in before:
        if before[label] != after[label]:
            if label == "host nftables ruleset":
                difference = list(
                    difflib.unified_diff(
                        before[label].splitlines(),
                        after[label].splitlines(),
                        fromfile="before/nftables",
                        tofile="after/nftables",
                        lineterm="",
                    )
                )
                detail = "\n".join(difference[:80])
                if len(difference) > 80:
                    detail += "\n... difference truncated"
                raise IntegrityError(f"Host state changed during disposable experiment: {label}\n{detail}")
            raise IntegrityError(f"Host state changed during disposable experiment: {label}")
        print(f"PASS: {label} unchanged across disposable WireGuard experiment")


def probe(token: str) -> None:
    """Verify host state even if the disposable WireGuard experiment fails."""
    before = observe()
    failure: Exception | None = None
    try:
        experiment(token)
    except (HarnessError, subprocess.CalledProcessError) as exc:
        failure = exc
    after = observe()
    verify(before, after)
    if failure is not None:
        raise IntegrityError(f"Disposable WireGuard experiment failed: {failure}") from failure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute", action="store_true", help="Run a privileged disposable two-pair WireGuard experiment"
    )
    args = parser.parse_args(argv)
    if not args.execute:
        print("DRY RUN: would execute the existing disposable two-pair WireGuard harness")
        print("and compare host routes, nftables rules and resolver contents before and after.")
        print("Does not verify real-tunnel DNS confinement or production fail-closed integration.")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("--execute requires Linux root")
    missing = [tool for tool in ("ip", "wg", "nft", "ping") if shutil.which(tool) is None]
    if missing:
        parser.error("Missing prerequisites: " + ", ".join(missing))
    try:
        probe(secrets.token_hex(3))
    except (IntegrityError, HarnessError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
