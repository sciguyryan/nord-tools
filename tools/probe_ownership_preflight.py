#!/usr/bin/env python3
"""Opt-in privileged acceptance probe for ownership verification preflight.

No host routes, DNS, firewall rules or existing namespaces are modified. One
disposable namespace is created, its creation-time binding is recorded, and the
preflight must verify it. A deliberately mistaken interface binding must be
rejected, and one unverified claim must fail the whole batch. The namespace is
then retired and its recorded retirement must classify as consistent.

Run only the default dry-run description without privileges. Re-run
``sudo ip netns list`` afterwards; if anything remains, inspect it manually and
never delete a namespace based on its name alone.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nord_tools_internal.nordvpn_identity import allocate_identity  # noqa: E402
from nord_tools_internal.nordvpn_lifecycle import write_journal  # noqa: E402
from nord_tools_internal.nordvpn_lifecycle_store import transition_journal  # noqa: E402
from nord_tools_internal.nordvpn_discovery import DiscoveryError, discover  # noqa: E402
from nord_tools_internal.nordvpn_namespace_ownership import OwnershipError, disposable_namespace  # noqa: E402
from nord_tools_internal.nordvpn_ownership_verify import (  # noqa: E402
    initialise_bindings,
    preflight_ownership,
    read_bindings,
    record_binding,
)
from nord_tools_internal.nordvpn_registry import RegistryError  # noqa: E402


class ProbeError(RuntimeError):
    """An acceptance check failed; the resource is left for manual inspection."""


def describe() -> str:
    return (
        "Ownership preflight probe (dry run). The privileged run creates one\n"
        "disposable nt- namespace, records its device/inode binding while the\n"
        "creating process still holds the namespace descriptor, verifies the\n"
        "preflight classifies it as verified_current, records a deliberately\n"
        "mistaken interface binding and requires the preflight to reject it and\n"
        "fail the whole batch, then retires the namespace and requires its\n"
        "recorded retirement to classify as consistent_retired. No host routes,\n"
        "DNS or firewall state is modified."
    )


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def _finding(result: dict, allocation_id: str) -> dict:
    matching = [item for item in result["resources"] if item["allocation_id"] == allocation_id]
    if len(matching) != 1:
        raise ProbeError(f"preflight did not report allocation {allocation_id}")
    return matching[0]


def probe(*, confirmed: bool = False) -> None:
    """Run only after explicit opt-in."""
    if not confirmed:
        raise OwnershipError("explicit --run-privileged confirmation required")
    if sys.platform != "linux" or os.geteuid() != 0:
        raise OwnershipError("requires Linux and effective root privileges")
    if shutil.which("ip") is None:
        raise OwnershipError("iproute2 'ip' executable is required")

    with tempfile.TemporaryDirectory(prefix="nord-tools-ownership-preflight-") as workspace:
        base = Path(workspace)
        journal_path = base / "lifecycle.json"
        bindings_path = base / "owner-bindings.json"
        resource = allocate_identity("namespace", "nt-" + os.urandom(8).hex(), "probe")
        token, name = resource["allocation_id"], resource["identifier"]
        journal = {"version": 1, "allocations": {"version": 2, "resources": [resource]}, "events": []}
        write_journal(journal_path, journal)
        initialise_bindings(bindings_path)
        journal = transition_journal(journal_path, token, "reserved")
        journal = transition_journal(journal_path, token, "creating")

        print(f"Creating disposable namespace {name}; inspect /run/netns if interrupted", flush=True)
        with disposable_namespace(name) as owned:
            owned.verify()
            record_binding(bindings_path, journal, token, {"device": owned.device, "inode": owned.inode})
            journal = transition_journal(journal_path, token, "active")
            result = preflight_ownership(journal, read_bindings(bindings_path, journal), discover())
            finding = _finding(result, token)
            _assert(
                finding["finding"] == "verified_current" and finding["verified"] is True,
                f"verified binding was not accepted: {finding}",
            )
            _assert(
                result["ownership_verified"] and result["operator_review_required"] is False,
                "verified namespace did not pass the preflight batch",
            )
            print(f"PASS: creation-time binding verified for {name}", flush=True)

            # A binding the creator never actually established must never be
            # accepted, and one bad claim must fail the complete batch.
            foreign = allocate_identity("interface", "lo", "probe")
            expanded = {
                "version": 1,
                "allocations": {"version": 2, "resources": [resource, foreign]},
                "events": journal["events"],
            }
            write_journal(journal_path, expanded)
            journal = expanded
            record_binding(bindings_path, journal, foreign["allocation_id"], {"scope": name, "ifindex": 424242})
            result = preflight_ownership(journal, read_bindings(bindings_path, journal), discover())
            wrong = _finding(result, foreign["allocation_id"])
            _assert(
                wrong["finding"] == "identity_conflict" and wrong["verified"] is False,
                f"a mistaken interface binding was not rejected: {wrong}",
            )
            _assert(
                result["ownership_verified"] is False and result["operator_review_required"] is True,
                "one unverified claim did not fail the whole batch",
            )
            print("PASS: mistaken binding rejected and batch failed closed", flush=True)

        journal = transition_journal(journal_path, token, "retiring")
        journal = transition_journal(journal_path, token, "retired")
        snapshot = discover()
        _assert(name not in snapshot["namespaces"], f"namespace {name} was not retired")
        result = preflight_ownership(journal, read_bindings(bindings_path, journal), snapshot)
        retired = _finding(result, token)
        _assert(
            retired["finding"] == "consistent_retired" and retired["verified"] is True,
            f"recorded retirement was not classified consistently: {retired}",
        )
        print(f"PASS: retirement recorded consistently: {name}", flush=True)
        other_unclaimed = [item for item in result["unclaimed"]]
        print(f"Unclaimed observations reported separately: {len(other_unclaimed)} entries", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-privileged",
        action="store_true",
        help="Explicitly authorise one disposable namespace creation and retirement",
    )
    args = parser.parse_args(argv)
    try:
        if args.run_privileged:
            probe(confirmed=True)
        else:
            print(describe())
    except (OwnershipError, RegistryError, DiscoveryError, ProbeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
