#!/usr/bin/env python3
"""Opt-in E2 acceptance using four private, operator-supplied provider configurations.

The probe restores one default shared profile, one named shared profile and two
isolated application allocations through the production executor. It requires
a disposable supported guest. Private inputs and derived keys are never printed
or retained as failure artefacts.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_allocation_profiles import expand_allocation_profiles  # noqa: E402
from nord_tools_internal.nordvpn_application_executor import launch_provisioned_application  # noqa: E402
from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup  # noqa: E402
from nord_tools_internal.nordvpn_discovery import discover  # noqa: E402
from nord_tools_internal.nordvpn_provider import (  # noqa: E402
    import_provider_configuration,
    load_provider_catalogue,
    read_provider_configuration,
)
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state  # noqa: E402
from nord_tools_internal.nordvpn_runtime_consumers import (  # noqa: E402
    initialise_runtime_consumers,
    read_runtime_consumers,
)
from nord_tools_internal.nordvpn_startup import validate_startup_config  # noqa: E402
from tools.probe_wireguard_host_integrity import observe, verify  # noqa: E402


class ProbeError(RuntimeError):
    """The provider workflow did not satisfy its acceptance contract."""


def command(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=20)
    if check and result.returncode:
        raise ProbeError(f"fixture command failed: {arguments[0]}")
    return result


def parse_configuration(value: str) -> tuple[str, Path]:
    server, separator, filename = value.partition("=")
    if not separator or not server or not filename:
        raise argparse.ArgumentTypeError("use SERVER=/private/path.conf")
    return server, Path(filename)


def install_forwarding_fixture() -> str:
    if command(["nft", "list", "table", "ip", "nord_tools_e2_fixture"], check=False).returncode == 0:
        raise ProbeError("the E2 forwarding fixture table already exists")
    previous = command(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip()
    if previous not in {"0", "1"}:
        raise ProbeError("IPv4 forwarding state is indeterminate")
    command(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
    try:
        command(["nft", "add", "table", "ip", "nord_tools_e2_fixture"])
        command(
            [
                "nft",
                "add",
                "chain",
                "ip",
                "nord_tools_e2_fixture",
                "postrouting",
                "{ type nat hook postrouting priority srcnat; policy accept; }",
            ]
        )
        command(
            [
                "nft",
                "add",
                "rule",
                "ip",
                "nord_tools_e2_fixture",
                "postrouting",
                "ip",
                "saddr",
                "10.216.0.0/16",
                "masquerade",
            ]
        )
    except BaseException:
        command(["nft", "delete", "table", "ip", "nord_tools_e2_fixture"], check=False)
        command(["sysctl", "-q", "-w", f"net.ipv4.ip_forward={previous}"], check=False)
        raise
    return previous


def remove_forwarding_fixture(previous: str) -> None:
    error = None
    try:
        command(["nft", "delete", "table", "ip", "nord_tools_e2_fixture"])
    except BaseException as exc:
        error = exc
    try:
        command(["sysctl", "-q", "-w", f"net.ipv4.ip_forward={previous}"])
    except BaseException as exc:
        error = error or exc
    if error is not None:
        raise error


def active_namespaces(root: Path) -> dict[str, tuple[str, str]]:
    journal = json.loads((root / "lifecycle.json").read_text(encoding="utf-8"))
    states = {event["allocation_id"]: event["state"] for event in journal["events"]}
    grouped: dict[str, dict[str, str]] = {}
    for item in journal["allocations"]["resources"]:
        if states.get(item["allocation_id"]) != "active":
            continue
        record = grouped.setdefault(item["profile"], {})
        if item["kind"] == "namespace":
            record["namespace"] = item["identifier"]
        elif item["kind"] == "interface" and item["identifier"].startswith("ntwg"):
            record["interface"] = item["identifier"]
    if any(set(record) != {"namespace", "interface"} for record in grouped.values()):
        raise ProbeError("an active provider allocation lacks one namespace or WireGuard interface")
    return {profile: (record["namespace"], record["interface"]) for profile, record in grouped.items()}


def verify_live_provider(namespaces: dict[str, tuple[str, str]]) -> None:
    for profile, (namespace, interface) in sorted(namespaces.items()):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            dns = command(["ip", "netns", "exec", namespace, "getent", "ahostsv4", "example.com"], check=False)
            handshake = command(
                ["ip", "netns", "exec", namespace, "wg", "show", interface, "latest-handshakes"], check=False
            )
            timestamps = [int(line.split()[-1]) for line in handshake.stdout.splitlines() if line.split()]
            if dns.returncode == 0 and any(timestamp > 0 for timestamp in timestamps):
                break
            time.sleep(1)
        else:
            raise ProbeError(f"provider traffic did not become live for allocation {profile}")


def run_probe(
    configurations: list[tuple[str, Path]],
    uid: int,
    gid: int,
    benchmark_report: Path,
    max_report_age_seconds: int,
) -> None:
    if len(configurations) < 4 or len({server for server, _ in configurations}) != len(configurations):
        raise ProbeError("four distinct provider configurations are required")
    if len({path.resolve() for _, path in configurations}) != len(configurations):
        raise ProbeError("provider configuration files must be distinct")
    baseline = observe()
    root = Path(tempfile.mkdtemp(prefix="nt-provider-e2-"))
    root.chmod(0o700)
    forwarding = None
    restored = False
    failure = None
    try:
        catalogue_path = root / "provider-catalogue.json"
        canonical_servers = []
        for index, (server, source) in enumerate(configurations):
            imported = import_provider_configuration(
                read_provider_configuration(source),
                server=server,
                catalogue_path=catalogue_path,
                credential_path=root / f"provider-{index}.key",
                execute=True,
            )
            canonical_servers.append(imported["server"])
        catalogue = load_provider_catalogue(catalogue_path)
        if any(entry["endpoint_address"].count(":") for entry in catalogue["servers"]):
            raise ProbeError("E2 currently accepts provider configurations with IPv4 endpoints only")
        entries = {entry["server"]: entry for entry in catalogue["servers"]}
        ordered = [entries[server] for server in canonical_servers]
        policy = {
            "version": 1,
            "defaults": {"vpn": "primary"},
            "vpn_profiles": {
                "primary": {"selection": {"mode": "pinned", "server": ordered[0]["server"]}},
                "shared": {"selection": {"mode": "country", "country": ordered[1]["country"]}},
                "isolated": {
                    "selection": {"mode": "fastest", "filter": "protocol:udp"},
                    "sharing": "isolated",
                },
            },
            "applications": {
                "default_app": {"executable": "/usr/bin/true", "vpn": "primary"},
                "shared_app": {"executable": "/usr/bin/true", "vpn": "shared"},
                "isolated_a": {"executable": "/usr/bin/true", "vpn": "isolated"},
                "isolated_b": {"executable": "/usr/bin/true", "vpn": "isolated"},
            },
        }
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        effective, _ = expand_allocation_profiles(policy)
        tunnels = {
            name: {
                "underlay": {
                    "namespace_address": f"10.216.{index}.2/30",
                    "host_address": f"10.216.{index}.1/30",
                }
            }
            for index, name in enumerate(sorted(effective["vpn_profiles"]), start=1)
        }
        startup = validate_startup_config(
            {
                "version": 1,
                "policy": str(policy_path),
                "journal": str(root / "lifecycle.json"),
                "bindings": str(root / "owner-bindings.json"),
                "intent": str(root / "operation-intents.json"),
                "run_record": str(root / "startup-runs.json"),
                "tunnels": tunnels,
                "provider": {
                    "catalogue": str(catalogue_path),
                    "benchmark_report": str(benchmark_report.resolve()),
                    "max_report_age_seconds": max_report_age_seconds,
                },
            }
        )
        forwarding = install_forwarding_fixture()
        result = restore_boot_state(startup)
        if set(result["restored"]) != set(effective["vpn_profiles"]):
            raise ProbeError("the complete provider allocation set was not restored")
        if len({item["server"] for item in result["provider_selections"].values()}) != 4:
            raise ProbeError("provider identities were reused across concurrent allocations")
        namespaces = active_namespaces(root)
        verify_live_provider(namespaces)
        print("PASS: default, shared and isolated provider tunnels carried live DNS", flush=True)
        runtime = root / "runtime-consumers.json"
        initialise_runtime_consumers(runtime, policy)
        for application in sorted(policy["applications"]):
            status = launch_provisioned_application(
                policy,
                application,
                (),
                runtime_consumers=str(runtime),
                journal_path=startup["journal"],
                bindings_path=startup["bindings"],
                intent_path=startup["intent"],
                observe=discover,
                uid=uid,
                gid=gid,
            )
            if status != 0:
                raise ProbeError(f"registered application failed for {application}")
        if read_runtime_consumers(runtime, policy)["leases"]:
            raise ProbeError("an exited provider application retained a lease")
        print("PASS: registered default, shared and isolated applications used verified allocations", flush=True)
        repeat = restore_boot_state(startup)
        if repeat["restored"] or not repeat["reconciled"]:
            raise ProbeError("provider restoration was not idempotent")
        cleanup = plan_cleanup(
            startup["journal"],
            startup["bindings"],
            intent_path=startup["intent"],
            resolvers=True,
            execute=True,
        )
        if len(cleanup["deletions"]) != 16:
            raise ProbeError("provider workflow did not retire exactly four complete allocations")
        restored = True
        print("PASS: repeat restoration and complete provider retirement were deterministic", flush=True)
    except BaseException as exc:
        failure = exc
    finally:
        if not restored and all(
            (root / name).exists() for name in ("lifecycle.json", "owner-bindings.json", "operation-intents.json")
        ):
            try:
                plan_cleanup(
                    root / "lifecycle.json",
                    root / "owner-bindings.json",
                    intent_path=root / "operation-intents.json",
                    resolvers=True,
                    execute=True,
                )
            except BaseException as exc:
                failure = failure or exc
        for credential in root.glob("provider-*.key"):
            credential.unlink(missing_ok=True)
        if forwarding is not None:
            try:
                remove_forwarding_fixture(forwarding)
            except BaseException as exc:
                failure = failure or exc
        try:
            verify(baseline, observe())
        except BaseException as exc:
            failure = failure or exc
        if restored and failure is None:
            shutil.rmtree(root)
        else:
            print(f"Retained secret-free E2 diagnostic state: {root}", file=sys.stderr)
    if failure is not None:
        raise ProbeError(str(failure)) from failure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument(
        "--provider-config",
        action="append",
        type=parse_configuration,
        default=[],
        metavar="SERVER=/PRIVATE/CONFIG",
        help="private root-owned provider configuration; supply four or more distinct entries",
    )
    parser.add_argument("--uid", type=int, help="existing non-root application user")
    parser.add_argument("--gid", type=int, help="existing non-root application group")
    parser.add_argument("--benchmark-report", type=Path, help="fresh version 1 report containing the imported servers")
    parser.add_argument("--max-report-age-seconds", type=int, default=86400)
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: would exercise four distinct real provider configurations in a disposable guest.")
        print("No provider configuration is read and no networking is changed.")
        return 0
    if os.geteuid() != 0 or not args.uid or not args.gid or args.benchmark_report is None:
        parser.error("Linux root, --uid/--gid and --benchmark-report are required")
    missing = [name for name in ("getent", "ip", "nft", "sysctl", "wg") if shutil.which(name) is None]
    if missing:
        parser.error("missing prerequisites: " + ", ".join(missing))
    try:
        run_probe(
            args.provider_config,
            args.uid,
            args.gid,
            args.benchmark_report,
            args.max_report_age_seconds,
        )
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("PASS: E2 provider workflow acceptance", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
