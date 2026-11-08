#!/usr/bin/env python3
"""Accept one real WireGuard profile installed by the production restoration executor.

The peer and underlay are disposable. Only the production executor installs the
client namespace, firewall, WireGuard interface, routes and pinned resolver.
The probe preserves failure evidence rather than deleting uncertain resources.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup  # noqa: E402
from nord_tools_internal.nordvpn_discovery import discover  # noqa: E402
from nord_tools_internal.nordvpn_isolation_install import _verify_base_chains  # noqa: E402
from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy  # noqa: E402
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership  # noqa: E402
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy  # noqa: E402
from nord_tools_internal.nordvpn_dns_confinement import verify_dns_routes, verify_resolver_file  # noqa: E402
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state  # noqa: E402
from tools.probe_live_tunnel_replacement import (  # noqa: E402
    attach_underlay_to_peer,
    command,
    read,
    start_dns_responder,
    tunnel_plan,
    write,
)
from tools.probe_wireguard_host_integrity import observe as observe_host  # noqa: E402
from tools.probe_wireguard_host_integrity import verify as verify_host  # noqa: E402


class AcceptanceError(RuntimeError):
    """An observed production profile failed its integrated acceptance contract."""


def owned_namespace(config: dict) -> tuple[str, str, str]:
    """Identify the exact namespace, WireGuard and underlay from durable bindings."""
    journal = read(Path(config["journal"]))
    bindings = read(Path(config["bindings"]))
    intents = read(Path(config["intent"]))
    status = preflight_ownership(journal, bindings, discover(), intents)
    if status["operator_review_required"] or any(
        resource["finding"] != "verified_current" for resource in status["resources"]
    ):
        raise AcceptanceError("production ownership could not be verified")
    resources = {item["allocation_id"]: item for item in journal["allocations"]["resources"]}
    identified: dict[str, list[str]] = {"namespace": [], "wireguard": [], "underlay": []}
    for item in bindings["bindings"]:
        resource = resources[item["allocation_id"]]
        if resource["kind"] == "namespace":
            identified["namespace"].append(item["identifier"])
        elif resource["kind"] == "interface" and item["binding"].get("scope") != "host":
            scope = item["binding"]["scope"]
            if scope not in {
                binding["identifier"] for binding in bindings["bindings"] if binding["kind"] == "namespace"
            }:
                raise AcceptanceError("interface binding refers to an unexpected namespace")
            group = "wireguard" if item["identifier"].startswith("ntwg") else "underlay"
            identified[group].append(item["identifier"])
    if any(len(values) != 1 for values in identified.values()):
        raise AcceptanceError("production resources do not identify exactly one owned profile")
    return identified["namespace"][0], identified["wireguard"][0], identified["underlay"][0]


def verify_tunnel(namespace: str, interface: str, peer_public: str) -> None:
    actual = command("ip", "netns", "exec", namespace, "wg", "show", interface, "peers").decode()
    if actual.strip() != peer_public:
        raise AcceptanceError("production WireGuard peer differs from pinned plan")
    for family, destination in (("-4", "10.250.0.1"), ("-6", "fd42:250::1")):
        route = command("ip", "-n", namespace, family, "route", "get", destination).decode()
        if f"dev {interface}" not in route:
            raise AcceptanceError(f"{family} route does not use the production WireGuard interface")
        try:
            command("ip", "netns", "exec", namespace, "ping", family, "-c", "2", "-W", "3", destination)
        except subprocess.CalledProcessError as exc:
            raise AcceptanceError(f"production {family} tunnel traffic did not succeed") from exc


def verify_endpoint_port(namespace: str, server_namespace: str) -> None:
    """Prove non-endpoint UDP cannot reach the peer's underlay listener."""
    listener = """import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.214.10.1',51002));s.settimeout(3)
print('READY',flush=True)
try:s.recvfrom(128)
except socket.timeout:sys.exit(0)
sys.exit(3)
"""
    receiver = subprocess.Popen(
        ["ip", "netns", "exec", server_namespace, sys.executable, "-I", "-c", listener],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if receiver.stdout is None or receiver.stdout.readline().strip() != "READY":
            raise AcceptanceError("endpoint exception listener did not start")
        sender = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                sys.executable,
                "-I",
                "-c",
                "import socket;socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'forbidden',('10.214.10.1',51002))",
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
        # A blocked send may return success or a policy error; actual delivery is decisive.
        if (
            sender.returncode
            and b"Operation not permitted" not in sender.stderr
            and b"Network is unreachable" not in sender.stderr
        ):
            raise AcceptanceError("endpoint exception sender failed unexpectedly")
        if receiver.wait(timeout=6):
            raise AcceptanceError("application UDP escaped via the WireGuard endpoint on an unauthorised port")
    finally:
        if receiver.poll() is None:
            receiver.kill()
            receiver.wait(timeout=5)
        if receiver.stdout:
            receiver.stdout.close()
        if receiver.stderr:
            receiver.stderr.close()


def run_probe() -> None:
    token = secrets.token_hex(3)
    peer_interface = f"ntpr{token}"
    server_namespace = f"ntsrv{token}"
    bridge = f"ntbr{token}"
    server_host = f"ntvh{token}"
    server_link = f"ntvs{token}"
    temporary = Path(tempfile.mkdtemp(prefix="nt-production-wg-"))
    baseline = observe_host()
    dns_responder: subprocess.Popen | None = None
    succeeded = False
    try:
        peer_private = command("wg", "genkey")
        client_private = command("wg", "genkey")
        peer_public = command("wg", "pubkey", input_data=peer_private + b"\n").decode()
        client_public = command("wg", "pubkey", input_data=client_private + b"\n").decode()
        peer_key = temporary / "peer.key"
        client_key = temporary / "client.key"
        peer_key.write_bytes(peer_private + b"\n")
        client_key.write_bytes(client_private + b"\n")
        peer_key.chmod(0o600)
        client_key.chmod(0o600)
        command("ip", "netns", "add", server_namespace)
        command("ip", "link", "add", bridge, "type", "bridge")
        command("ip", "link", "set", bridge, "up")
        command("ip", "link", "add", server_host, "type", "veth", "peer", "name", server_link)
        command("ip", "link", "set", server_link, "netns", server_namespace)
        command("ip", "link", "set", server_host, "master", bridge)
        command("ip", "link", "set", server_host, "up")
        command("ip", "-n", server_namespace, "link", "set", "lo", "up")
        command("ip", "-n", server_namespace, "link", "set", server_link, "up")
        command("ip", "-n", server_namespace, "address", "add", "10.214.10.1/30", "dev", server_link)
        command("ip", "-n", server_namespace, "link", "add", peer_interface, "type", "wireguard")
        command("ip", "-n", server_namespace, "address", "add", "10.250.0.1/24", "dev", peer_interface)
        command("ip", "-n", server_namespace, "address", "add", "fd42:250::1/64", "dev", peer_interface)
        command(
            "ip",
            "netns",
            "exec",
            server_namespace,
            "wg",
            "set",
            peer_interface,
            "private-key",
            str(peer_key),
            "listen-port",
            "51820",
            "peer",
            client_public,
            "allowed-ips",
            "10.250.0.2/32,fd42:250::2/128",
        )
        command("ip", "-n", server_namespace, "link", "set", peer_interface, "up")
        dns_responder = start_dns_responder(server_namespace)
        policy_path = temporary / "policy.json"
        write(
            policy_path,
            {
                "version": 1,
                "defaults": {"vpn": "alpha"},
                "vpn_profiles": {"alpha": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
                "applications": {},
            },
        )
        config = {
            "version": 1,
            "policy": str(policy_path),
            "journal": str(temporary / "journal.json"),
            "bindings": str(temporary / "bindings.json"),
            "intent": str(temporary / "intents.json"),
            "run_record": str(temporary / "runs.json"),
            "tunnels": {
                "alpha": {
                    **tunnel_plan("10.214.10.1", "10.250.0.2/32", 10, peer_public),
                    "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
                    "tunnel_address": "10.250.0.2/32",
                }
            },
            "credentials": {"alpha": str(client_key)},
        }
        # An IPv6 route alone is insufficient. The live IPv6 ping below must
        # succeed or the probe fails, exposing the production address gap.
        write(temporary / "startup.json", config)
        restore_boot_state(config)
        attach_underlay_to_peer(config, "alpha", bridge, "10.214.10.1/30")
        namespace, interface, underlay = owned_namespace(config)
        _verify_base_chains(namespace, NamespaceIsolationPolicy(interface, underlay, "10.214.10.1", 51820))
        resolver = NamespaceResolverPolicy(("10.250.0.1",))
        verify_resolver_file(namespace, resolver)
        verify_dns_routes(namespace, interface, resolver)
        verify_tunnel(namespace, interface, peer_public)
        verify_endpoint_port(namespace, server_namespace)
        result = plan_cleanup(
            config["journal"],
            config["bindings"],
            intent_path=config["intent"],
            selected_profiles=("alpha",),
            resolvers=True,
            execute=True,
        )
        if not result["executed"]:
            raise AcceptanceError("ownership-aware retirement was not executed")
        if any(
            item["identifier"] in discover().get("namespaces", ())
            for item in read(Path(config["journal"]))["allocations"]["resources"]
            if item["kind"] == "namespace"
        ):
            raise AcceptanceError("production namespace survived verified retirement")
        dns_responder.terminate()
        dns_responder.wait(timeout=5)
        dns_responder = None
        command("ip", "netns", "del", server_namespace)
        command("ip", "link", "del", bridge)
        verify_host(baseline, observe_host())
        succeeded = True
        print("PASS: one production-owned WireGuard profile, firewall, routes, DNS, live traffic and retirement")
    finally:
        if dns_responder is not None:
            dns_responder.terminate()
            dns_responder.wait(timeout=5)
        subprocess.run(["ip", "netns", "del", server_namespace], capture_output=True, check=False)
        subprocess.run(["ip", "link", "del", bridge], capture_output=True, check=False)
        if succeeded:
            shutil.rmtree(temporary)
        else:
            print(f"FAILED RUN EVIDENCE RETAINED: {temporary}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: production-owned WireGuard integration, traffic, endpoint and retirement")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("privileged acceptance requires Linux root")
    missing = [name for name in ("ip", "wg", "nft", "ping") if shutil.which(name) is None]
    if missing:
        parser.error("missing prerequisites: " + ", ".join(missing))
    try:
        run_probe()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
