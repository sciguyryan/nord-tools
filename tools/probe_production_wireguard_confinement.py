#!/usr/bin/env python3
"""Accept production WireGuard traffic, failure confinement and recovery.

The peer and underlay are disposable. Only the production executor installs the
client namespace, firewall, WireGuard interface, routes and pinned resolver. The
probe exercises establishment rollback, explicit recovery, loss and restart,
conservative readback refusal and verified retirement. It preserves failure
evidence rather than deleting uncertain resources.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup  # noqa: E402
from nord_tools_internal.nordvpn_discovery import discover  # noqa: E402
from nord_tools_internal.nordvpn_dns_confinement import (  # noqa: E402
    DNSConfinementError,
    verify_dns_routes,
    verify_resolver_file,
)
from nord_tools_internal.nordvpn_isolation_install import (  # noqa: E402
    IsolationInstallError,
    _verify_base_chains,
)
from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy  # noqa: E402
from nord_tools_internal.nordvpn_ownership_verify import preflight_ownership  # noqa: E402
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy  # noqa: E402
from nord_tools_internal import nordvpn_restore_executor as restore_executor  # noqa: E402
from nord_tools_internal.nordvpn_recovery_executor import plan_recovery  # noqa: E402
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state  # noqa: E402
from tools.probe_live_tunnel_replacement import (  # noqa: E402
    attach_underlay_to_peer,
    command,
    read,
    start_dns_responder,
    tunnel_plan,
    write,
)
from tools.production_application_dns import (  # noqa: E402
    verify_application_dns,
    verify_dns_unavailable,
    verify_underlay_bypass,
)
from tools.probe_wireguard_host_integrity import observe as observe_host  # noqa: E402
from tools.probe_wireguard_host_integrity import verify as verify_host  # noqa: E402


class AcceptanceError(RuntimeError):
    """An observed production profile failed its integrated acceptance contract."""


@dataclass(frozen=True)
class ProductionConfinementContext:
    """Live production fixture details exposed to a composed acceptance stage."""

    temporary: Path
    config: dict
    namespace: str
    interface: str
    server_namespace: str
    peer_interface: str
    peer_public_key: str


ApplicationExperiment = Callable[[ProductionConfinementContext], None]


def owned_namespace(config: dict) -> tuple[str, str, str]:
    """Identify the exact namespace, WireGuard and underlay from durable bindings."""
    journal = read(Path(config["journal"]))
    bindings = read(Path(config["bindings"]))
    intents = read(Path(config["intent"]))
    status = preflight_ownership(journal, bindings, discover(), intents)
    states = {event["allocation_id"]: event["state"] for event in journal["events"]}
    active = {token for token, state in states.items() if state == "active"}
    findings = {item["allocation_id"]: item["finding"] for item in status["resources"]}
    if status["operator_review_required"] or any(findings.get(token) != "verified_current" for token in active):
        raise AcceptanceError("production ownership could not be verified")
    verified = {token for token in active if findings.get(token) == "verified_current"}
    resources = {
        item["allocation_id"]: item for item in journal["allocations"]["resources"] if item["allocation_id"] in verified
    }
    identified: dict[str, list[str]] = {"namespace": [], "wireguard": [], "underlay": []}
    for item in bindings["bindings"]:
        if item["allocation_id"] not in verified:
            continue
        resource = resources[item["allocation_id"]]
        if resource["kind"] == "namespace":
            identified["namespace"].append(item["identifier"])
        elif resource["kind"] == "interface" and item["binding"].get("scope") != "host":
            scope = item["binding"]["scope"]
            if scope not in {
                binding["identifier"]
                for binding in bindings["bindings"]
                if binding["kind"] == "namespace" and binding["allocation_id"] in verified
            }:
                raise AcceptanceError("interface binding refers to an unexpected namespace")
            group = "wireguard" if item["identifier"].startswith("ntwg") else "underlay"
            identified[group].append(item["identifier"])
    if any(len(values) != 1 for values in identified.values()):
        raise AcceptanceError("production resources do not identify exactly one owned profile")
    return identified["namespace"][0], identified["wireguard"][0], identified["underlay"][0]


def verify_profile_absent(config: dict) -> None:
    """Require rollback to remove every resource named by the failed attempt."""
    journal = read(Path(config["journal"]))
    observation = discover()
    namespaces = set(observation.get("namespaces", ()))
    host_interfaces = {item["name"] for item in observation.get("host_interfaces", ())}
    namespace_interfaces = {
        item["name"] for details in observation.get("namespace_details", ()) for item in details.get("interfaces", ())
    }
    for resource in journal["allocations"]["resources"]:
        identifier = resource["identifier"]
        if resource["kind"] == "namespace" and identifier in namespaces:
            raise AcceptanceError("failed establishment left its namespace present")
        if resource["kind"] == "interface" and identifier in host_interfaces | namespace_interfaces:
            raise AcceptanceError("failed establishment left an interface present")
    intents = read(Path(config["intent"]))
    if not any(item["outcome"] == "uncertain" for item in intents["operations"]):
        raise AcceptanceError("failed establishment did not retain uncertain recovery evidence")


def verify_failed_establishment(config: dict, baseline: dict) -> None:
    """Fail after WireGuard configuration, then require complete real-kernel rollback."""
    kernel = restore_executor._real_kernel()

    def refuse_routing(*_args, **_kwargs):
        raise AcceptanceError("injected route establishment failure")

    try:
        restore_boot_state(config, kernel=replace(kernel, route_tunnel=refuse_routing))
    except AcceptanceError as exc:
        if str(exc) != "injected route establishment failure":
            raise
    else:
        raise AcceptanceError("injected establishment failure was not propagated")
    verify_profile_absent(config)
    verify_host(baseline, observe_host())
    print("PASS: failed production establishment rolled back without host drift", flush=True)

    recovery = plan_recovery(
        config["journal"],
        config["bindings"],
        config["intent"],
        execute=True,
        resolvers=True,
    )
    if recovery["operator_review_required"] or not recovery["executed"]:
        raise AcceptanceError("explicit recovery did not close the rolled-back generation")
    print("PASS: explicit recovery closed the uncertain rolled-back generation", flush=True)


def verify_fail_closed(namespace: str, server_namespace: str, port: int) -> None:
    """Require both DNS families and reachable underlay transports to remain closed."""
    for family, address in ((4, "10.214.10.1"), (6, "fd42:214::1")):
        for protocol in ("udp", "tcp"):
            verify_underlay_bypass(
                namespace,
                server_namespace,
                address,
                port,
                family=family,
                protocol=protocol,
            )
    verify_dns_unavailable(namespace, "10.250.0.1", family=4)
    verify_dns_unavailable(namespace, "fd42:250::1", family=6)


def verify_uncertain_readbacks(
    namespace: str,
    firewall: NamespaceIsolationPolicy,
    resolver: NamespaceResolverPolicy,
    temporary: Path,
) -> None:
    """Require malformed firewall and unsafe resolver observations to be refused."""
    fake_bin = temporary / "malformed-readback-bin"
    fake_bin.mkdir(mode=0o700)
    fake_nft = fake_bin / "nft"
    fake_nft.write_text("#!/bin/sh\nprintf '%s\\n' '{malformed-json'\n", encoding="ascii")
    fake_nft.chmod(0o700)
    original_path = os.environ.get("PATH")
    os.environ["PATH"] = str(fake_bin) + (os.pathsep + original_path if original_path else "")
    try:
        try:
            _verify_base_chains(namespace, firewall)
        except IsolationInstallError:
            pass
        else:
            raise AcceptanceError("malformed firewall readback was accepted")
    finally:
        if original_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = original_path

    resolver_path = Path("/etc/netns") / namespace / "resolv.conf"
    extra_link = resolver_path.with_name("uncertain-resolver-link")
    os.link(resolver_path, extra_link)
    try:
        try:
            verify_resolver_file(namespace, resolver)
        except DNSConfinementError:
            pass
        else:
            raise AcceptanceError("multiply linked resolver readback was accepted")
    finally:
        extra_link.unlink()
    _verify_base_chains(namespace, firewall)
    verify_resolver_file(namespace, resolver)
    print("PASS: malformed firewall and uncertain resolver readbacks were refused", flush=True)


def verify_tunnel(namespace: str, interface: str, peer_public: str, *, timeout: float = 15) -> None:
    """Require pinned routes and live traffic within a bounded handshake window."""
    actual = command("ip", "netns", "exec", namespace, "wg", "show", interface, "peers").decode()
    if actual.strip() != peer_public:
        raise AcceptanceError("production WireGuard peer differs from pinned plan")
    for family, destination in (("-4", "10.250.0.1"), ("-6", "fd42:250::1")):
        route = command("ip", "-n", namespace, family, "route", "get", destination).decode()
        if f"dev {interface}" not in route:
            raise AcceptanceError(f"{family} route does not use the production WireGuard interface")
        deadline = time.monotonic() + timeout
        while True:
            result = subprocess.run(
                ["ip", "netns", "exec", namespace, "ping", family, "-c", "1", "-W", "2", destination],
                capture_output=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise AcceptanceError(f"production {family} tunnel traffic did not recover within {timeout:g} seconds")
            time.sleep(1)


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


def run_probe(
    *,
    applications: dict | None = None,
    application_experiment: ApplicationExperiment | None = None,
) -> None:
    token = secrets.token_hex(3)
    peer_interface = f"ntpr{token}"
    server_namespace = f"ntsrv{token}"
    bridge = f"ntbr{token}"
    server_host = f"ntvh{token}"
    server_link = f"ntvs{token}"
    temporary = Path(tempfile.mkdtemp(prefix="nt-production-wg-"))
    if applications:
        temporary.chmod(0o755)
    baseline = observe_host()
    dns_responder: subprocess.Popen | None = None
    dns_responder_v6: subprocess.Popen | None = None
    succeeded = False
    config: dict | None = None
    restoration_attempted = False
    retired = False
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
        command("ip", "-n", server_namespace, "-6", "address", "add", "fd42:214::1/64", "dev", server_link)
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
        # The existing IPv4 responder proves packet-level DNS. The IPv6
        # responder supplies the same deterministic NXDOMAIN response for a
        # real application-level DNS exchange over the second tunnel family.
        dns6_script = r"""
import socket
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind(('fd42:250::1', 53))
print('READY', flush=True)
while True:
    query, peer = sock.recvfrom(4096)
    if len(query) >= 12:
        response = query[:2] + b'\x81\x83' + query[4:6] + b'\x00' * 6 + query[12:]
        sock.sendto(response, peer)
"""
        dns_responder_v6 = subprocess.Popen(
            ["ip", "netns", "exec", server_namespace, sys.executable, "-I", "-c", dns6_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if dns_responder_v6.stdout is None or dns_responder_v6.stdout.readline().strip() != "READY":
            raise AcceptanceError("IPv6 DNS responder did not become ready")
        policy_path = temporary / "policy.json"
        write(
            policy_path,
            {
                "version": 1,
                "defaults": {"vpn": "alpha"},
                "vpn_profiles": {"alpha": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
                "applications": applications or {},
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
                    **tunnel_plan(
                        "10.214.10.1",
                        ("10.250.0.2/32", "fd42:250::2/128"),
                        10,
                        peer_public,
                    ),
                    "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
                }
            },
            "credentials": {"alpha": str(client_key)},
        }
        write(temporary / "startup.json", config)
        restoration_attempted = True
        # Exercise a real late provisioning failure after the production
        # firewall, underlay and WireGuard device exist. Rollback must leave
        # only durable uncertainty, without changing unrelated host state.
        profile_baseline = observe_host()
        verify_failed_establishment(config, profile_baseline)
        # Boot recovery resolves the certified-absent failed generation before
        # creating a new production generation from the same pinned plan.
        restore_boot_state(config)
        command("ip", "netns", "exec", server_namespace, "wg", "set", peer_interface, "listen-port", "0")
        attach_underlay_to_peer(config, "alpha", bridge, "10.214.10.1/30")
        # The second underlay family is deliberately available to the peer.
        # A successful leak attempt must therefore be observable, not merely unroutable.
        command("ip", "-n", server_namespace, "-6", "route", "get", "fd42:214::1")
        namespace, interface, underlay = owned_namespace(config)
        # Provide a real connected IPv6 underlay route. Otherwise an IPv6
        # bypass test could pass simply because no IPv6 path existed.
        command("ip", "-n", namespace, "-6", "address", "add", "fd42:214::2/64", "dev", underlay)
        firewall = NamespaceIsolationPolicy(interface, underlay, "10.214.10.1", 51820)
        _verify_base_chains(namespace, firewall)
        resolver = NamespaceResolverPolicy(("10.250.0.1",))
        verify_resolver_file(namespace, resolver)
        verify_dns_routes(namespace, interface, resolver)
        # The underlay is live and reachable, but the peer cannot establish.
        # The installed production policy must not fall back to that path.
        verify_fail_closed(namespace, server_namespace, 53051)
        print("PASS: unavailable peer establishment remained fail closed", flush=True)
        command(
            "ip",
            "netns",
            "exec",
            server_namespace,
            "wg",
            "set",
            peer_interface,
            "listen-port",
            "51820",
        )
        # Both address families must exchange live packets. Route presence on
        # its own is not evidence that the peer can return tunnel traffic.
        verify_tunnel(namespace, interface, peer_public)
        verify_endpoint_port(namespace, server_namespace)
        if application_experiment is not None:
            application_experiment(
                ProductionConfinementContext(
                    temporary=temporary,
                    config=config,
                    namespace=namespace,
                    interface=interface,
                    server_namespace=server_namespace,
                    peer_interface=peer_interface,
                    peer_public_key=peer_public,
                )
            )
        verify_application_dns(namespace, "10.250.0.1", family=4)
        verify_application_dns(namespace, "fd42:250::1", family=6)
        print("PASS: production-owned applications received valid IPv4 and IPv6 DNS replies")
        for family, address in ((4, "10.214.10.1"), (6, "fd42:214::1")):
            for protocol in ("udp", "tcp"):
                verify_underlay_bypass(
                    namespace,
                    server_namespace,
                    address,
                    53053,
                    family=family,
                    protocol=protocol,
                )
        print("PASS: production-owned application UDP and TCP underlay bypass refused")
        for family, address in ((4, "10.214.10.1"), (6, "fd42:214::1")):
            for protocol in ("udp", "tcp"):
                verify_underlay_bypass(
                    namespace,
                    server_namespace,
                    address,
                    53,
                    family=family,
                    protocol=protocol,
                )
        print("PASS: alternate underlay DNS destinations refused for both families and transports")
        verify_uncertain_readbacks(namespace, firewall, resolver, temporary)
        # After a live session has been established, stop only the peer's
        # WireGuard listener. The production namespace retains its firewall,
        # routes and resolver while the encrypted transport is unavailable.
        command("ip", "netns", "exec", server_namespace, "wg", "set", peer_interface, "listen-port", "0")
        verify_fail_closed(namespace, server_namespace, 53054)
        print("PASS: tunnel shutdown refused application DNS and underlay fallback")
        command(
            "ip",
            "netns",
            "exec",
            server_namespace,
            "wg",
            "set",
            peer_interface,
            "listen-port",
            "51820",
        )
        verify_tunnel(namespace, interface, peer_public)
        verify_application_dns(namespace, "10.250.0.1", family=4)
        verify_application_dns(namespace, "fd42:250::1", family=6)
        print("PASS: owned tunnel restart restored IPv4, IPv6 and application DNS", flush=True)
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
        retired = True
        if any(
            item["identifier"] in discover().get("namespaces", ())
            for item in read(Path(config["journal"]))["allocations"]["resources"]
            if item["kind"] == "namespace"
        ):
            raise AcceptanceError("production namespace survived verified retirement")
        dns_responder.terminate()
        dns_responder.wait(timeout=5)
        dns_responder = None
        dns_responder_v6.terminate()
        dns_responder_v6.wait(timeout=5)
        dns_responder_v6 = None
        command("ip", "netns", "del", server_namespace)
        command("ip", "link", "del", bridge)
        verify_host(baseline, observe_host())
        succeeded = True
        print("PASS: one production-owned WireGuard profile, firewall, routes, DNS, live traffic and retirement")
    finally:
        # A failing traffic assertion must not strand a production-owned namespace.
        # Retire only resources verified by the existing ownership-aware executor;
        # retain the journal and other evidence when a probe fails.
        if restoration_attempted and not retired and config is not None:
            try:
                result = plan_cleanup(
                    config["journal"],
                    config["bindings"],
                    intent_path=config["intent"],
                    selected_profiles=("alpha",),
                    resolvers=True,
                    execute=True,
                )
                if not result["executed"]:
                    print("FAIL: recovery cleanup did not execute; evidence retained", file=sys.stderr)
                else:
                    print("PASS: failure-path ownership-aware retirement completed", flush=True)
            except (OSError, RuntimeError, ValueError) as exc:
                print(f"FAIL: failure-path ownership-aware retirement: {exc}", file=sys.stderr)
        if dns_responder is not None:
            dns_responder.terminate()
            dns_responder.wait(timeout=5)
        if dns_responder_v6 is not None:
            dns_responder_v6.terminate()
            dns_responder_v6.wait(timeout=5)
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
