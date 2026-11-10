#!/usr/bin/env python3
"""Accept the host-default lifecycle against a disposable real WireGuard peer.

The probe creates a private static IPv4 underlay and peer namespace, then lets
the production host executor install every host-side firewall, WireGuard,
routing and resolver object. Its deny barrier intentionally interrupts remote
management until verified retirement, so privileged execution requires a
disposable guest with console access.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import select
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_host_executor import (  # noqa: E402
    HostProtectionError,
    activate_host_protection,
    deactivate_host_protection,
    host_protection_status,
    recover_host_protection,
)
from nord_tools_internal.nordvpn_host_linux import linux_host_kernel  # noqa: E402
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan  # noqa: E402
from nord_tools_internal.nordvpn_host_store import read_host_store  # noqa: E402
from tools.probe_wireguard_host_integrity import observe as observe_host  # noqa: E402
from tools.probe_wireguard_host_integrity import verify as verify_host  # noqa: E402


class HostAcceptanceError(RuntimeError):
    """The live host-domain protection contract was not demonstrated."""


DNS_CLIENT = r"""
import socket
import sys

address, family = sys.argv[1:]
family = socket.AF_INET6 if family == '6' else socket.AF_INET
transaction = b'\x44\x31'
name = b'\x08nordhost\x07invalid\x00'
question = transaction + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + name + b'\x00\x01\x00\x01'
with socket.socket(family, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.sendto(question, (address, 53))
    response, source = sock.recvfrom(4096)
if source[0] != address or response[:4] != transaction + b'\x81\x83':
    sys.exit(2)
if response[4:12] != b'\x00\x01' + b'\x00' * 6 or response[12:] != question[12:]:
    sys.exit(3)
"""


DNS_RESPONDER = r"""
import json
from pathlib import Path
import selectors
import socket
import sys

log = Path(sys.argv[1])
selector = selectors.DefaultSelector()
for family, address in ((socket.AF_INET, '10.77.0.1'), (socket.AF_INET6, 'fd42:77::1')):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((address, 53))
    selector.register(sock, selectors.EVENT_READ, address)
print('READY', flush=True)
while True:
    for key, _ in selector.select():
        query, peer = key.fileobj.recvfrom(4096)
        if len(query) < 12:
            continue
        response = query[:2] + b'\x81\x83' + query[4:6] + b'\x00' * 6 + query[12:]
        key.fileobj.sendto(response, peer)
        with log.open('a', encoding='utf-8') as target:
            target.write(json.dumps({'server': key.data, 'peer': peer[0]}) + '\n')
            target.flush()
"""


UNDERLAY_LISTENER = r"""
import socket
import struct
import sys
import time

interface, address, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
    sock.bind((interface, 0))
    sock.settimeout(3)
    print('READY', flush=True)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            frame = sock.recv(65535)
        except socket.timeout:
            break
        if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != socket.IPPROTO_UDP:
            continue
        header_length = (frame[14] & 0x0f) * 4
        udp = 14 + header_length
        if len(frame) < udp + 4:
            continue
        destination = socket.inet_ntoa(frame[30:34])
        destination_port = struct.unpack('!H', frame[udp + 2:udp + 4])[0]
        if destination == address and destination_port == port:
            sys.exit(3)
    sys.exit(0)
"""


UNDERLAY_SENDER = r"""
import socket
import sys

source, address, port, mark = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    sock.bind((source, 0))
    try:
        sock.sendto(b'forbidden', (address, port))
    except OSError:
        pass
"""


HANDSHAKE_DRIVER = r"""
import subprocess
import time

while True:
    for family, address in (('-4', '10.77.0.1'), ('-6', 'fd42:77::1')):
        subprocess.run(['ping', family, '-c', '1', '-W', '1', address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.1)
"""


def command(*arguments: str, input_data: bytes | None = None, timeout: float = 15) -> bytes:
    result = subprocess.run(arguments, input=input_data, capture_output=True, check=False, timeout=timeout)
    if result.returncode:
        detail = result.stderr.decode(errors="replace").strip()[-800:]
        raise HostAcceptanceError(
            f"command failed ({result.returncode}): {' '.join(arguments)}: {detail or 'no stderr'}"
        )
    return result.stdout.strip()


def write_json(path: Path, document: object) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def snapshot() -> dict:
    return {
        "links": json.loads(command("ip", "-j", "link", "show")),
        "ipv4_rules": json.loads(command("ip", "-4", "-j", "rule", "show")),
        "ipv6_rules": json.loads(command("ip", "-6", "-j", "rule", "show")),
        "ipv4_routes": json.loads(command("ip", "-4", "-j", "route", "show", "table", "all")),
        "ipv6_routes": json.loads(command("ip", "-6", "-j", "route", "show", "table", "all")),
        "nftables": json.loads(command("nft", "-j", "list", "ruleset")),
        "resolver": Path("/etc/resolv.conf").read_text(encoding="utf-8"),
    }


def without_runtime_values(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: without_runtime_values(item)
            for key, item in value.items()
            if key not in {"packets", "bytes", "handle", "metainfo", "expires"}
        }
    if isinstance(value, list):
        return [without_runtime_values(item) for item in value]
    return value


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stdout is not None:
        process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()


def start_dns_responder(namespace: str, log: Path) -> subprocess.Popen:
    process = subprocess.Popen(
        ["ip", "netns", "exec", namespace, sys.executable, "-I", "-c", DNS_RESPONDER, str(log)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdout is None or process.stdout.readline().strip() != "READY":
        detail = process.stderr.read(400) if process.stderr is not None else ""
        stop_process(process)
        raise HostAcceptanceError(f"dual-stack DNS responder did not start: {detail.strip()}")
    return process


def verify_dns(address: str, family: int) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-c", DNS_CLIENT, address, str(family)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode:
        raise HostAcceptanceError(f"IPv{family} host DNS exchange failed (exit {result.returncode})")


def verify_dns_unavailable(address: str, family: int) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-c", DNS_CLIENT, address, str(family)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode == 0:
        raise HostAcceptanceError(f"IPv{family} host DNS unexpectedly succeeded without the tunnel")


def dns_event_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except FileNotFoundError:
        return 0


def verify_resolved_packet_path(log: Path, token: str) -> None:
    before = dns_event_count(log)
    query_name = f"{token}.d1.nordtools"
    result = subprocess.run(
        ["resolvectl", "query", "--type=A", query_name],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    deadline = time.monotonic() + 5
    while dns_event_count(log) == before and time.monotonic() < deadline:
        time.sleep(0.1)
    if dns_event_count(log) == before:
        raise HostAcceptanceError(
            f"systemd-resolved sent no packet to the pinned tunnel resolvers (exit {result.returncode})"
        )


def verify_underlay_refused(
    namespace: str,
    peer_link: str,
    source: str,
    address: str,
    port: int,
    mark: int,
) -> None:
    listener = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            namespace,
            sys.executable,
            "-I",
            "-c",
            UNDERLAY_LISTENER,
            peer_link,
            address,
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if listener.stdout is None or listener.stdout.readline().strip() != "READY":
            raise HostAcceptanceError("underlay refusal listener did not become ready")
        subprocess.run(
            [sys.executable, "-I", "-c", UNDERLAY_SENDER, source, address, str(port), str(mark)],
            capture_output=True,
            check=False,
            timeout=10,
        )
        if listener.wait(timeout=6) != 0:
            raise HostAcceptanceError(f"unauthorised underlay datagram reached {address}:{port}")
    finally:
        stop_process(listener)


def verify_routes(interface: str) -> None:
    for family, destination in (("-4", "10.77.0.1"), ("-6", "fd42:77::1")):
        route = command("ip", family, "route", "get", destination).decode()
        if f"dev {interface}" not in route:
            raise HostAcceptanceError(f"{family} host policy route did not select {interface}")
        deadline = time.monotonic() + 15
        while True:
            result = subprocess.run(
                ["ping", family, "-c", "1", "-W", "2", destination],
                capture_output=True,
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise HostAcceptanceError(f"{family} host tunnel traffic did not recover")
            time.sleep(0.5)


def activate_with_key(plan: HostProtectionPlan, store: Path, key: Path) -> dict:
    key_fd = os.open(key, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return activate_host_protection(plan, store, key_fd)
    finally:
        os.close(key_fd)


def set_peer_listener(namespace: str, interface: str, port: int) -> None:
    command(
        "ip",
        "netns",
        "exec",
        namespace,
        "wg",
        "set",
        interface,
        "listen-port",
        str(port),
    )


def expect_host_refusal(operation, label: str) -> None:
    try:
        operation()
    except HostProtectionError:
        return
    raise HostAcceptanceError(f"{label} was accepted despite uncertain readback")


def verify_uncertain_host_readbacks(plan: HostProtectionPlan, store: Path, evidence_dir: Path) -> None:
    original_path = os.environ.get("PATH")
    fake_bin = evidence_dir / "uncertain-readback-bin"
    fake_bin.mkdir(mode=0o700)
    fake_nft = fake_bin / "nft"
    fake_nft.write_text("#!/bin/sh\nprintf '%s\\n' '{malformed-json'\n", encoding="ascii")
    fake_nft.chmod(0o700)
    os.environ["PATH"] = str(fake_bin) + (os.pathsep + original_path if original_path else "")
    before = store.read_bytes()
    try:
        expect_host_refusal(
            lambda: deactivate_host_protection(plan, store, expose_host_egress=True),
            "malformed firewall observation",
        )
    finally:
        if original_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = original_path
    if store.read_bytes() != before:
        raise HostAcceptanceError("firewall inspection failure changed durable host state")
    if host_protection_status(plan, store)["ordinary_host_egress_blocked"] is not True:
        raise HostAcceptanceError("firewall inspection failure weakened the host barrier")

    fake_nft.unlink()
    fake_resolvectl = fake_bin / "resolvectl"
    fake_resolvectl.write_text("#!/bin/sh\nprintf '%s\\n' 'malformed resolver output'\n", encoding="ascii")
    fake_resolvectl.chmod(0o700)
    os.environ["PATH"] = str(fake_bin) + (os.pathsep + original_path if original_path else "")
    try:
        expect_host_refusal(
            lambda: deactivate_host_protection(plan, store, expose_host_egress=True),
            "malformed resolver observation",
        )
    finally:
        if original_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = original_path
    if host_protection_status(plan, store)["ordinary_host_egress_blocked"] is not True:
        raise HostAcceptanceError("resolver inspection failure weakened the host barrier")


def interrupt_deactivation_before_routes(plan: HostProtectionPlan, store: Path) -> None:
    reader, writer = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        kernel = linux_host_kernel(plan)

        def pause_before_routes(_plan: HostProtectionPlan, _evidence: dict) -> dict:
            os.write(writer, b"READY\n")
            while True:
                signal.pause()

        try:
            deactivate_host_protection(
                plan,
                store,
                expose_host_egress=True,
                kernel=replace(kernel, remove_routes=pause_before_routes),
            )
        except BaseException:
            os._exit(2)
        os._exit(3)
    os.close(writer)
    try:
        ready, _, _ = select.select([reader], [], [], 15)
        if not ready or os.read(reader, 64) != b"READY\n":
            raise HostAcceptanceError("deactivation worker did not reach the route checkpoint")
        os.kill(pid, signal.SIGKILL)
        waited, status = os.waitpid(pid, 0)
        if waited != pid or not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
            raise HostAcceptanceError("deactivation worker did not terminate at the checkpoint")
    finally:
        os.close(reader)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass


def run_failure_recovery_lifecycle(
    *,
    plan: HostProtectionPlan,
    store: Path,
    client_key: Path,
    evidence_dir: Path,
    namespace: str,
    peer_link: str,
    peer_wireguard: str,
    host_wireguard: str,
    endpoint_port: int,
    fwmark: int,
) -> dict:
    handshake_process: subprocess.Popen | None = None
    try:
        set_peer_listener(namespace, peer_wireguard, 0)
        handshake_process = subprocess.Popen(
            [sys.executable, "-I", "-c", HANDSHAKE_DRIVER],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        unavailable = activate_with_key(plan, store, client_key)
        write_json(evidence_dir / "failed-activation-status.json", unavailable)
        if (
            unavailable["state"] != "protected_tunnel_unavailable"
            or unavailable["ordinary_host_egress_blocked"] is not True
        ):
            raise HostAcceptanceError("unavailable peer did not retain verified host protection")
        verify_dns_unavailable("10.77.0.1", 4)
        verify_dns_unavailable("fd42:77::1", 6)
        verify_underlay_refused(namespace, peer_link, "192.0.2.2", "192.0.2.1", endpoint_port + 1, fwmark)

        set_peer_listener(namespace, peer_wireguard, endpoint_port)
        active = activate_with_key(plan, store, client_key)
        write_json(evidence_dir / "recovered-activation-status.json", active)
        if active["state"] != "active_verified" or active["ordinary_host_egress_blocked"] is not True:
            raise HostAcceptanceError("host activation did not recover after the peer became available")
        stop_process(handshake_process)
        handshake_process = None
        verify_routes(host_wireguard)
        verify_dns("10.77.0.1", 4)
        verify_dns("fd42:77::1", 6)

        set_peer_listener(namespace, peer_wireguard, 0)
        verify_dns_unavailable("10.77.0.1", 4)
        verify_dns_unavailable("fd42:77::1", 6)
        verify_underlay_refused(namespace, peer_link, "192.0.2.2", "192.0.2.1", endpoint_port + 1, fwmark)
        lost = host_protection_status(plan, store)
        write_json(evidence_dir / "tunnel-loss-status.json", lost)
        if lost["ordinary_host_egress_blocked"] is not True:
            raise HostAcceptanceError("real tunnel loss weakened the host barrier")

        set_peer_listener(namespace, peer_wireguard, endpoint_port)
        verify_routes(host_wireguard)
        verify_dns("10.77.0.1", 4)
        verify_dns("fd42:77::1", 6)
        verify_uncertain_host_readbacks(plan, store, evidence_dir)

        resolver_recovery = recover_host_protection(plan, store, execute=False)
        write_json(evidence_dir / "resolver-recovery-preview.json", resolver_recovery)
        if resolver_recovery["findings"] != [{"step": "remove_resolver", "observed": "present"}]:
            raise HostAcceptanceError("resolver uncertainty did not retain the expected recovery finding")
        if resolver_recovery["automatic_barrier_removal"] is not False:
            raise HostAcceptanceError("resolver recovery unexpectedly authorised barrier removal")
        resolver_recovery = recover_host_protection(plan, store, execute=True)
        write_json(evidence_dir / "resolver-recovery-executed.json", resolver_recovery)

        interrupt_deactivation_before_routes(plan, store)
        interrupted_store = read_host_store(store)
        write_json(evidence_dir / "interrupted-deactivation-store.json", interrupted_store)
        states = {item["name"]: item["state"] for item in interrupted_store["record"]["steps"]}
        if states.get("remove_resolver") != "absent" or states.get("remove_routes") != "pending":
            raise HostAcceptanceError("process death did not retain the expected retirement boundary")
        interrupted = host_protection_status(plan, store)
        write_json(evidence_dir / "interrupted-deactivation-status.json", interrupted)
        if interrupted["ordinary_host_egress_blocked"] is not True:
            raise HostAcceptanceError("process death removed the host barrier before recovery")

        route_recovery = recover_host_protection(plan, store, execute=False)
        write_json(evidence_dir / "route-recovery-preview.json", route_recovery)
        if route_recovery["findings"] != [{"step": "remove_routes", "observed": "present"}]:
            raise HostAcceptanceError("route interruption did not retain the expected recovery finding")
        route_recovery = recover_host_protection(plan, store, execute=True)
        write_json(evidence_dir / "route-recovery-executed.json", route_recovery)
        if route_recovery["automatic_barrier_removal"] is not False:
            raise HostAcceptanceError("route recovery unexpectedly authorised barrier removal")

        retired = deactivate_host_protection(plan, store, expose_host_egress=True)
        write_json(evidence_dir / "retired-status.json", retired)
        if retired["state"] != "absent" or retired["ordinary_host_egress_blocked"] is not False:
            raise HostAcceptanceError("recovered deactivation did not retire the barrier last")
        return retired
    finally:
        stop_process(handshake_process)


def verify_disposable_veth_retired(host_link: str, expected_ifindex: int, *, timeout: float = 2.0) -> None:
    """Confirm namespace retirement removed its veth peer without a stale-name delete.

    Removing a network namespace destroys its veth endpoint and ordinarily its
    paired host endpoint. A second ``ip link del`` is both unnecessary and
    unsafe: the name may already be absent or have been reused by another actor.
    Require successful full-link enumeration and reject unexpected identity.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            links = json.loads(command("ip", "-j", "link", "show"))
        except (ValueError, TypeError) as exc:
            raise HostAcceptanceError("cannot verify disposable host veth retirement") from exc
        if not isinstance(links, list) or any(
            not isinstance(link, dict) or not isinstance(link.get("ifname"), str) for link in links
        ):
            raise HostAcceptanceError("invalid host link inventory after namespace retirement")
        matches = [link for link in links if link["ifname"] == host_link]
        if not matches:
            return
        if len(matches) != 1 or matches[0].get("ifindex") != expected_ifindex:
            raise HostAcceptanceError("disposable host veth identity changed; refusing deletion")
        if time.monotonic() >= deadline:
            raise HostAcceptanceError("disposable host veth still exists after namespace retirement")
        time.sleep(0.1)


def run_probe(evidence_dir: Path, *, phase: str = "d1") -> dict:
    if phase not in {"d1", "d2"}:
        raise ValueError("host acceptance phase must be d1 or d2")
    token = secrets.token_hex(3)
    namespace = f"nthp{token}"
    host_link = f"nthh{token}"
    peer_link = f"nthv{token}"
    host_wireguard = f"nthw{token}"
    peer_wireguard = f"nthpwg{token}"
    endpoint_port = 51821
    fwmark = 51900
    store = evidence_dir / "host-store.json"
    dns_log = evidence_dir / "dns-events.jsonl"
    client_key = evidence_dir / "client.key"
    peer_key = evidence_dir / "peer.key"
    dns_process: subprocess.Popen | None = None
    handshake_process: subprocess.Popen | None = None
    activated = False
    retired = False
    original = observe_host()
    original_links = json.loads(command("ip", "-j", "link", "show"))
    try:
        client_private = command("wg", "genkey")
        peer_private = command("wg", "genkey")
        client_public = command("wg", "pubkey", input_data=client_private + b"\n").decode()
        peer_public = command("wg", "pubkey", input_data=peer_private + b"\n").decode()
        client_key.write_bytes(client_private + b"\n")
        peer_key.write_bytes(peer_private + b"\n")
        client_key.chmod(0o600)
        peer_key.chmod(0o600)

        command("ip", "netns", "add", namespace)
        command("ip", "link", "add", host_link, "type", "veth", "peer", "name", peer_link)
        command("ip", "link", "set", peer_link, "netns", namespace)
        command("ip", "link", "set", host_link, "addrgenmode", "none")
        command("ip", "-n", namespace, "link", "set", peer_link, "addrgenmode", "none")
        command("ip", "address", "add", "192.0.2.2/29", "dev", host_link)
        command("ip", "link", "set", host_link, "up")
        command("ip", "-n", namespace, "link", "set", "lo", "up")
        command("ip", "-n", namespace, "address", "add", "192.0.2.1/29", "dev", peer_link)
        command("ip", "-n", namespace, "address", "add", "192.0.2.3/29", "dev", peer_link)
        command("ip", "-n", namespace, "link", "set", peer_link, "up")
        command("ip", "-n", namespace, "link", "add", peer_wireguard, "type", "wireguard")
        command("ip", "-n", namespace, "address", "add", "10.77.0.1/24", "dev", peer_wireguard)
        command("ip", "-n", namespace, "address", "add", "fd42:77::1/64", "dev", peer_wireguard)
        command(
            "ip",
            "netns",
            "exec",
            namespace,
            "wg",
            "set",
            peer_wireguard,
            "private-key",
            str(peer_key),
            "listen-port",
            str(endpoint_port),
            "peer",
            client_public,
            "allowed-ips",
            "10.77.0.2/32,fd42:77::2/128",
        )
        command("ip", "-n", namespace, "link", "set", peer_wireguard, "up")
        dns_process = start_dns_responder(namespace, dns_log)
        egress_ifindex = int(command("cat", f"/sys/class/net/{host_link}/ifindex").decode())
        plan = HostProtectionPlan.from_mapping(
            {
                "generation": f"{phase}-{token}",
                "interface": host_wireguard,
                "peer_public_key": peer_public,
                "endpoint_address": "192.0.2.1",
                "endpoint_port": endpoint_port,
                "tunnel_addresses": ["10.77.0.2/32", "fd42:77::2/128"],
                "dns_servers": ["10.77.0.1", "fd42:77::1"],
                "egress_interface": host_link,
                "egress_ifindex": egress_ifindex,
                "egress_source_address": "192.0.2.2",
                "route_table": 51900,
                "endpoint_rule_priority": 100,
                "tunnel_rule_priority": 110,
                "fwmark": fwmark,
                "resolver_mode": "systemd-resolved",
                "firewall_family": "inet",
                "firewall_table": "nord_tools_host",
                "firewall_priority": -200,
                "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
                "version": 1,
            }
        )
        fixture_baseline = snapshot()
        write_json(evidence_dir / "fixture-baseline.json", fixture_baseline)
        if phase == "d2":
            activated = True
            retired_status = run_failure_recovery_lifecycle(
                plan=plan,
                store=store,
                client_key=client_key,
                evidence_dir=evidence_dir,
                namespace=namespace,
                peer_link=peer_link,
                peer_wireguard=peer_wireguard,
                host_wireguard=host_wireguard,
                endpoint_port=endpoint_port,
                fwmark=fwmark,
            )
            checks = [
                "failed activation retained the deny barrier",
                "real tunnel loss refused DNS and underlay fallback",
                "peer restart restored dual-stack traffic",
                "uncertain firewall and resolver readback refused mutation",
                "SIGKILL interruption retained route and barrier evidence",
                "explicit recovery resumed barrier-last deactivation",
                "host integrity restoration",
            ]
            scope = "D2 host-domain failure and recovery acceptance"
        else:
            handshake_process = subprocess.Popen(
                [sys.executable, "-I", "-c", HANDSHAKE_DRIVER],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            active = activate_with_key(plan, store, client_key)
            activated = True
            write_json(evidence_dir / "active-status.json", active)
            write_json(evidence_dir / "active-snapshot.json", snapshot())
            if active["state"] != "active_verified" or active["ordinary_host_egress_blocked"] is not True:
                raise HostAcceptanceError("host protection did not reach its verified active state")
            stop_process(handshake_process)
            handshake_process = None

            verify_routes(host_wireguard)
            verify_dns("10.77.0.1", 4)
            verify_dns("fd42:77::1", 6)
            verify_resolved_packet_path(dns_log, token)
            verify_underlay_refused(namespace, peer_link, "192.0.2.2", "192.0.2.1", endpoint_port + 1, fwmark)
            verify_underlay_refused(namespace, peer_link, "192.0.2.2", "192.0.2.3", endpoint_port, fwmark)

            retired_status = deactivate_host_protection(plan, store, expose_host_egress=True)
            checks = [
                "deny-first production activation",
                "pinned marked endpoint exception",
                "IPv4 and IPv6 host policy routing",
                "dual-stack tunnel DNS exchange",
                "systemd-resolved tunnel packet path",
                "barrier-last verified retirement",
                "host integrity restoration",
            ]
            scope = "D1 host-domain static-egress acceptance"
        retired = True
        write_json(evidence_dir / "retired-status.json", retired_status)
        after_retirement = snapshot()
        write_json(evidence_dir / "retired-snapshot.json", after_retirement)
        if without_runtime_values(fixture_baseline) != without_runtime_values(after_retirement):
            raise HostAcceptanceError("verified host retirement did not restore the fixture baseline")

        stop_process(dns_process)
        dns_process = None
        command("ip", "netns", "del", namespace)
        verify_disposable_veth_retired(host_link, egress_ifindex)
        verify_host(original, observe_host())
        final_links = json.loads(command("ip", "-j", "link", "show"))
        if without_runtime_values(original_links) != without_runtime_values(final_links):
            raise HostAcceptanceError("disposable peer links survived the accepted host lifecycle")
        report = {
            "result": "passed",
            "scope": scope,
            "generation": plan.generation,
            "evidence_dir": str(evidence_dir),
            "checks": checks,
        }
        write_json(evidence_dir / "result.json", report)
        return report
    finally:
        stop_process(handshake_process)
        stop_process(dns_process)
        if retired:
            # The normal path has already verified peer retirement. Never issue
            # a second name-based link deletion from the finaliser.
            subprocess.run(["ip", "netns", "del", namespace], capture_output=True, check=False)
        elif activated:
            print(
                "FAIL: verified host protection remains active; use the guest console for evidence-led recovery",
                file=sys.stderr,
                flush=True,
            )
        elif not store.exists():
            # Only the namespace created by this probe is eligible for best-effort
            # cleanup. Namespace deletion also retires the paired host veth.
            subprocess.run(["ip", "netns", "del", namespace], capture_output=True, check=False)


def validated_evidence_directory(value: str | None, *, phase: str = "d1") -> Path:
    if value is None:
        return Path(tempfile.mkdtemp(prefix=f"nt-host-{phase}-", dir="/var/tmp"))
    path = Path(value).absolute()
    if path.exists():
        raise HostAcceptanceError("evidence directory must not already exist")
    path.mkdir(mode=0o700, parents=False)
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise HostAcceptanceError("evidence directory must be root-owned mode 0700")
    return path


def main(argv: list[str] | None = None, *, phase: str = "d1") -> int:
    if phase not in {"d1", "d2"}:
        raise ValueError("host acceptance phase must be d1 or d2")
    description = __doc__ if phase == "d1" else "Accept host-default failure and recovery guarantees."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument("--evidence-dir")
    parser.add_argument("--result", help="Optional result JSON written after verified retirement")
    parser.add_argument("--startup-delay", type=float, default=0.0, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not args.run_privileged:
        if phase == "d1":
            print("DRY RUN: D1 host-domain barrier, endpoint, dual-stack route, DNS and retirement acceptance")
        else:
            print("DRY RUN: D2 host-domain failure, interruption, recovery and barrier-last retirement acceptance")
        print("Privileged execution intentionally interrupts remote guest management while the barrier is active.")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error(f"privileged {phase.upper()} acceptance requires Linux root")
    missing = [name for name in ("ip", "wg", "nft", "ping", "resolvectl") if shutil.which(name) is None]
    if missing:
        parser.error("missing prerequisites: " + ", ".join(missing))
    if args.startup_delay < 0 or args.startup_delay > 30:
        parser.error("--startup-delay must be between zero and 30 seconds")
    time.sleep(args.startup_delay)
    evidence_dir: Path | None = None
    try:
        evidence_dir = validated_evidence_directory(args.evidence_dir, phase=phase)
        report = run_probe(evidence_dir, phase=phase)
        if args.result:
            write_json(Path(args.result), report)
        print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        if args.result:
            write_json(
                Path(args.result),
                {
                    "result": "failed",
                    "scope": (
                        "D1 host-domain static-egress acceptance"
                        if phase == "d1"
                        else "D2 host-domain failure and recovery acceptance"
                    ),
                    "error": str(exc),
                    "evidence_dir": str(evidence_dir) if evidence_dir is not None else None,
                },
            )
        print(f"FAIL: {exc}", file=sys.stderr, flush=True)
        if evidence_dir is not None:
            print(f"FAILED RUN EVIDENCE RETAINED: {evidence_dir}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
