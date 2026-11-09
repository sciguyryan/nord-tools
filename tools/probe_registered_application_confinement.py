#!/usr/bin/env python3
"""Accept concurrent registered direct and VPN-bound packet behaviour.

The production restoration path owns the VPN namespace, WireGuard interface,
firewall, routes and resolver. A VPN-bound child launched through the durable
lease gate performs the traffic checks itself while a registered direct child
continues to use the host namespace. The same children remain alive through
peer loss and recovery.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_profiles import validate_policy  # noqa: E402
from nord_tools_internal.nordvpn_runtime_consumers import (  # noqa: E402
    initialise_runtime_consumers,
    read_runtime_consumers,
)
from tools.production_application_dns import UNDERLAY_LISTENER  # noqa: E402
from tools.probe_live_tunnel_replacement import (  # noqa: E402
    finish_launch,
    launch,
    stop_launch,
    verify_launch_evidence,
    wait_for_report,
)
from tools.probe_production_wireguard_confinement import (  # noqa: E402
    ProductionConfinementContext,
    command,
    run_probe as run_production_probe,
    verify_tunnel,
)


class RegisteredConfinementError(RuntimeError):
    """The registered application packet contract was not demonstrated."""


CHILD_SOURCE = r"""import json
import os
from pathlib import Path
import socket
import sys
import time


def dns(address, family):
    family = socket.AF_INET6 if family == 6 else socket.AF_INET
    transaction = b'NT'
    name = b'\x08nordtest\x07invalid\x00'
    question = transaction + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + name + b'\x00\x01\x00\x01'
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(question, (address, 53))
        response, source = sock.recvfrom(4096)
    if source[0] != address or len(response) < 12:
        raise RuntimeError('invalid DNS source or response length')
    if response[:2] != transaction or response[2:4] != b'\x81\x83':
        raise RuntimeError('invalid DNS transaction or flags')
    if response[4:6] != b'\x00\x01' or response[6:12] != b'\x00' * 6 or response[12:] != question[12:]:
        raise RuntimeError('invalid DNS response body')


def echo(address, family, port):
    family = socket.AF_INET6 if family == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(b'nord-tools-direct', (address, port))
        response, _ = sock.recvfrom(128)
    if response != b'nord-tools-direct':
        raise RuntimeError('invalid echo response')


def bypass(address, family, protocol, port):
    family = socket.AF_INET6 if family == 6 else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    error = None
    with socket.socket(family, kind) as sock:
        sock.settimeout(2)
        try:
            if protocol == 'tcp':
                sock.connect((address, port))
            else:
                sock.sendto(b'forbidden', (address, port))
        except OSError as exc:
            error = {'errno': exc.errno, 'message': exc.strerror}
    return error


report = Path(sys.argv[1])
commands = Path(sys.argv[2])
replies = Path(sys.argv[3])
release = Path(sys.argv[4])
namespace = os.stat('/proc/self/ns/net')
with report.open('x', encoding='utf-8') as stream:
    json.dump(
        {
            'pid': os.getpid(),
            'uid': os.geteuid(),
            'gid': os.getegid(),
            'groups': os.getgroups(),
            'namespace_device': namespace.st_dev,
            'namespace_inode': namespace.st_ino,
            'executable': os.readlink('/proc/self/exe'),
        },
        stream,
        sort_keys=True,
    )
    stream.flush()
    os.fsync(stream.fileno())

sequence = 1
deadline = time.monotonic() + 300
while not release.exists() and time.monotonic() < deadline:
    request_path = commands / f'{sequence:04d}.json'
    if not request_path.exists():
        time.sleep(0.02)
        continue
    request = json.loads(request_path.read_text(encoding='utf-8'))
    try:
        if request['action'] == 'dns':
            dns(request['address'], request['family'])
            result = {'ok': True}
        elif request['action'] == 'echo':
            echo(request['address'], request['family'], request['port'])
            result = {'ok': True}
        elif request['action'] == 'bypass':
            result = {
                'ok': True,
                'socket_error': bypass(
                    request['address'], request['family'], request['protocol'], request['port']
                ),
            }
        else:
            raise RuntimeError('unknown command')
    except Exception as exc:
        result = {'ok': False, 'error': f'{type(exc).__name__}: {exc}'}
    reply_path = replies / f'{sequence:04d}.json'
    temporary = reply_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(result, sort_keys=True), encoding='utf-8')
    temporary.replace(reply_path)
    sequence += 1
raise SystemExit(0 if release.exists() else 124)
"""


ECHO_SERVER = r"""import socket
import sys

family = socket.AF_INET6 if sys.argv[1] == '6' else socket.AF_INET
address = '::1' if family == socket.AF_INET6 else '127.0.0.1'
with socket.socket(family, socket.SOCK_DGRAM) as sock:
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, 0))
    print(f'READY:{sock.getsockname()[1]}', flush=True)
    while True:
        payload, peer = sock.recvfrom(128)
        sock.sendto(payload, peer)
"""


def write_child(path: Path) -> None:
    path.write_text(CHILD_SOURCE, encoding="utf-8")
    path.chmod(0o644)


def start_echo(family: int) -> tuple[subprocess.Popen, int]:
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", ECHO_SERVER, str(family)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ready = "" if process.stdout is None else process.stdout.readline().strip()
    if not ready.startswith("READY:") or not ready.removeprefix("READY:").isdigit():
        stop_process(process)
        raise RegisteredConfinementError(f"IPv{family} direct echo responder did not start")
    return process, int(ready.removeprefix("READY:"))


def stop_process(process: subprocess.Popen) -> None:
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


class ChildController:
    def __init__(self, root: Path, process: subprocess.Popen):
        self.process = process
        self.commands = root / "commands"
        self.replies = root / "replies"
        self.sequence = 0

    def issue(self, request: dict, *, timeout: float = 15) -> dict:
        self.sequence += 1
        request_path = self.commands / f"{self.sequence:04d}.json"
        response_path = self.replies / f"{self.sequence:04d}.json"
        request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RegisteredConfinementError("registered child exited during packet acceptance")
            try:
                return json.loads(response_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError):
                time.sleep(0.05)
        raise RegisteredConfinementError("registered child did not complete a packet command")


def child_paths(root: Path, uid: int, gid: int) -> tuple[Path, Path, Path, Path]:
    root.mkdir(mode=0o700)
    os.chown(root, uid, gid)
    commands = root / "commands"
    replies = root / "replies"
    commands.mkdir(mode=0o700)
    replies.mkdir(mode=0o700)
    os.chown(commands, uid, gid)
    os.chown(replies, uid, gid)
    return root / "report.json", commands, replies, root / "release"


def require_success(result: dict, label: str) -> None:
    if result.get("ok") is not True:
        raise RegisteredConfinementError(f"{label} failed: {result.get('error', 'unknown child error')}")


def require_failure(result: dict, label: str) -> None:
    if result.get("ok") is not False:
        raise RegisteredConfinementError(f"{label} unexpectedly succeeded")


def verify_direct_evidence(report: dict, *, uid: int, gid: int, executable: str) -> None:
    namespace = os.stat("/proc/self/ns/net")
    expected = {
        "uid": uid,
        "gid": gid,
        "groups": [],
        "namespace_device": namespace.st_dev,
        "namespace_inode": namespace.st_ino,
        "executable": executable,
    }
    if type(report.get("pid")) is not int or {key: report.get(key) for key in expected} != expected:
        raise RegisteredConfinementError("direct child identity or host namespace was incorrect")


def verify_only_vpn_lease(leases: list[dict]) -> None:
    if len(leases) != 1 or leases[0].get("application") != "vpn-probe":
        raise RegisteredConfinementError("runtime leases did not contain exactly the VPN-bound child")


def verify_direct_traffic(controller: ChildController, ports: dict[int, int]) -> None:
    for family, address in ((4, "127.0.0.1"), (6, "::1")):
        result = controller.issue({"action": "echo", "address": address, "family": family, "port": ports[family]})
        require_success(result, f"direct IPv{family} traffic")


def verify_vpn_dns(controller: ChildController) -> None:
    for family, address in ((4, "10.250.0.1"), (6, "fd42:250::1")):
        result = controller.issue({"action": "dns", "address": address, "family": family})
        require_success(result, f"registered IPv{family} VPN DNS")


def verify_vpn_dns_unavailable(controller: ChildController) -> None:
    for family, address in ((4, "10.250.0.1"), (6, "fd42:250::1")):
        result = controller.issue({"action": "dns", "address": address, "family": family})
        require_failure(result, f"registered IPv{family} VPN DNS during tunnel loss")


def verify_registered_underlay_refusal(controller: ChildController, server_namespace: str) -> None:
    for family, address in ((4, "10.214.10.1"), (6, "fd42:214::1")):
        for protocol in ("udp", "tcp"):
            listener = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    server_namespace,
                    sys.executable,
                    "-I",
                    "-c",
                    UNDERLAY_LISTENER,
                    str(family),
                    protocol,
                    address,
                    "53",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                if listener.stdout is None or listener.stdout.readline().strip() != "READY":
                    raise RegisteredConfinementError("underlay refusal listener did not start")
                result = controller.issue(
                    {
                        "action": "bypass",
                        "address": address,
                        "family": family,
                        "protocol": protocol,
                        "port": 53,
                    }
                )
                require_success(result, f"IPv{family} {protocol} underlay attempt")
                if listener.wait(timeout=6) != 0:
                    raise RegisteredConfinementError(
                        f"registered IPv{family} {protocol} DNS traffic escaped onto the underlay"
                    )
            finally:
                stop_process(listener)


def wait_for_no_leases(path: Path, policy: dict, *, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not read_runtime_consumers(path, policy)["leases"]:
            return
        time.sleep(0.1)
    raise RegisteredConfinementError("registered child lease remained after shutdown")


def wait_for_vpn_lease(
    path: Path,
    policy: dict,
    process: subprocess.Popen,
    stderr_path: Path,
    *,
    timeout: float = 15,
) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = [
            item
            for item in read_runtime_consumers(path, policy)["leases"]
            if item["application"] == "vpn-probe" and item["generation_id"] == "unversioned"
        ]
        if len(matches) == 1:
            return matches[0]
        result = process.poll()
        if result is not None:
            detail = stderr_path.read_text(encoding="utf-8").strip()[-1200:]
            raise RegisteredConfinementError(
                f"VPN-bound launcher exited {result} before leasing: {detail or 'no diagnostic'}"
            )
        time.sleep(0.1)
    raise RegisteredConfinementError("timed out waiting for vpn-probe lease on unversioned")


def application_experiment(uid: int, gid: int, context: ProductionConfinementContext) -> None:
    temporary = context.temporary
    policy = validate_policy(json.loads(Path(context.config["policy"]).read_text(encoding="utf-8")))
    leases = temporary / "registered-leases.json"
    initialise_runtime_consumers(leases, policy)
    child_script = temporary / "registered_packet_child.py"
    write_child(child_script)
    vpn_root = temporary / "vpn-child"
    direct_root = temporary / "direct-child"
    vpn_report, vpn_commands, vpn_replies, vpn_release = child_paths(vpn_root, uid, gid)
    direct_report, direct_commands, direct_replies, direct_release = child_paths(direct_root, uid, gid)
    config_path = temporary / "startup.json"
    executable = str(Path(sys.executable).resolve())
    echo_processes: list[subprocess.Popen] = []
    echo_ports: dict[int, int] = {}
    vpn_stderr = temporary / "vpn-child.stderr"
    direct_stderr = temporary / "direct-child.stderr"
    launchers: list[subprocess.Popen] = []
    primary_error: Exception | None = None
    cleanup_errors: list[str] = []
    try:
        for family in (4, 6):
            process, port = start_echo(family)
            echo_processes.append(process)
            echo_ports[family] = port
        vpn_process = launch(
            config_path,
            leases,
            "vpn-probe",
            uid,
            gid,
            (str(child_script), str(vpn_report), str(vpn_commands), str(vpn_replies), str(vpn_release)),
            stderr_path=vpn_stderr,
        )
        launchers.append(vpn_process)
        direct_process = launch(
            config_path,
            leases,
            "direct-probe",
            uid,
            gid,
            (
                str(child_script),
                str(direct_report),
                str(direct_commands),
                str(direct_replies),
                str(direct_release),
            ),
            stderr_path=direct_stderr,
        )
        launchers.append(direct_process)
        lease = wait_for_vpn_lease(leases, policy, vpn_process, vpn_stderr)
        verify_launch_evidence(
            wait_for_report(vpn_report),
            lease,
            uid=uid,
            gid=gid,
            application="vpn-probe",
            generation="unversioned",
            allocation_key="profile:alpha",
            kernel_profile="alpha",
            namespace_stat=os.stat(f"/run/netns/{context.namespace}"),
            executable=executable,
        )
        verify_direct_evidence(wait_for_report(direct_report), uid=uid, gid=gid, executable=executable)
        verify_only_vpn_lease(read_runtime_consumers(leases, policy)["leases"])
        vpn = ChildController(vpn_root, vpn_process)
        direct = ChildController(direct_root, direct_process)

        verify_direct_traffic(direct, echo_ports)
        verify_vpn_dns(vpn)
        verify_registered_underlay_refusal(vpn, context.server_namespace)
        print("PASS: registered direct and VPN-bound children exchanged concurrent dual-stack traffic", flush=True)
        print("PASS: registered VPN child refused dual-stack UDP/TCP underlay DNS bypass", flush=True)

        command(
            "ip",
            "netns",
            "exec",
            context.server_namespace,
            "wg",
            "set",
            context.peer_interface,
            "listen-port",
            "0",
        )
        try:
            verify_vpn_dns_unavailable(vpn)
            verify_registered_underlay_refusal(vpn, context.server_namespace)
            verify_direct_traffic(direct, echo_ports)
            verify_only_vpn_lease(read_runtime_consumers(leases, policy)["leases"])
            print("PASS: the same VPN child remained fail closed while the direct child stayed usable", flush=True)
        finally:
            command(
                "ip",
                "netns",
                "exec",
                context.server_namespace,
                "wg",
                "set",
                context.peer_interface,
                "listen-port",
                "51820",
            )
        verify_tunnel(context.namespace, context.interface, context.peer_public_key)
        verify_vpn_dns(vpn)
        verify_direct_traffic(direct, echo_ports)
        print("PASS: the existing registered children recovered VPN traffic without relaunch", flush=True)
    except Exception as exc:
        primary_error = exc
    finally:
        for release in (vpn_release, direct_release):
            try:
                release.touch(mode=0o600)
            except OSError as exc:
                cleanup_errors.append(str(exc))
        launch_details = zip(
            launchers,
            (vpn_release, direct_release),
            ("vpn-probe", "direct-probe"),
            strict=False,
        )
        for process, release, application in launch_details:
            try:
                finish_launch(process, release, leases, policy, application)
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                cleanup_errors.append(str(exc))
                try:
                    stop_launch(process)
                except Exception as stop_exc:
                    cleanup_errors.append(str(stop_exc))
        try:
            wait_for_no_leases(leases, policy)
        except (OSError, RuntimeError, ValueError) as exc:
            cleanup_errors.append(str(exc))
        for process in echo_processes:
            stop_process(process)
    if primary_error is not None:
        if cleanup_errors:
            raise RegisteredConfinementError(
                f"{primary_error}; child cleanup also failed: {'; '.join(cleanup_errors)}"
            ) from primary_error
        raise primary_error
    if cleanup_errors:
        raise RegisteredConfinementError("registered child cleanup failed: " + "; ".join(cleanup_errors))


def run_acceptance(uid: int, gid: int) -> None:
    executable = str(Path(sys.executable).resolve())
    applications = {
        "vpn-probe": {"executable": executable, "vpn": "alpha"},
        "direct-probe": {"executable": executable, "vpn": "direct"},
    }
    run_production_probe(
        applications=applications,
        application_experiment=lambda context: application_experiment(uid, gid, context),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument("--uid", type=int, help="existing non-root test user")
    parser.add_argument("--gid", type=int, help="existing non-root test group")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: concurrent registered direct and VPN-bound dual-stack packet acceptance")
        return 0
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or args.uid is None
        or args.gid is None
        or args.uid <= 0
        or args.gid <= 0
    ):
        parser.error("--run-privileged requires Linux root and explicit non-root --uid/--gid")
    missing = [name for name in ("ip", "wg", "nft", "ping") if shutil.which(name) is None]
    if missing:
        parser.error("missing prerequisites: " + ", ".join(missing))
    try:
        run_acceptance(args.uid, args.gid)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
