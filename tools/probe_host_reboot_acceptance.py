#!/usr/bin/env python3
"""D3 real-reboot fixture and console-controlled host restoration acceptance.

Only use in the dedicated disposable guest. The fixture is rebuilt at early boot;
no privileged host networking on the operator's machine is touched.
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

from nord_tools_internal.nordvpn_host_executor import (  # noqa: E402
    activate_host_protection,
    deactivate_host_protection,
    host_protection_status,
    recover_host_protection,
)
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan  # noqa: E402
from nord_tools_internal.nordvpn_host_startup import (  # noqa: E402
    ACTIVATION_UNIT,
    BARRIER_UNIT,
    render_host_startup_units,
)
from tools.probe_host_domain_acceptance import (  # noqa: E402
    HANDSHAKE_DRIVER,
    command,
    verify_dns,
    verify_routes,
    snapshot,
    verify_disposable_veth_retired,
    interrupt_deactivation_before_routes,
    without_runtime_values,
    write_json,
)

STATE = Path("/var/lib/nord-tools-d3")
BOOT_ROOT = STATE / "source"
UNIT_DIR = Path("/etc/systemd/system")
SETUP_UNIT = "nord-tools-d3-fixture.service"
PEER_UNIT = "nord-tools-d3-peer.service"
RESULT = Path("/var/tmp/nord-tools-d3-result.json")
NAMESPACE = "ntd3peer"
HOST_LINK = "ntd3host"
PEER_LINK = "ntd3link"
WG_PEER = "ntd3wgpeer"
WG_HOST = "ntd3wghost"
PORT = 51821
BOOT_PROBES = (
    "probe_host_reboot_acceptance.py",
    "probe_host_domain_acceptance.py",
    "probe_wireguard_host_integrity.py",
    "probe_two_wireguard.py",
)


def stage_boot_probes(source_root: Path, destination_root: Path) -> None:
    """Copy the complete D3 probe import closure without following source symlinks."""
    destination = destination_root / "tools"
    destination.mkdir(mode=0o700)
    for name in BOOT_PROBES:
        source = source_root / "tools" / name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"D3 boot probe missing or symlinked: {source}")
        shutil.copy2(source, destination / name)


def verify_staged_boot_imports(destination_root: Path) -> None:
    """Import the installed boot entry point, not the development checkout."""
    entry = destination_root / "tools" / "probe_host_reboot_acceptance.py"
    result = subprocess.run(
        [sys.executable, "-I", str(entry), "--help"],
        cwd="/",
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"D3 staged boot entry point failed import preflight ({result.returncode}): {result.stderr.strip()}"
        )


def call(*args: str) -> None:
    command(*args, timeout=30)


def unit(name: str, body: str) -> None:
    target = UNIT_DIR / name
    if target.exists() or target.is_symlink():
        raise RuntimeError(f"D3 refuses to replace an existing systemd unit: {target}")
    target.write_text(body, encoding="utf-8")
    target.chmod(0o644)


def setup() -> None:
    """Stage the peer and fresh boot-specific plan before the early deny barrier."""
    if (STATE / "host-store.json").exists():
        # Never discard an interrupted earlier-boot transaction to make a test pass.
        raise RuntimeError("D3 prior boot has unresolved host evidence; console recovery required")
    call("ip", "netns", "add", NAMESPACE)
    call("ip", "link", "add", HOST_LINK, "type", "veth", "peer", "name", PEER_LINK)
    call("ip", "link", "set", PEER_LINK, "netns", NAMESPACE)
    call("ip", "link", "set", HOST_LINK, "addrgenmode", "none")
    call("ip", "-n", NAMESPACE, "link", "set", PEER_LINK, "addrgenmode", "none")
    call("ip", "address", "add", "192.0.2.2/29", "dev", HOST_LINK)
    call("ip", "link", "set", HOST_LINK, "up")
    call("ip", "-n", NAMESPACE, "link", "set", "lo", "up")
    call("ip", "-n", NAMESPACE, "address", "add", "192.0.2.1/29", "dev", PEER_LINK)
    call("ip", "-n", NAMESPACE, "link", "set", PEER_LINK, "up")
    call("ip", "-n", NAMESPACE, "link", "add", WG_PEER, "type", "wireguard")
    call("ip", "-n", NAMESPACE, "address", "add", "10.77.0.1/24", "dev", WG_PEER)
    call("ip", "-n", NAMESPACE, "address", "add", "fd42:77::1/64", "dev", WG_PEER)
    call(
        "ip",
        "netns",
        "exec",
        NAMESPACE,
        "wg",
        "set",
        WG_PEER,
        "private-key",
        str(STATE / "peer.key"),
        "listen-port",
        str(PORT),
        "peer",
        (STATE / "client.pub").read_text(encoding="ascii").strip(),
        "allowed-ips",
        "10.77.0.2/32,fd42:77::2/128",
    )
    call("ip", "-n", NAMESPACE, "link", "set", WG_PEER, "up")
    plan = HostProtectionPlan.from_mapping(
        {
            "version": 1,
            "generation": "d3-reboot",
            "interface": WG_HOST,
            "peer_public_key": (STATE / "peer.pub").read_text(encoding="ascii").strip(),
            "endpoint_address": "192.0.2.1",
            "endpoint_port": PORT,
            "tunnel_addresses": ["10.77.0.2/32", "fd42:77::2/128"],
            "dns_servers": ["10.77.0.1", "fd42:77::1"],
            "egress_interface": HOST_LINK,
            "egress_ifindex": int((Path("/sys/class/net") / HOST_LINK / "ifindex").read_text()),
            "egress_source_address": "192.0.2.2",
            "route_table": 51900,
            "endpoint_rule_priority": 100,
            "tunnel_rule_priority": 110,
            "fwmark": 51900,
            "resolver_mode": "systemd-resolved",
            "firewall_family": "inet",
            "firewall_table": "nord_tools_host",
            "firewall_priority": -200,
            "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
        }
    )
    write_json(STATE / "plan.json", plan.public_plan())
    write_json(STATE / "fixture-baseline.json", snapshot())
    write_json(
        STATE / "boot.json",
        {
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "fixture_ifindex": plan.egress_ifindex,
        },
    )


def peer_dns() -> None:
    """Serve the isolated peer DNS sockets."""
    import selectors
    import socket

    selector = selectors.DefaultSelector()
    for family, address in ((socket.AF_INET, "10.77.0.1"), (socket.AF_INET6, "fd42:77::1")):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.bind((address, 53))
        selector.register(sock, selectors.EVENT_READ)
    print("D3 peer DNS ready", flush=True)
    while True:
        for key, _ in selector.select(timeout=1):
            request, source = key.fileobj.recvfrom(4096)
            if len(request) >= 12:
                key.fileobj.sendto(request[:2] + b"\x81\x83" + request[4:6] + b"\x00" * 6 + request[12:], source)


def peer() -> None:
    """Start peer DNS in its namespace and initiate real host handshakes."""
    dns = subprocess.Popen(
        ["ip", "netns", "exec", NAMESPACE, sys.executable, str(Path(__file__).resolve()), "peer-dns"]
    )
    driver = subprocess.Popen([sys.executable, "-I", "-c", HANDSHAKE_DRIVER])
    try:
        while True:
            if dns.poll() is not None or driver.poll() is not None:
                raise RuntimeError("D3 peer or handshake driver exited unexpectedly")
            time.sleep(1)
    finally:
        for process in (dns, driver):
            process.terminate()
            process.wait(timeout=5)


def prepare() -> None:
    if os.geteuid() != 0 or not Path("/etc/arch-release").exists():
        raise RuntimeError("D3 preparation requires root inside the disposable Arch guest")
    if STATE.exists() or RESULT.exists():
        raise RuntimeError("D3 requires a fresh guest with no prior D3 state")
    for name in (SETUP_UNIT, PEER_UNIT, BARRIER_UNIT, ACTIVATION_UNIT):
        if (UNIT_DIR / name).exists() or (UNIT_DIR / name).is_symlink():
            raise RuntimeError(f"D3 unit already exists: {name}")
    STATE.mkdir(mode=0o700)
    # Root-owned boot code must not be writable by the unprivileged SSH user.
    BOOT_ROOT.mkdir(mode=0o700)
    for source in ROOT.glob("*.py"):
        if source.is_symlink():
            raise RuntimeError("D3 refuses symlinked executable source")
        shutil.copy2(source, BOOT_ROOT / source.name)
    (BOOT_ROOT / "nord_tools_internal").mkdir(mode=0o700)
    for source in (ROOT / "nord_tools_internal").glob("*.py"):
        if source.is_symlink():
            raise RuntimeError("D3 refuses symlinked internal source")
        shutil.copy2(source, BOOT_ROOT / "nord_tools_internal" / source.name)
    stage_boot_probes(ROOT, BOOT_ROOT)
    # Must pass before keys, systemd units or reboot eligibility are created.
    verify_staged_boot_imports(BOOT_ROOT)
    for name in ("nordvpn_manage.py",):
        if not (BOOT_ROOT / name).is_file():
            raise RuntimeError("D3 root-owned boot code is incomplete")
    for name in ("client", "peer"):
        private = command("wg", "genkey") + b"\n"
        (STATE / f"{name}.key").write_bytes(private)
        (STATE / f"{name}.key").chmod(0o600)
        (STATE / f"{name}.pub").write_bytes(command("wg", "pubkey", input_data=private) + b"\n")
    # The rendered units only embed paths. The boot setup creates the validated
    # plan with the new boot's actual interface index before barrier execution.
    template = HostProtectionPlan.from_mapping(
        {
            "version": 1,
            "generation": "d3-reboot",
            "interface": WG_HOST,
            "peer_public_key": (STATE / "peer.pub").read_text().strip(),
            "endpoint_address": "192.0.2.1",
            "endpoint_port": PORT,
            "tunnel_addresses": ["10.77.0.2/32", "fd42:77::2/128"],
            "dns_servers": ["10.77.0.1", "fd42:77::1"],
            "egress_interface": HOST_LINK,
            "egress_ifindex": 1,
            "egress_source_address": "192.0.2.2",
            "route_table": 51900,
            "endpoint_rule_priority": 100,
            "tunnel_rule_priority": 110,
            "fwmark": 51900,
            "resolver_mode": "systemd-resolved",
            "firewall_family": "inet",
            "firewall_table": "nord_tools_host",
            "firewall_priority": -200,
            "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
        }
    )
    script = str(BOOT_ROOT / "tools" / "probe_host_reboot_acceptance.py")
    generated = render_host_startup_units(
        template,
        plan_path=STATE / "plan.json",
        store_path=STATE / "host-store.json",
        private_key_path=STATE / "client.key",
        python_executable="/usr/bin/python",
        script_path=BOOT_ROOT / "nordvpn_manage.py",
    )
    # Boot fixture must exist before the barrier, while network-pre remains blocked.
    generated[BARRIER_UNIT] = generated[BARRIER_UNIT].replace(
        "After=local-fs.target", f"After=local-fs.target {SETUP_UNIT}\nRequires={SETUP_UNIT}"
    )
    generated[BARRIER_UNIT] = generated[BARRIER_UNIT].replace(
        "Before=network-pre.target", "Before=network-pre.target network.target systemd-networkd.service"
    )
    generated[BARRIER_UNIT] = generated[BARRIER_UNIT].replace(
        "RequiredBy=network-pre.target", "RequiredBy=network-pre.target\nWantedBy=sysinit.target"
    )
    generated[ACTIVATION_UNIT] = generated[ACTIVATION_UNIT].replace(
        "Wants=network-online.target", f"Wants=network-online.target\nRequires={PEER_UNIT}\nAfter={PEER_UNIT}"
    )
    generated[ACTIVATION_UNIT] = generated[ACTIVATION_UNIT].replace(
        "\n[Install]", f"\nExecStartPost=/usr/bin/python {script} converge %d/ntwg-host\n\n[Install]"
    )
    setup_content = (
        f"[Unit]\nDescription=D3 disposable boot peer setup\nDefaultDependencies=no\n"
        f"After=local-fs.target\nBefore={BARRIER_UNIT} network-pre.target\n"
        f"RequiresMountsFor={STATE} {script}\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        f"ExecStart=/usr/bin/python {script} setup\n\n[Install]\nWantedBy=sysinit.target\n"
    )
    peer_content = (
        f"[Unit]\nDescription=D3 disposable dual-stack WireGuard peer\n"
        f"Requires={BARRIER_UNIT}\nAfter={BARRIER_UNIT}\nBefore={ACTIVATION_UNIT}\n\n"
        f"[Service]\nType=simple\nExecStart=/usr/bin/python {script} peer\n"
        f"Restart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
    )
    unit(SETUP_UNIT, setup_content)
    unit(PEER_UNIT, peer_content)
    for name, content in generated.items():
        unit(name, content)
    call("systemctl", "daemon-reload")
    for name in (SETUP_UNIT, PEER_UNIT, BARRIER_UNIT, ACTIVATION_UNIT):
        call("systemctl", "enable", name)
    write_json(
        STATE / "prepared.json",
        {
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "units": [SETUP_UNIT, PEER_UNIT, BARRIER_UNIT, ACTIVATION_UNIT],
        },
    )


def converge(private_key: str) -> None:
    """Retry the actual host executor until the peer handshake verifies."""
    plan = HostProtectionPlan.from_mapping(json.loads((STATE / "plan.json").read_text()))
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        fd = os.open(private_key, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            state = activate_host_protection(plan, STATE / "host-store.json", fd)
        finally:
            os.close(fd)
        if state.get("state") == "active_verified" and state.get("ordinary_host_egress_blocked") is True:
            return
        time.sleep(1)
    raise RuntimeError("D3 host activation did not verify a real WireGuard handshake")


def inspect() -> None:
    prepared = json.loads((STATE / "prepared.json").read_text())
    boot = json.loads((STATE / "boot.json").read_text())
    current = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if current == prepared["boot_id"] or current != boot["boot_id"]:
        raise RuntimeError("D3 has not observed the required real guest reboot")
    for name in (SETUP_UNIT, PEER_UNIT, BARRIER_UNIT, ACTIVATION_UNIT):
        result = subprocess.run(["systemctl", "is-active", "--quiet", name], check=False)
        if result.returncode:
            raise RuntimeError(f"D3 boot unit did not reach active state: {name}")
    times = {}
    for name in (SETUP_UNIT, BARRIER_UNIT, PEER_UNIT, ACTIVATION_UNIT):
        output = command("systemctl", "show", name, "-p", "ExecMainStartTimestampMonotonic").decode()
        times[name] = int(output.strip().split("=", 1)[1])
    if not (0 < times[SETUP_UNIT] <= times[BARRIER_UNIT] < times[ACTIVATION_UNIT]):
        raise RuntimeError("D3 did not establish early barrier before network-online activation")
    networkd = (
        command("systemctl", "show", "systemd-networkd.service", "-p", "ExecMainStartTimestampMonotonic")
        .decode()
        .strip()
        .split("=", 1)[1]
    )
    if not networkd.isdecimal() or int(networkd) < times[BARRIER_UNIT]:
        raise RuntimeError("D3 ordinary networking started before the host deny barrier")
    online = (
        command("systemctl", "show", "network-online.target", "-p", "ActiveEnterTimestampMonotonic")
        .decode()
        .strip()
        .split("=", 1)[1]
    )
    if not online.isdecimal() or not 0 < int(online) <= times[ACTIVATION_UNIT]:
        raise RuntimeError("D3 host activation preceded network-online.target")
    times["systemd-networkd.service"] = int(networkd)
    times["network-online.target"] = int(online)
    plan = HostProtectionPlan.from_mapping(json.loads((STATE / "plan.json").read_text()))
    state = host_protection_status(plan, STATE / "host-store.json")
    if state.get("ordinary_host_egress_blocked") is not True or state.get("state") != "active_verified":
        raise RuntimeError("D3 reboot did not converge to verified protected host state")
    verify_routes(WG_HOST)
    verify_dns("10.77.0.1", 4)
    verify_dns("fd42:77::1", 6)
    write_json(STATE / "verified.json", {"boot_id": current, "times": times, "status": state})
    print("PASS: real guest reboot installed early deny barrier and converged protected dual-stack traffic", flush=True)


def retire() -> None:
    if not (STATE / "verified.json").exists():
        raise RuntimeError("D3 retirement requires independent verified reboot evidence")
    plan = HostProtectionPlan.from_mapping(json.loads((STATE / "plan.json").read_text()))
    interrupt_deactivation_before_routes(plan, STATE / "host-store.json")
    interrupted = host_protection_status(plan, STATE / "host-store.json")
    if interrupted.get("ordinary_host_egress_blocked") is not True:
        raise RuntimeError("D3 interrupted retirement lost the deny barrier")
    recover_host_protection(plan, STATE / "host-store.json", execute=True)
    retired = deactivate_host_protection(plan, STATE / "host-store.json", expose_host_egress=True)
    if retired.get("ordinary_host_egress_blocked") is not False:
        raise RuntimeError("D3 did not verify barrier-last retirement")
    before = json.loads((STATE / "fixture-baseline.json").read_text())
    after = snapshot()
    if without_runtime_values(after["nftables"]) != without_runtime_values(before["nftables"]):
        raise RuntimeError("D3 retirement did not restore the original nftables ruleset")
    if any(link.get("ifname") == WG_HOST for link in after["links"]):
        raise RuntimeError("D3 retired WireGuard interface remains present")
    for key in ("ipv4_rules", "ipv6_rules"):
        if any(rule.get("priority") in (100, 110) and rule not in before[key] for rule in after[key]):
            raise RuntimeError("D3 retired policy routing rule remains present")
    for key in ("ipv4_routes", "ipv6_routes"):
        if any(str(route.get("table")) in ("51900",) for route in after[key]):
            raise RuntimeError("D3 retired policy routing table remains present")
    write_json(STATE / "retired-snapshot.json", after)
    # Do not remove boot services before their owned network objects have retired.
    for name in (ACTIVATION_UNIT, BARRIER_UNIT, PEER_UNIT, SETUP_UNIT):
        call("systemctl", "disable", name)
    for name in (ACTIVATION_UNIT, BARRIER_UNIT, PEER_UNIT, SETUP_UNIT):
        call("systemctl", "stop", name)
    expected_ifindex = int(json.loads((STATE / "boot.json").read_text())["fixture_ifindex"])
    call("ip", "netns", "del", NAMESPACE)
    verify_disposable_veth_retired(HOST_LINK, expected_ifindex)
    for name in (ACTIVATION_UNIT, BARRIER_UNIT, PEER_UNIT, SETUP_UNIT):
        (UNIT_DIR / name).unlink()
    call("systemctl", "daemon-reload")
    write_json(
        RESULT,
        {
            "result": "passed",
            "scope": "D3 real-reboot host startup acceptance",
            "boot_id": json.loads((STATE / "verified.json").read_text())["boot_id"],
            "checks": [
                "actual reboot",
                "early barrier ordering",
                "network-online activation",
                "dual-stack tunnel and DNS",
                "SIGKILL interruption and explicit recovery",
                "evidence-gated barrier-last retirement",
            ],
        },
    )
    print("PASS: D3 host barrier retired after verified recovery", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "setup", "peer", "peer-dns", "converge", "inspect", "retire"))
    parser.add_argument("credential", nargs="?")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("D3 requires root inside the disposable guest")
    try:
        if args.action == "converge":
            if not args.credential:
                raise RuntimeError("D3 converge requires the systemd credential path")
            converge(args.credential)
            return 0
        if args.credential:
            raise RuntimeError("unexpected D3 credential argument")
        {"prepare": prepare, "setup": setup, "peer": peer, "peer-dns": peer_dns, "inspect": inspect, "retire": retire}[
            args.action
        ]()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: D3 {args.action}: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
