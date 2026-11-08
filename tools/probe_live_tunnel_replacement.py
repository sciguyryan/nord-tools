#!/usr/bin/env python3
"""Opt-in production generation-replacement acceptance with a local real peer.

The runner owns every generated key, namespace, interface and state store.  It
provisions A through production restoration, launches a lease-gated process,
provisions and activates B, proves generation-specific leases and retirement
refusal, drains A, retires it, and confirms B remains launchable.  Host routes,
nftables configuration (excluding only counter values) and resolver contents
must return to their exact baseline after verified cleanup.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_allocation_profiles import kernel_profile_for_generation  # noqa: E402
from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup  # noqa: E402
from nord_tools_internal.nordvpn_discovery import discover  # noqa: E402
from nord_tools_internal.nordvpn_generation_recovery import recover_generation  # noqa: E402
from nord_tools_internal.nordvpn_generation_handover import (  # noqa: E402
    AllocationGeneration,
    GenerationHandoverError,
    policy_digest,
    prepare_generation_handover,
)
from nord_tools_internal.nordvpn_profiles import validate_policy  # noqa: E402
from nord_tools_internal.nordvpn_replacement_executor import (  # noqa: E402
    _production_provision,
    activate_replacement,
    prepare_replacement,
    replacement_status,
    retire_old_generation,
)
from nord_tools_internal.nordvpn_restore_executor import restore_boot_state  # noqa: E402
from nord_tools_internal.nordvpn_runtime_consumers import (  # noqa: E402
    initialise_runtime_consumers,
    read_runtime_consumers,
)
from tools.probe_wireguard_host_integrity import observe as observe_host  # noqa: E402
from tools.probe_wireguard_host_integrity import verify as verify_host  # noqa: E402


class ProbeError(RuntimeError):
    """The disposable replacement scenario did not meet its contract."""


def command(*arguments: str, input_data: bytes | None = None) -> bytes:
    result = subprocess.run(arguments, input=input_data, capture_output=True, check=False, timeout=15)
    if result.returncode:
        raise ProbeError(f"command failed: {arguments[0]}")
    return result.stdout.strip()


def write(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def wait_for_lease(path: Path, policy: dict, application: str, generation: str, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        leases = read_runtime_consumers(path, policy)["leases"]
        if any(item["application"] == application and item["generation_id"] == generation for item in leases):
            return
        time.sleep(0.1)
    raise ProbeError(f"timed out waiting for {application} lease on {generation}")


def launch(config: Path, leases: Path, application: str, uid: int, gid: int) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "nord_tools.py"),
            "manage",
            "launch-consumer",
            "--config",
            str(config),
            "--runtime-consumers",
            str(leases),
            "--consumer",
            application,
            "--uid",
            str(uid),
            "--gid",
            str(gid),
            "--execute",
            "120",
        ],
        stderr=subprocess.DEVNULL,
    )


def start_dns_responder(server_namespace: str) -> subprocess.Popen:
    """Serve deterministic DNS-shaped responses on the local tunnel peer."""
    script = """
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('10.250.0.1', 53))
print('READY', flush=True)
while True:
    query, peer = sock.recvfrom(4096)
    if len(query) >= 12:
        response = query[:2] + b'\\x81\\x83' + query[4:6] + b'\\x00\\x00\\x00\\x00\\x00\\x00' + query[12:]
        sock.sendto(response, peer)
"""
    process = subprocess.Popen(
        ["ip", "netns", "exec", server_namespace, sys.executable, "-I", "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdout is None or process.stdout.readline().strip() != "READY":
        error = process.stderr.read(200) if process.stderr is not None else ""
        process.kill()
        process.wait()
        raise ProbeError(f"local DNS responder could not start: {error.strip()}")
    return process


def attach_underlay_to_peer(config: dict, kernel_profile: str, bridge: str, host_address: str) -> None:
    """Bridge one production-owned host veth directly to the peer namespace."""
    journal = read(Path(config["journal"]))
    bindings = {item["allocation_id"]: item["binding"] for item in read(Path(config["bindings"]))["bindings"]}
    candidates = [
        item
        for item in journal["allocations"]["resources"]
        if item["profile"] == kernel_profile
        and item["kind"] == "interface"
        and bindings.get(item["allocation_id"], {}).get("scope") == "host"
    ]
    if len(candidates) != 1:
        raise ProbeError(f"cannot identify the host underlay for {kernel_profile}")
    interface = candidates[0]["identifier"]
    command("ip", "address", "del", host_address, "dev", interface)
    command("ip", "link", "set", interface, "master", bridge)
    command("ip", "link", "set", interface, "up")


def stop_launch(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ProbeError("application launcher did not release its lease") from exc


def tunnel_plan(endpoint: str, tunnel_addresses: tuple[str, ...], underlay_index: int, peer_key: str) -> dict:
    return {
        "peer_public_key": peer_key,
        "endpoint_address": endpoint,
        "endpoint_port": 51820,
        "tunnel_addresses": list(tunnel_addresses),
        "peer_allowed_ips": ["0.0.0.0/0"],
        "underlay": {
            "namespace_address": f"10.214.{underlay_index}.2/30",
            "host_address": f"10.214.{underlay_index}.1/30",
        },
        "dns_servers": ["10.250.0.1"],
    }


def verify_adversarial_recovery(
    config: dict,
    handover: Path,
    leases: Path,
    *,
    expected_disposition: str,
) -> None:
    """Exercise read-only repeatability and fail-closed recovery refusals.

    The deliberately failed packet verifier never mutates the live tunnel.
    Profile/allocation mismatch checks must refuse before kernel discovery.
    """
    arguments = {
        "handover_path": str(handover),
        "runtime_consumers_path": str(leases),
        "observe": discover,
    }
    before = recover_generation(config, **arguments)
    after = recover_generation(config, **arguments)
    if before != after or before["disposition"] != expected_disposition:
        raise ProbeError("read-only recovery is not repeatable at the current generation boundary")
    if before["network_changes_applied"] or before["automatic_kernel_repair_authorised"]:
        raise ProbeError("read-only recovery unexpectedly authorised network mutation")
    for expected in ({"expected_profile": "unrelated"}, {"expected_allocation_key": "profile:unrelated"}):
        try:
            recover_generation(config, **arguments, execute=True, allow_reprovision=True, **expected)
        except GenerationHandoverError:
            pass
        else:
            raise ProbeError("cross-profile or cross-allocation recovery was not refused")
    if before["selected_generation"] == "generation-b":
        failed = recover_generation(
            config,
            **arguments,
            execute=True,
            allow_reprovision=True,
            packet_verifier=lambda _namespace: False,
        )
        if (
            failed["disposition"] != "selected_generation_drift_fail_closed"
            or failed["selected_packet_verified"] is not False
            or failed["network_changes_applied"]
        ):
            raise ProbeError("failed packet readiness did not produce non-mutating fail-closed drift")
        if recover_generation(config, **arguments) != before:
            raise ProbeError("refused drift assessment changed the selected generation")


def run_probe(uid: int, gid: int, *, inject_replacement_interruption: bool = False) -> None:
    token = secrets.token_hex(3)
    peer_interface = f"ntpr{token}"
    server_namespace = f"ntsrv{token}"
    bridge = f"ntbr{token}"
    server_host = f"ntvh{token}"
    server_link = f"ntvs{token}"
    temporary = Path(tempfile.mkdtemp(prefix="nt-live-replacement-"))
    launchers: list[subprocess.Popen] = []
    dns_responder: subprocess.Popen | None = None
    baseline = observe_host()
    succeeded = False
    try:
        peer_private = command("wg", "genkey")
        client_a_private = command("wg", "genkey")
        client_b_private = command("wg", "genkey")
        peer_public = command("wg", "pubkey", input_data=peer_private + b"\n").decode()
        client_a_public = command("wg", "pubkey", input_data=client_a_private + b"\n").decode()
        client_b_public = command("wg", "pubkey", input_data=client_b_private + b"\n").decode()
        peer_key = temporary / "peer.key"
        key_a = temporary / "a.key"
        key_b = temporary / "b.key"
        for path, value in ((peer_key, peer_private), (key_a, client_a_private), (key_b, client_b_private)):
            path.write_bytes(value + b"\n")
            path.chmod(0o600)
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
        command("ip", "-n", server_namespace, "address", "add", "10.214.11.1/30", "dev", server_link)
        command("ip", "-n", server_namespace, "link", "add", peer_interface, "type", "wireguard")
        command("ip", "-n", server_namespace, "address", "add", "10.250.0.1/24", "dev", peer_interface)
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
            client_a_public,
            "allowed-ips",
            "10.250.0.2/32",
            "peer",
            client_b_public,
            "allowed-ips",
            "10.250.0.3/32",
        )
        command("ip", "-n", server_namespace, "link", "set", peer_interface, "up")
        dns_responder = start_dns_responder(server_namespace)

        policy_document = {
            "version": 1,
            "defaults": {"vpn": "alpha"},
            # Provider selection is not used by this fully pinned local plan,
            # but the production policy contract still requires a syntactically
            # valid NordVPN server identity.
            "vpn_profiles": {"alpha": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
            "applications": {
                "consumer-a": {"executable": "/usr/bin/sleep", "vpn": "alpha"},
                "consumer-b": {"executable": "/usr/bin/sleep", "vpn": "alpha"},
            },
        }
        policy_path = temporary / "policy.json"
        config_path = temporary / "startup.json"
        leases = temporary / "leases.json"
        handover = temporary / "handover.json"
        write(policy_path, policy_document)
        # Every durable fingerprint must use the same canonical policy shape
        # as production readers and launchers.
        policy = validate_policy(policy_document)
        config = {
            "version": 1,
            "policy": str(policy_path),
            "journal": str(temporary / "journal.json"),
            "bindings": str(temporary / "bindings.json"),
            "intent": str(temporary / "intents.json"),
            "run_record": str(temporary / "runs.json"),
            "tunnels": {"alpha": tunnel_plan("10.214.10.1", ("10.250.0.2/32",), 10, peer_public)},
            "credentials": {"alpha": str(key_a)},
            "handovers": {"profile:alpha": str(handover)},
        }
        write(config_path, config)
        # Restore A before publishing a handover selection.
        restore_boot_state({key: value for key, value in config.items() if key != "handovers"})
        attach_underlay_to_peer(config, "alpha", bridge, "10.214.10.1/30")
        initialise_runtime_consumers(leases, policy)
        digest = policy_digest(policy)
        replacement_kernel = kernel_profile_for_generation("alpha", "profile:alpha", "generation-b")
        prepare_generation_handover(
            handover,
            old=AllocationGeneration("alpha", "profile:alpha", "generation-a", "alpha", digest),
            replacement=AllocationGeneration("alpha", "profile:alpha", "generation-b", replacement_kernel, digest),
            policy=policy,
        )
        first = launch(config_path, leases, "consumer-a", uid, gid)
        launchers.append(first)
        wait_for_lease(leases, policy, "consumer-a", "generation-a")

        config["tunnels"]["alpha"] = tunnel_plan("10.214.11.1", ("10.250.0.3/32",), 11, peer_public)
        config["credentials"]["alpha"] = str(key_b)
        write(config_path, config)

        def provision_b(validated: dict, checked_policy: dict, replacement: AllocationGeneration) -> object:
            result = _production_provision(validated, checked_policy, replacement)
            attach_underlay_to_peer(validated, replacement.kernel_profile, bridge, "10.214.11.1/30")
            return result

        before = recover_generation(
            config, handover_path=str(handover), runtime_consumers_path=str(leases), observe=discover
        )
        if before["disposition"] != "eligible_for_explicit_reprovision":
            raise ProbeError("recovery did not recognise verified-absent unselected replacement")
        if inject_replacement_interruption:
            child = os.fork()
            if child == 0:
                try:

                    def interrupted_provision(
                        validated: dict, checked_policy: dict, replacement: AllocationGeneration
                    ) -> object:
                        result = provision_b(validated, checked_policy, replacement)
                        os.kill(os.getpid(), signal.SIGKILL)
                        return result

                    prepare_replacement(
                        config,
                        profile="alpha",
                        allocation_key="profile:alpha",
                        old_generation_id="generation-a",
                        replacement_generation_id="generation-b",
                        handover_path=str(handover),
                        runtime_consumers_path=str(leases),
                        observe=discover,
                        provision=interrupted_provision,
                    )
                except BaseException:
                    os._exit(3)
                os._exit(4)
            _, status = os.waitpid(child, 0)
            if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
                raise ProbeError("replacement interruption did not reach the post-provision checkpoint")
            interrupted = recover_generation(
                config,
                handover_path=str(handover),
                runtime_consumers_path=str(leases),
                observe=discover,
                execute=True,
            )
            if interrupted["phase"] != "verified" or interrupted["network_changes_applied"]:
                raise ProbeError("post-provision interruption did not recover without kernel changes")
        else:
            prepare_replacement(
                config,
                profile="alpha",
                allocation_key="profile:alpha",
                old_generation_id="generation-a",
                replacement_generation_id="generation-b",
                handover_path=str(handover),
                runtime_consumers_path=str(leases),
                observe=discover,
                provision=provision_b,
            )
        staged = recover_generation(
            config, handover_path=str(handover), runtime_consumers_path=str(leases), observe=discover
        )
        if staged["disposition"] != "verified_awaiting_explicit_activation":
            raise ProbeError("recovery did not preserve the explicit activation boundary")
        if inject_replacement_interruption:
            child = os.fork()
            if child == 0:
                try:
                    activate_replacement(
                        config,
                        handover_path=str(handover),
                        runtime_consumers_path=str(leases),
                        observe=discover,
                    )
                    os.kill(os.getpid(), signal.SIGKILL)
                except BaseException:
                    os._exit(3)
                os._exit(4)
            _, status = os.waitpid(child, 0)
            if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
                raise ProbeError("activation interruption did not reach the durable cut-over checkpoint")
        else:
            activate_replacement(
                config,
                handover_path=str(handover),
                runtime_consumers_path=str(leases),
                observe=discover,
            )
        activated = recover_generation(
            config, handover_path=str(handover), runtime_consumers_path=str(leases), observe=discover
        )
        if activated["disposition"] != "draining_active_consumers" or not activated["selected_packet_verified"]:
            raise ProbeError("recovery did not recognise healthy B and A's active lease")
        verify_adversarial_recovery(
            config,
            handover,
            leases,
            expected_disposition="draining_active_consumers",
        )
        second = launch(config_path, leases, "consumer-b", uid, gid)
        launchers.append(second)
        wait_for_lease(leases, policy, "consumer-b", "generation-b")
        status = replacement_status(
            config, handover_path=str(handover), runtime_consumers_path=str(leases), observe=discover
        )
        if status["lease_counts"] != {"generation-a": 1, "generation-b": 1}:
            raise ProbeError("concurrent leases were not attributed to their exact generations")
        try:
            retire_old_generation(
                config,
                handover_path=str(handover),
                runtime_consumers_path=str(leases),
                observe=discover,
                execute=True,
            )
        except ValueError:
            pass
        else:
            raise ProbeError("old generation retirement succeeded while its consumer was active")
        stop_launch(first)
        launchers.remove(first)
        if inject_replacement_interruption:
            child = os.fork()
            if child == 0:
                try:
                    retire_old_generation(
                        config,
                        handover_path=str(handover),
                        runtime_consumers_path=str(leases),
                        observe=discover,
                        execute=True,
                    )
                    os.kill(os.getpid(), signal.SIGKILL)
                except BaseException:
                    os._exit(3)
                os._exit(4)
            _, status = os.waitpid(child, 0)
            if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
                raise ProbeError("retirement interruption did not reach the verified cleanup checkpoint")
        else:
            retire_old_generation(
                config,
                handover_path=str(handover),
                runtime_consumers_path=str(leases),
                observe=discover,
                execute=True,
            )
        if (
            replacement_status(
                config, handover_path=str(handover), runtime_consumers_path=str(leases), observe=discover
            )["selected_generation_ownership_verified"]
            is not True
        ):
            raise ProbeError("B stopped being operational after A retirement")
        retired = recover_generation(
            config, handover_path=str(handover), runtime_consumers_path=str(leases), observe=discover
        )
        if retired["disposition"] != "old_generation_retired":
            raise ProbeError("recovery did not recognise completed exact retirement")
        verify_adversarial_recovery(
            config,
            handover,
            leases,
            expected_disposition="old_generation_retired",
        )
        stop_launch(second)
        launchers.remove(second)
        plan_cleanup(
            config["journal"],
            config["bindings"],
            intent_path=config["intent"],
            selected_profiles=(replacement_kernel,),
            desired_policy=None,
            consumer_policy=policy,
            runtime_consumers_path=leases,
            resolvers=True,
            execute=True,
        )
        dns_responder.terminate()
        dns_responder.wait(timeout=5)
        dns_responder = None
        command("ip", "netns", "del", server_namespace)
        command("ip", "link", "del", bridge)
        verify_host(baseline, observe_host())
        succeeded = True
        print("PASS: production generation replacement, drain and exact retirement", flush=True)
    finally:
        for process in launchers:
            try:
                stop_launch(process)
            except Exception:
                pass
        if dns_responder is not None:
            dns_responder.terminate()
            try:
                dns_responder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dns_responder.kill()
                dns_responder.wait()
        subprocess.run(["ip", "netns", "del", server_namespace], capture_output=True, check=False)
        subprocess.run(["ip", "link", "del", bridge], capture_output=True, check=False)
        if succeeded:
            shutil.rmtree(temporary)
        else:
            print(f"FAILED RUN EVIDENCE RETAINED: {temporary}", file=sys.stderr, flush=True)
            config_path = temporary / "startup.json"
            if config_path.exists():
                print(
                    "VERIFIED CLEANUP COMMAND: "
                    f"sudo {sys.executable} {ROOT / 'nord_tools.py'} manage clear-ownership "
                    f"--config {config_path} --resolvers --execute",
                    file=sys.stderr,
                    flush=True,
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument(
        "--inject-replacement-interruption",
        action="store_true",
        help="Kill the replacement worker after B provisioning and recover the durable prepared handover",
    )
    parser.add_argument("--uid", type=int, help="existing non-root test user")
    parser.add_argument("--gid", type=int, help="existing non-root test group")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: production A/B replacement, gated launches, drain, retirement and host-integrity checks")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0 or not args.uid or not args.gid:
        parser.error("--run-privileged requires Linux root and explicit non-root --uid/--gid")
    missing = [name for name in ("ip", "wg", "nft", "ping") if shutil.which(name) is None]
    if missing or not Path("/usr/bin/sleep").is_file():
        parser.error("missing prerequisites: " + ", ".join(missing or ["/usr/bin/sleep"]))
    try:
        run_probe(args.uid, args.gid, inject_replacement_interruption=args.inject_replacement_interruption)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
