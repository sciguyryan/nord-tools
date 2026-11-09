#!/usr/bin/env python3
"""Privileged acceptance for concurrent registered application lifecycles.

The probe provisions one shared and two isolated production allocations, then
keeps registered applications on all three allocations and an explicit direct
application alive together. It verifies allocation reuse and separation,
lease-protected retirement, exact cleanup and refusal without direct fallback.
Packet confinement and desktop integration remain separate acceptance scopes.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import nordvpn_manage  # noqa: E402
from nord_tools_internal.nordvpn_allocation_profiles import kernel_profile_for_allocation  # noqa: E402
from nord_tools_internal.nordvpn_cleanup_executor import plan_cleanup  # noqa: E402
from nord_tools_internal.nordvpn_profiles import validate_policy  # noqa: E402
from nord_tools_internal.nordvpn_registry import RegistryError  # noqa: E402
from nord_tools_internal.nordvpn_runtime_consumers import (  # noqa: E402
    initialise_runtime_consumers,
    read_runtime_consumers,
)
from tools.probe_live_tunnel_replacement import (  # noqa: E402
    finish_launch,
    launch,
    stop_launch,
    verify_launch_evidence,
    wait_for_lease,
    wait_for_report,
)


class ProbeError(RuntimeError):
    """Concurrent application acceptance could not establish a safe result."""


def command(*argv: str, input_data: bytes | None = None) -> bytes:
    result = subprocess.run(argv, input=input_data, capture_output=True, check=False, timeout=15)
    if result.returncode:
        raise ProbeError(f"prerequisite command failed: {argv[0]}")
    return result.stdout.strip()


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def tunnel_plan(index: int, peer_public_key: str) -> dict:
    return {
        "peer_public_key": peer_public_key,
        "endpoint_address": "198.51.100.10",
        "endpoint_port": 51820,
        "tunnel_addresses": [f"10.213.{220 + index}.2/32"],
        "peer_allowed_ips": [f"10.213.{220 + index}.1/32"],
        "underlay": {
            "namespace_address": f"10.214.{40 + index}.2/30",
            "host_address": f"10.214.{40 + index}.1/30",
        },
    }


def verify_exact_leases(leases: list[dict], expected: dict[str, str]) -> None:
    """Reject duplicate, missing, unexpected or misallocated runtime leases."""
    if not isinstance(leases, list) or len(leases) != len(expected):
        raise ProbeError("concurrent VPN lease count did not match registered children")
    actual = collections.Counter(item.get("application") for item in leases if isinstance(item, dict))
    if actual != collections.Counter(expected.keys()):
        raise ProbeError("concurrent VPN lease identities were not exact")
    for item in leases:
        if not isinstance(item, dict) or item.get("allocation_key") != expected[item["application"]]:
            raise ProbeError("concurrent VPN lease allocation identity was incorrect")


def wait_for_lease_release(path: Path, policy: dict, *, timeout: float = 10) -> None:
    """Allow launcher cleanup to finish, without guessing that leases were released."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not read_runtime_consumers(path, policy)["leases"]:
            return
        time.sleep(0.1)
    raise ProbeError("launcher termination did not release all runtime leases")


def recover_failed_allocations(
    journal: Path, bindings: Path, intents: Path, leases: Path, policy: dict, profiles: tuple[str, ...]
) -> str:
    """Retire only verified owned allocations after the children have released leases."""
    try:
        wait_for_lease_release(leases, policy)
        plan_cleanup(
            journal,
            bindings,
            intent_path=intents,
            selected_profiles=profiles,
            consumer_policy=policy,
            released_consumers=("shared-a", "shared-b", "isolated-a", "isolated-b"),
            runtime_consumers_path=leases,
            execute=True,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return f"ownership-verified recovery refused or failed: {exc}"
    return "ownership-verified recovery completed"


def write_child_script(path: Path) -> None:
    path.write_text(
        "import json, os, pathlib, sys, time\n"
        "report = pathlib.Path(sys.argv[1])\n"
        "release = pathlib.Path(sys.argv[2])\n"
        "namespace = os.stat('/proc/self/ns/net')\n"
        "evidence = {\n"
        "    'pid': os.getpid(),\n"
        "    'uid': os.geteuid(),\n"
        "    'gid': os.getegid(),\n"
        "    'groups': os.getgroups(),\n"
        "    'namespace_device': namespace.st_dev,\n"
        "    'namespace_inode': namespace.st_ino,\n"
        "    'executable': os.readlink('/proc/self/exe'),\n"
        "}\n"
        "with report.open('x', encoding='utf-8') as stream:\n"
        "    json.dump(evidence, stream, sort_keys=True)\n"
        "    stream.flush()\n"
        "    os.fsync(stream.fileno())\n"
        "deadline = time.monotonic() + 300\n"
        "while not release.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.05)\n"
        "raise SystemExit(0 if release.exists() else 124)\n",
        encoding="utf-8",
    )
    path.chmod(0o644)


def namespace_for_profile(journal: dict, profile: str) -> str:
    states = {item["allocation_id"]: item["state"] for item in journal["events"]}
    namespaces = [
        item["identifier"]
        for item in journal["allocations"]["resources"]
        if item["profile"] == profile and item["kind"] == "namespace" and states.get(item["allocation_id"]) == "active"
    ]
    if len(namespaces) != 1:
        raise ProbeError(f"profile {profile} does not have one active namespace")
    return namespaces[0]


def verify_vpn_launch(
    journal: dict,
    leases_path: Path,
    policy: dict,
    report_path: Path,
    *,
    uid: int,
    gid: int,
    application: str,
    allocation_key: str,
    kernel_profile: str,
) -> tuple[dict, dict]:
    lease = wait_for_lease(leases_path, policy, application, "unversioned")
    report = wait_for_report(report_path)
    namespace = namespace_for_profile(journal, kernel_profile)
    verify_launch_evidence(
        report,
        lease,
        uid=uid,
        gid=gid,
        application=application,
        generation="unversioned",
        allocation_key=allocation_key,
        kernel_profile=kernel_profile,
        namespace_stat=os.stat(f"/run/netns/{namespace}"),
        executable=policy["applications"][application]["executable"],
    )
    return report, lease


def verify_direct_launch(report: dict, *, uid: int, gid: int, host_namespace: os.stat_result, executable: str) -> None:
    expected = {
        "uid": uid,
        "gid": gid,
        "groups": [],
        "namespace_device": host_namespace.st_dev,
        "namespace_inode": host_namespace.st_ino,
        "executable": executable,
    }
    if type(report.get("pid")) is not int or report["pid"] <= 0:
        raise ProbeError("direct registered child did not report a valid process identity")
    if {key: report.get(key) for key in expected} != expected or set(report) != {"pid", *expected}:
        raise ProbeError("explicit direct child did not retain the host namespace and non-root identity")


def finish_direct(process: subprocess.Popen, release_path: Path) -> None:
    release_path.touch(mode=0o600)
    try:
        result = process.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ProbeError("explicit direct child did not exit") from exc
    if result != 0:
        raise ProbeError(f"explicit direct launcher returned {result}")


def refused_launch(
    config: Path,
    leases: Path,
    application: str,
    uid: int,
    gid: int,
    arguments: tuple[str, ...],
    report_path: Path,
) -> None:
    process = launch(config, leases, application, uid, gid, arguments)
    try:
        result = process.wait(timeout=10)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ProbeError("unavailable VPN-bound launch did not refuse promptly") from exc
    if result == 0 or report_path.exists():
        raise ProbeError("VPN-bound launch used an unavailable allocation or direct fallback")


def run_probe(uid: int, gid: int) -> None:
    if os.geteuid() != 0:
        raise ProbeError("root privileges are required")
    for binary in ("ip", "wg", "nft"):
        if shutil.which(binary) is None:
            raise ProbeError(f"missing prerequisite: {binary}")

    temporary = Path(tempfile.mkdtemp(prefix="nt-concurrent-applications-"))
    temporary.chmod(0o755)
    launchers: list[subprocess.Popen] = []
    succeeded = False
    recovery_context = None
    print(
        f"Creating shared and isolated application allocations under {temporary}; inspect /run/netns if interrupted",
        flush=True,
    )
    try:
        executable = str(Path(sys.executable).resolve())
        policy_document = {
            "version": 1,
            "defaults": {"vpn": "shared"},
            "vpn_profiles": {
                "shared": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"},
                "isolated": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "isolated"},
            },
            "applications": {
                "shared-a": {"executable": executable, "vpn": "shared"},
                "shared-b": {"executable": executable, "vpn": "shared"},
                "isolated-a": {"executable": executable, "vpn": "isolated"},
                "isolated-b": {"executable": executable, "vpn": "isolated"},
                "direct-a": {"executable": executable, "vpn": "direct"},
            },
        }
        policy = validate_policy(policy_document)
        isolated_profiles = {
            application: kernel_profile_for_allocation(
                f"application:{application}:profile:isolated", "isolated", "isolated"
            )
            for application in ("isolated-a", "isolated-b")
        }
        profiles = ("shared", isolated_profiles["isolated-a"], isolated_profiles["isolated-b"])
        tunnels = {}
        credentials = {}
        for index, profile in enumerate(profiles):
            credential = temporary / f"{profile}.key"
            credential.write_bytes(command("wg", "genkey") + b"\n")
            credential.chmod(0o600)
            peer_private = command("wg", "genkey")
            tunnels[profile] = tunnel_plan(index, command("wg", "pubkey", input_data=peer_private).decode("ascii"))
            credentials[profile] = str(credential)

        policy_path = temporary / "policy.json"
        config_path = temporary / "startup.json"
        journal_path = temporary / "journal.json"
        bindings_path = temporary / "bindings.json"
        intents_path = temporary / "intents.json"
        leases_path = temporary / "leases.json"
        child_state = temporary / "children"
        child_state.mkdir(mode=0o700)
        os.chown(child_state, uid, gid)
        child_script = temporary / "inspect_child.py"
        write_child_script(child_script)
        write(policy_path, policy_document)
        config = {
            "version": 1,
            "policy": str(policy_path),
            "journal": str(journal_path),
            "bindings": str(bindings_path),
            "intent": str(intents_path),
            "run_record": str(temporary / "runs.json"),
            "tunnels": tunnels,
            "credentials": credentials,
        }
        write(config_path, config)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = nordvpn_manage.main(["restore-startup", "--config", str(config_path)])
        restored = json.loads(output.getvalue()).get("restored", []) if status == 0 else []
        if sorted(restored) != sorted(profiles):
            raise ProbeError("shared and isolated production allocations were not restored")
        initialise_runtime_consumers(leases_path, policy)
        recovery_context = (journal_path, bindings_path, intents_path, leases_path, policy, profiles)
        journal = read(journal_path)
        recorded_namespaces = {namespace_for_profile(journal, profile) for profile in profiles}
        if len(recorded_namespaces) != 3:
            raise ProbeError("shared and isolated allocations did not receive distinct namespaces")

        processes = {}
        reports = {}
        releases = {}
        for application in policy["applications"]:
            report = child_state / f"{application}.json"
            release = temporary / f"release-{application}"
            process = launch(
                config_path,
                leases_path,
                application,
                uid,
                gid,
                (str(child_script), str(report), str(release)),
            )
            launchers.append(process)
            processes[application] = process
            reports[application] = report
            releases[application] = release

        vpn_evidence = {}
        for application in ("shared-a", "shared-b"):
            vpn_evidence[application] = verify_vpn_launch(
                journal,
                leases_path,
                policy,
                reports[application],
                uid=uid,
                gid=gid,
                application=application,
                allocation_key="profile:shared",
                kernel_profile="shared",
            )
        for application in ("isolated-a", "isolated-b"):
            vpn_evidence[application] = verify_vpn_launch(
                journal,
                leases_path,
                policy,
                reports[application],
                uid=uid,
                gid=gid,
                application=application,
                allocation_key=f"application:{application}:profile:isolated",
                kernel_profile=isolated_profiles[application],
            )
        direct_report = wait_for_report(reports["direct-a"])
        verify_direct_launch(
            direct_report,
            uid=uid,
            gid=gid,
            host_namespace=os.stat("/proc/self/ns/net"),
            executable=executable,
        )

        shared_reports = [vpn_evidence[name][0] for name in ("shared-a", "shared-b")]
        isolated_reports = [vpn_evidence[name][0] for name in ("isolated-a", "isolated-b")]
        if shared_reports[0]["namespace_inode"] != shared_reports[1]["namespace_inode"]:
            raise ProbeError("shared registered applications did not reuse one namespace")
        if isolated_reports[0]["namespace_inode"] == isolated_reports[1]["namespace_inode"]:
            raise ProbeError("isolated registered applications shared a namespace")
        active_leases = read_runtime_consumers(leases_path, policy)["leases"]
        verify_exact_leases(
            active_leases,
            {
                "shared-a": "profile:shared",
                "shared-b": "profile:shared",
                "isolated-a": "application:isolated-a:profile:isolated",
                "isolated-b": "application:isolated-b:profile:isolated",
            },
        )
        print("PASS: concurrent shared applications reused one production allocation", flush=True)
        print("PASS: concurrent isolated applications used independent production allocations", flush=True)
        print("PASS: explicit direct application remained on the host without a VPN lease", flush=True)

        isolated_a = isolated_profiles["isolated-a"]
        try:
            plan_cleanup(
                journal_path,
                bindings_path,
                intent_path=intents_path,
                selected_profiles=(isolated_a,),
                consumer_policy=policy,
                released_consumers=("isolated-a",),
                runtime_consumers_path=leases_path,
                execute=True,
            )
        except RegistryError as exc:
            if "runtime consumer leases retain" not in str(exc):
                raise ProbeError(f"unexpected live-lease retirement refusal: {exc}") from exc
        else:
            raise ProbeError("live isolated lease permitted allocation retirement")
        if not Path("/run/netns", namespace_for_profile(read(journal_path), isolated_a)).exists():
            raise ProbeError("lease refusal disturbed the isolated allocation")
        print("PASS: live launcher lease blocked isolated allocation retirement", flush=True)

        finish_launch(processes["isolated-a"], releases["isolated-a"], leases_path, policy, "isolated-a")
        launchers.remove(processes["isolated-a"])
        retired = plan_cleanup(
            journal_path,
            bindings_path,
            intent_path=intents_path,
            selected_profiles=(isolated_a,),
            consumer_policy=policy,
            released_consumers=("isolated-a",),
            runtime_consumers_path=leases_path,
            execute=True,
        )
        if len(retired["deletions"]) != 4:
            raise ProbeError("released isolated allocation did not retire exactly four resources")

        failed_report = child_state / "isolated-a-refused.json"
        failed_release = temporary / "release-isolated-a-refused"
        refused_launch(
            config_path,
            leases_path,
            "isolated-a",
            uid,
            gid,
            (str(child_script), str(failed_report), str(failed_release)),
            failed_report,
        )
        if any(item["application"] == "isolated-a" for item in read_runtime_consumers(leases_path, policy)["leases"]):
            raise ProbeError("failed VPN-bound relaunch left a durable lease")
        if processes["direct-a"].poll() is not None:
            raise ProbeError("explicit direct application did not remain independent of VPN launch failure")
        print("PASS: unavailable VPN-bound allocation refused without execution or direct fallback", flush=True)

        for application in ("shared-a", "shared-b", "isolated-b"):
            finish_launch(processes[application], releases[application], leases_path, policy, application)
            launchers.remove(processes[application])
        finish_direct(processes["direct-a"], releases["direct-a"])
        launchers.remove(processes["direct-a"])
        if read_runtime_consumers(leases_path, policy)["leases"]:
            raise ProbeError("concurrent application exits left runtime leases")

        remaining_profiles = ("shared", isolated_profiles["isolated-b"])
        cleanup = plan_cleanup(
            journal_path,
            bindings_path,
            intent_path=intents_path,
            selected_profiles=remaining_profiles,
            consumer_policy=policy,
            released_consumers=("shared-a", "shared-b", "isolated-b"),
            runtime_consumers_path=leases_path,
            execute=True,
        )
        if len(cleanup["deletions"]) != 8:
            raise ProbeError("final shared and isolated retirement did not remove eight resources")
        if any(Path("/run/netns", namespace).exists() for namespace in recorded_namespaces):
            raise ProbeError("an application allocation namespace remained after verified retirement")
        print("PASS: released shared and isolated allocations retired with no residual leases", flush=True)
        succeeded = True
    finally:
        for process in launchers:
            try:
                stop_launch(process)
            except Exception:
                pass
        if succeeded:
            shutil.rmtree(temporary)
        else:
            if recovery_context is not None:
                print(recover_failed_allocations(*recovery_context), file=sys.stderr, flush=True)
            print(f"FAILED RUN EVIDENCE RETAINED: {temporary}", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument("--uid", type=int, help="existing non-root test user")
    parser.add_argument("--gid", type=int, help="existing non-root test group")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: concurrent shared, isolated and direct registered launches, lease refusal and exact retirement")
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
    try:
        run_probe(args.uid, args.gid)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
