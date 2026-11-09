#!/usr/bin/env python3
"""Validate registered desktop launch behaviour in a nested Linux session.

The probe starts headless Wayland and authenticated X11 servers under the
selected non-root account and uses that account's D-Bus session. It launches
one registered direct child through the public executor and one child through
the same privilege-dropping gate used by VPN launches. Both children exercise
the three protocols and spawn a descendant which must retain the environment
and non-root identity. No network configuration is changed.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nord_tools_internal.nordvpn_application_executor import launch_direct_application  # noqa: E402
from nord_tools_internal.nordvpn_desktop_environment import application_environment  # noqa: E402


class DesktopAcceptanceError(RuntimeError):
    """The active desktop session did not satisfy the launch contract."""


CHILD_SOURCE = r"""import json
import os
from pathlib import Path
import subprocess
import sys


def identity():
    namespace = os.stat('/proc/self/ns/net')
    return {
        'pid': os.getpid(),
        'uid': os.geteuid(),
        'gid': os.getegid(),
        'groups': os.getgroups(),
        'namespace_device': namespace.st_dev,
        'namespace_inode': namespace.st_ino,
        'environment': dict(os.environ),
    }


def check(command):
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed: {result.stderr.strip()[-400:]}')


report = Path(sys.argv[1])
if len(sys.argv) == 3 and sys.argv[2] == '--descendant':
    report.write_text(json.dumps(identity(), sort_keys=True), encoding='utf-8')
    raise SystemExit(0)

check(['wayland-info'])
check(['xdpyinfo'])
check([
    'dbus-send', '--session', '--type=method_call', '--print-reply',
    '--dest=org.freedesktop.DBus', '/', 'org.freedesktop.DBus.ListNames',
])
with open(os.environ['XAUTHORITY'], 'rb') as stream:
    stream.read(1)
descendant_path = report.with_name(report.stem + '-descendant.json')
result = subprocess.run(
    [sys.executable, __file__, str(descendant_path), '--descendant'],
    close_fds=True,
    check=False,
)
if result.returncode:
    raise SystemExit(result.returncode)
evidence = identity()
evidence['descendant'] = json.loads(descendant_path.read_text(encoding='utf-8'))
evidence['endpoints'] = ['wayland', 'x11', 'dbus', 'xauthority']
report.write_text(json.dumps(evidence, sort_keys=True), encoding='utf-8')
"""


def policy(executable: str) -> dict:
    return {
        "version": 1,
        "defaults": {"vpn": "primary"},
        "vpn_profiles": {"primary": {"selection": {"mode": "pinned", "server": "uk715"}}},
        "applications": {"desktop-probe": {"executable": executable, "vpn": "direct"}},
    }


def verify_report(report: dict, *, uid: int, gid: int, environment: dict[str, str]) -> None:
    namespace = os.stat("/proc/self/ns/net")
    expected = {
        "uid": uid,
        "gid": gid,
        "groups": [],
        "namespace_device": namespace.st_dev,
        "namespace_inode": namespace.st_ino,
        "environment": environment,
    }
    for evidence in (report, report.get("descendant", {})):
        if type(evidence.get("pid")) is not int or evidence["pid"] <= 0:
            raise DesktopAcceptanceError("desktop child did not report a valid process identity")
        if {key: evidence.get(key) for key in expected} != expected:
            raise DesktopAcceptanceError("desktop child or descendant identity, namespace or environment differed")
    if report.get("endpoints") != ["wayland", "x11", "dbus", "xauthority"]:
        raise DesktopAcceptanceError("desktop child did not reach every selected session endpoint")


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stderr is not None:
        process.stderr.close()


def _wait_for_endpoint(path: Path, process: subprocess.Popen, label: str, *, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        result = process.poll()
        if result is not None:
            detail = "" if process.stderr is None else process.stderr.read().strip()[-1200:]
            raise DesktopAcceptanceError(f"{label} exited {result} before creating its socket: {detail}")
        time.sleep(0.05)
    raise DesktopAcceptanceError(f"{label} did not create its socket")


def _display_number() -> int:
    for number in range(90, 120):
        if not Path(f"/tmp/.X11-unix/X{number}").exists() and not Path(f"/tmp/.X{number}-lock").exists():
            return number
    raise DesktopAcceptanceError("no unused nested X11 display number is available")


@contextmanager
def nested_desktop_session(uid: int, gid: int, state: Path):
    runtime = Path("/run/user") / str(uid)
    base = application_environment(uid, source={"LANG": os.environ.get("LANG", "C.UTF-8")})
    base["XDG_RUNTIME_DIR"] = str(runtime)
    base["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={runtime / 'bus'}"
    display_number = _display_number()
    xauthority = state / "Xauthority"
    cookie = secrets.token_hex(16)
    xauth = subprocess.run(
        ["xauth", "-f", str(xauthority), "add", f":{display_number}", ".", cookie],
        capture_output=True,
        text=True,
        check=False,
        user=uid,
        group=gid,
        extra_groups=[],
        env=base,
    )
    if xauth.returncode:
        raise DesktopAcceptanceError("could not create nested Xauthority: " + xauth.stderr.strip()[-800:])
    xauthority.chmod(0o600)

    xvfb = subprocess.Popen(
        [
            "Xvfb",
            f":{display_number}",
            "-screen",
            "0",
            "1280x720x24",
            "-nolisten",
            "tcp",
            "-auth",
            str(xauthority),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        user=uid,
        group=gid,
        extra_groups=[],
        env=base,
    )
    wayland_name = f"wayland-nt-{secrets.token_hex(4)}"
    weston_log = state / "weston.log"
    weston = subprocess.Popen(
        [
            "weston",
            "--backend=headless-backend.so",
            "--renderer=pixman",
            f"--socket={wayland_name}",
            "--idle-time=0",
            f"--log={weston_log}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        user=uid,
        group=gid,
        extra_groups=[],
        env=base,
    )
    try:
        _wait_for_endpoint(Path(f"/tmp/.X11-unix/X{display_number}"), xvfb, "Xvfb")
        _wait_for_endpoint(runtime / wayland_name, weston, "Weston")
        source = {
            **base,
            "DISPLAY": f":{display_number}",
            "WAYLAND_DISPLAY": wayland_name,
            "XAUTHORITY": str(xauthority),
            "XDG_SESSION_TYPE": "wayland",
            "XDG_CURRENT_DESKTOP": "NORD_TOOLS_ACCEPTANCE",
        }
        yield source
    finally:
        _stop(weston)
        _stop(xvfb)


def run_gate(
    child_script: Path,
    report: Path,
    *,
    uid: int,
    gid: int,
    environment: dict[str, str],
) -> None:
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    release_r, release_w = os.pipe2(os.O_CLOEXEC)
    process = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "nord_tools_internal" / "nordvpn_launch_gate.py"),
                str(ready_w),
                str(release_r),
                str(uid),
                str(gid),
                sys.executable,
                str(child_script),
                str(report),
            ],
            pass_fds=(ready_w, release_r),
            close_fds=True,
            env=environment,
        )
        os.close(ready_w)
        ready_w = -1
        os.close(release_r)
        release_r = -1
        if os.read(ready_r, 1) != b"R" or process.poll() is not None:
            raise DesktopAcceptanceError("desktop launch gate did not reach its pre-exec barrier")
        os.write(release_w, b"G")
        os.close(release_w)
        release_w = -1
        if process.wait(timeout=15):
            raise DesktopAcceptanceError("desktop launch gate child failed")
    finally:
        for descriptor in (ready_r, ready_w, release_r, release_w):
            if descriptor >= 0:
                os.close(descriptor)
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def run_probe(uid: int, gid: int) -> None:
    with tempfile.TemporaryDirectory(prefix="nt-desktop-acceptance-") as directory:
        temporary = Path(directory)
        temporary.chmod(0o755)
        child_script = temporary / "desktop_child.py"
        child_script.write_text(CHILD_SOURCE, encoding="utf-8")
        child_script.chmod(0o644)
        state = temporary / "state"
        state.mkdir(mode=0o700)
        os.chown(state, uid, gid)
        with nested_desktop_session(uid, gid, state) as source:
            environment = application_environment(uid, desktop_session=True, source=source)
            direct_report = state / "direct.json"
            result = launch_direct_application(
                policy(str(Path(sys.executable).resolve())),
                "desktop-probe",
                (str(child_script), str(direct_report)),
                uid=uid,
                gid=gid,
                desktop_session=True,
                environment_source=source,
            )
            if result:
                raise DesktopAcceptanceError(f"registered direct desktop child returned {result}")
            verify_report(
                json.loads(direct_report.read_text(encoding="utf-8")),
                uid=uid,
                gid=gid,
                environment=environment,
            )
            print("PASS: registered direct desktop child and descendant used Wayland, X11 and D-Bus", flush=True)

            gate_report = state / "gate.json"
            run_gate(child_script, gate_report, uid=uid, gid=gid, environment=environment)
            verify_report(
                json.loads(gate_report.read_text(encoding="utf-8")),
                uid=uid,
                gid=gid,
                environment=environment,
            )
            print("PASS: VPN launch gate preserved the desktop session after dropping privileges", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-privileged", action="store_true")
    parser.add_argument("--uid", type=int, help="active non-root desktop user")
    parser.add_argument("--gid", type=int, help="active non-root desktop group")
    args = parser.parse_args(argv)
    if not args.run_privileged:
        print("DRY RUN: nested Wayland, X11 and D-Bus registered desktop launch acceptance")
        print("No network namespace or network configuration will be changed.")
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
    missing = [
        name for name in ("weston", "wayland-info", "Xvfb", "xauth", "xdpyinfo", "dbus-send") if not shutil.which(name)
    ]
    if missing:
        parser.error("missing prerequisites: " + ", ".join(missing))
    try:
        run_probe(args.uid, args.gid)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
