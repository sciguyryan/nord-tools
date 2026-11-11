#!/usr/bin/env python3
"""Manage a disposable Nord Tools acceptance guest without changing host routing.

All libvirt operations target the system connection and a single named guest.
The GUI delegates blocking operations to workers so that its event loop remains usable.
"""

import argparse
import ast
import base64
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import fcntl
import fnmatch
import hashlib
import io
import ipaddress
import json
import os
import queue
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

VM = "nord-tools-acceptance"
URI = "qemu:///system"
IMAGE = "Arch-Linux-x86_64-cloudimg.qcow2"
BASE = "https://fastly.mirror.pkgbuild.com/images/latest"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "nord-tools" / "acceptance" / "images"
KNOWN_HOSTS = CACHE.parent / "known_hosts"
SSH_PRIVATE_KEY = CACHE.parent / "id_ed25519"
SSH_PUBLIC_KEY = CACHE.parent / "id_ed25519.pub"
SEED = Path("/var/lib/libvirt/images/nord-tools-acceptance-seed.iso")
DISK = Path("/var/lib/libvirt/images/nord-tools-acceptance.qcow2")
GUEST_MAC = "52:54:00:4e:54:08"
SSH_HOST = "127.0.0.1"
SSH_PORT = int(os.environ.get("NORD_TOOLS_ACCEPTANCE_SSH_PORT", "22222"))
SOURCE_ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/home/arch/nord-tools"
GUEST_ATTESTATION = "/etc/nord-tools-acceptance-spec"
PROVISION_REVISION = "4"
HOST_ACCEPTANCE_UNIT = "nord-tools-host-d1.service"
HOST_ACCEPTANCE_RESULT = "/var/tmp/nord-tools-host-d1-result.json"
HOST_ACCEPTANCE_EVIDENCE = "/var/tmp/nord-tools-host-d1-evidence"
HOST_FAILURE_UNIT = "nord-tools-host-d2.service"
HOST_FAILURE_RESULT = "/var/tmp/nord-tools-host-d2-result.json"
HOST_FAILURE_EVIDENCE = "/var/tmp/nord-tools-host-d2-evidence"
HOST_REBOOT_RESULT = "/var/tmp/nord-tools-d3-result.json"
HOST_REBOOT_PROBE = "/var/lib/nord-tools-d3/source/tools/probe_host_reboot_acceptance.py"
HOST_REBOOT_PREPARE = f"{REMOTE_ROOT}/tools/probe_host_reboot_acceptance.py"
RESULT_CACHE_SCHEMA = 2
IMPACT_POLICY = "tests/impact-rules.json"
RESULT_CACHE = CACHE.parent / "development-results-v1.json"
RESULT_CACHE_LOCK = CACHE.parent / "development-results-v1.lock"
SCENARIO_PROBES = {
    "network": "tools/probe_network_isolation_adversarial_acceptance.py",
    "application": "tools/probe_application_lifecycle_acceptance.py",
    "desktop": "tools/probe_desktop_launch_acceptance.py",
    "d1": "tools/probe_host_domain_acceptance.py",
    "d2": "tools/probe_host_failure_recovery_acceptance.py",
    "d3": "tools/probe_host_reboot_acceptance.py",
}
REQUIRED_PACKAGES = (
    "git",
    "python",
    "python-pip",
    "python-pytest",
    "ruff",
    "nodejs",
    "npm",
    "openssh",
    "sudo",
    "nftables",
    "wireguard-tools",
    "curl",
    "iproute2",
    "iputils",
    "bind",
    "dbus",
    "jq",
    "qemu-guest-agent",
    "weston",
    "wayland-utils",
    "xorg-server-xvfb",
    "xorg-xauth",
    "xorg-xdpyinfo",
)
_PRIVILEGE_PASSWORD = None
_CLI_PROGRESS = False
_COLOURBLIND = False
_ANSI_GREEN = "\033[32m"
_ANSI_RED = "\033[31m"
_ANSI_BLUE = "\033[38;5;33m"
_ANSI_ORANGE = "\033[38;5;208m"
_ANSI_RESET = "\033[0m"

if not 1024 <= SSH_PORT <= 65535:
    raise ValueError("NORD_TOOLS_ACCEPTANCE_SSH_PORT must be between 1024 and 65535.")


def run(*args, check=True, timeout=30):
    """Execute a command without a shell and preserve useful diagnostic output."""
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=timeout)


def progress(message):
    if _CLI_PROGRESS:
        print(message, flush=True)


def colourise_acceptance_status(line, *, enabled, colourblind=False):
    """Colour PASS and FAIL markers without changing captured evidence."""
    if not enabled:
        return line
    colours = {"PASS": _ANSI_BLUE, "FAIL": _ANSI_ORANGE} if colourblind else {"PASS": _ANSI_GREEN, "FAIL": _ANSI_RED}
    return re.sub(
        r"\b(PASS|FAIL)(?=:|\b)",
        lambda match: colours[match.group(1)] + match.group(1) + _ANSI_RESET,
        line,
    )


def virsh(*args, check=True):
    return run("virsh", "-c", URI, *args, check=check)


def status():
    """Return observed state; do not confuse guest existence with readiness."""
    listing = virsh("list", "--all", "--name", check=False)
    if listing.returncode:
        raise RuntimeError("Unable to query libvirt domains: " + (listing.stderr.strip() or "unknown error"))
    if VM not in listing.stdout.splitlines():
        return "Absent"
    result = virsh("domstate", VM, check=False)
    if result.returncode:
        raise RuntimeError("Unable to read guest state: " + (result.stderr.strip() or "unknown error"))
    return result.stdout.strip()


def address():
    """Return the IPv4 address reported for the expected guest MAC."""
    for source in ("agent", "lease"):
        result = virsh("domifaddr", VM, "--source", source, check=False)
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[1].lower() != GUEST_MAC.lower() or fields[2] != "ipv4":
                continue
            candidate = fields[3].split("/", 1)[0]
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not ip.is_loopback and not ip.is_link_local:
                return str(ip)
    return None


def ssh_endpoint():
    """Return the loopback-only passt forwarding endpoint."""
    return f"{SSH_HOST}:{SSH_PORT}"


def ssh_args(*args):
    """Build SSH arguments, preserving remote command argument boundaries."""
    KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    command = (
        "ssh",
        "-F",
        "/dev/null",
        "-p",
        str(SSH_PORT),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        str(SSH_PRIVATE_KEY),
        f"arch@{SSH_HOST}",
    )
    if not args:
        return command
    # OpenSSH joins separate command arguments with spaces before asking the
    # remote login shell to parse them. Quote the complete argv here so values
    # such as Python's -c program remain one remote argument.
    return (*command, shlex.join(args))


def ssh(*args, timeout=15, check=False):
    """Run a command through passt's loopback-only SSH forward."""
    return run(*ssh_args(*args), check=check, timeout=timeout)


def port_available():
    """Check that passt can bind its loopback forwarding port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind((SSH_HOST, SSH_PORT))
        except OSError:
            return False
    return True


def python_health():
    """Check guest Python independently of cloud-init's Python entry point.

    A rolling Arch upgrade can briefly replace the interpreter before its
    matching standard library is available. A broken cloud-init command is
    therefore not by itself evidence that cloud-init has failed.
    """
    try:
        result = ssh("/usr/bin/python", "-c", "import operator, argparse, sys; print(sys.version)")
    except (OSError, subprocess.SubprocessError) as exc:
        return f"Python health probe unavailable: {exc}"
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        return f"Guest Python standard library unavailable: {detail[:700]}"
    return None


def guest_boot_diagnostics():
    """Collect bounded, read-only diagnostics without relying on guest Python."""
    commands = (
        ("Python package and stdlib", ("sh", "-c", "pacman -Q python; ls -l /usr/lib/python*/operator.py")),
        ("Package operations", ("sh", "-c", "ps -eo pid,comm,args | grep -E '[p]acman|[c]loud-init'")),
        (
            "Cloud-init logs",
            (
                "sudo",
                "-n",
                "journalctl",
                "-b",
                "-u",
                "cloud-init.service",
                "-u",
                "cloud-config.service",
                "-u",
                "cloud-final.service",
                "--no-pager",
                "-n",
                "55",
            ),
        ),
    )
    sections = []
    for title, args in commands:
        try:
            result = ssh(*args, timeout=12)
            output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
            sections.append(f"{title}:\n{output[-3500:] or '(no output)'}")
        except (OSError, subprocess.SubprocessError) as exc:
            sections.append(f"{title}: unavailable ({exc})")
    return "\n".join(sections)


def readiness():
    """Require healthy guest Python and a successful cloud-init completion.

    A cloud-init invocation can fail while pacman replaces Python or its
    standard library. Such a failure is not a terminal provisioning result:
    only an observable cloud-init error/degraded status is terminal.
    """
    if status() != "running":
        return "Guest is not running"
    try:
        result = ssh("sudo", "-n", "cloud-init", "status", "--long")
    except (subprocess.SubprocessError, OSError) as exc:
        return f"SSH or cloud-init unavailable: {exc}"
    output = normalise_cloud_init_status(
        "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
    )
    if result.returncode == 255:
        return "SSH or cloud-init unavailable: " + (output or "SSH exited with status 255")
    health = python_health()
    if health:
        return "Guest Python unhealthy: " + health + "\n" + output
    if "status: error" in output or "status: degraded" in output:
        return "Provisioning failed:\n" + output
    if "status: done" in output and result.returncode == 0:
        return "Ready: cloud-init completed successfully\n" + output
    if result.returncode != 0:
        # A nonzero exit alone is not a reliable cloud-init failure while the
        # guest is upgrading Python. Keep polling until a structured terminal
        # status is available or the overall readiness deadline expires.
        return "Cloud-init status temporarily unavailable: " + (output or f"exit status {result.returncode}")
    return "Provisioning in progress:\n" + (output or "No status returned")


def normalise_cloud_init_status(output):
    """Label cloud-init boot-relative timestamps without presenting them as 1970 dates."""
    lines = []
    for line in output.splitlines():
        prefix = "last_update: "
        if not line.startswith(prefix):
            lines.append(line)
            continue
        value = line.removeprefix(prefix)
        try:
            timestamp = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            lines.append(line)
            continue
        if timestamp.year != 1970:
            lines.append(line)
            continue
        elapsed = max(0, round(timestamp.timestamp()))
        lines.append(f"completion_offset: {elapsed} seconds after boot")
    return "\n".join(lines)


def wait_ready(timeout=360, interval=5):
    """Poll until positive readiness or a genuine terminal provisioning state.

    Use the overall deadline for transient Python/cloud-init inconsistencies:
    package transactions can legitimately take longer than 90 seconds on a
    slow guest. Never treat a failed status invocation as a successful boot.
    """
    deadline = time.monotonic() + timeout
    last = "Not checked"
    reported = None
    while time.monotonic() < deadline:
        last = readiness()
        summary = last.splitlines()[0]
        if summary != reported:
            elapsed = int(timeout - max(0, deadline - time.monotonic()))
            progress(f"Readiness ({elapsed}s): {summary}")
            reported = summary
        if last.startswith("Ready:"):
            return last
        if last.startswith("Provisioning failed:") or last == "Guest is not running":
            raise RuntimeError(last + "\nGuest diagnostics:\n" + guest_boot_diagnostics())
        time.sleep(interval)
    raise RuntimeError(
        f"Guest was not ready after {timeout} seconds. Last observation: {last}"
        + "\nGuest diagnostics:\n"
        + guest_boot_diagnostics()
    )


def digest_from_text(text):
    """Accept only a well-formed SHA-256 digest associated with the cloud image."""
    for line in text.splitlines():
        match = re.fullmatch(r"\s*([0-9a-fA-F]{64})(?:\s+\*?(.+))?\s*", line)
        if match and (not match.group(2) or Path(match.group(2)).name == IMAGE):
            return match.group(1).lower()
    raise ValueError("The downloaded SHA-256 file has no valid image digest.")


def download(url, target):
    """Write atomically to prevent partial downloads being treated as cached files."""
    fd, temporary = tempfile.mkstemp(prefix=".download-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as output, urllib.request.urlopen(url, timeout=60) as source:
            shutil.copyfileobj(source, output)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def verify(path, digest):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest() == digest


def cache_image(refresh=False):
    """Reuse verified bytes; fetch the publisher's current checksum on each invocation.

    The digest and image share a transport trust boundary. A checksum alone does
    not authenticate the publisher; signatures should be added before high-trust use.
    """
    CACHE.mkdir(parents=True, exist_ok=True, mode=0o700)
    checksum = CACHE / f"{IMAGE}.SHA256"
    image = CACHE / IMAGE
    progress("Fetching the Arch Linux cloud image checksum...")
    download(f"{BASE}/{IMAGE}.SHA256", checksum)
    expected = digest_from_text(checksum.read_text(encoding="utf-8"))
    if image.is_file() and verify(image, expected) and not refresh:
        progress("Reusing the verified cached cloud image.")
        return f"Verified cached image: {image}"
    progress("Downloading and verifying the Arch Linux cloud image...")
    download(f"{BASE}/{IMAGE}", image)
    if not verify(image, expected):
        image.unlink(missing_ok=True)
        raise RuntimeError("Downloaded image failed SHA-256 verification.")
    return f"Image downloaded and verified: {image}"


def privileged(*args, timeout=120):
    """Use an explicit GUI authorisation; never put a password in command arguments."""
    if _PRIVILEGE_PASSWORD is None:
        result = run("sudo", "-n", *args, check=False, timeout=timeout)
    else:
        result = subprocess.run(
            ["sudo", "-S", "-p", "", *args],
            input=_PRIVILEGE_PASSWORD + "\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result


def check_dependencies():
    required = ("virsh", "virt-install", "qemu-img", "xorriso", "ssh", "ssh-keygen", "sudo", "passt", "tar")
    missing = [name for name in required if not shutil.which(name)]
    if missing:
        raise RuntimeError("Missing host dependencies: " + ", ".join(missing))


def acceptance_public_key():
    """Create or read the dedicated non-interactive key for this disposable VM."""
    SSH_PRIVATE_KEY.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if SSH_PRIVATE_KEY.exists() != SSH_PUBLIC_KEY.exists():
        raise RuntimeError(f"Incomplete acceptance SSH keypair under {SSH_PRIVATE_KEY.parent}; remove it and retry.")
    if not SSH_PRIVATE_KEY.exists():
        progress("Generating a dedicated acceptance SSH key...")
        result = run(
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "nord-tools-acceptance",
            "-f",
            str(SSH_PRIVATE_KEY),
            check=False,
        )
        if result.returncode:
            raise RuntimeError("Unable to generate the acceptance SSH key: " + result.stderr.strip())
    SSH_PRIVATE_KEY.chmod(0o600)
    SSH_PUBLIC_KEY.chmod(0o600)
    return SSH_PUBLIC_KEY.read_text(encoding="utf-8").strip()


def provisioning_spec(key):
    """Fingerprint the immutable cloud-init contract, not the source checkout."""
    return hashlib.sha256(
        json.dumps(
            {
                "revision": PROVISION_REVISION,
                "vm": VM,
                "mac": GUEST_MAC,
                "port": SSH_PORT,
                "ssh_key": key,
                "memory_mib": 4096,
                "vcpus": 4,
                "disk_gib": 32,
                "packages": REQUIRED_PACKAGES,
                "network": "passt",
                "cpu": "host-passthrough",
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()


def guest_command(script, *, timeout=30):
    """Pass scripts through SSH stdin; never interpolate multiline code into a shell."""
    return subprocess.run(
        ssh_args("python", "-"), input=script, text=True, capture_output=True, timeout=timeout, check=False
    )


def guest_provisioning_issues():
    """Check the reusable guest contract without requiring a pristine baseline."""
    if not SSH_PUBLIC_KEY.is_file():
        return ["acceptance SSH public key missing"]
    expected = provisioning_spec(SSH_PUBLIC_KEY.read_text(encoding="utf-8").strip())
    try:
        probe = guest_command(f"""from pathlib import Path
import json, subprocess
p = Path('/etc/nord-tools-acceptance-spec')
try:
    spec = p.read_text().strip()
except OSError:
    spec = ''
packages = {REQUIRED_PACKAGES!r}
missing = [package for package in packages if subprocess.run(
    ['pacman', '-Q', package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
).returncode]
print(json.dumps({{'spec': spec, 'missing': missing}}))
""")
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"guest provisioning attestation failed: {exc}"]
    if probe.returncode:
        return ["guest provisioning attestation unavailable"]
    try:
        report = json.loads(probe.stdout)
    except (ValueError, TypeError):
        return ["guest provisioning attestation malformed"]
    issues = []
    if report.get("spec") != expected:
        issues.append("guest provisioning specification differs")
    missing = report.get("missing")
    if not isinstance(missing, list):
        issues.append("guest provisioning attestation malformed")
    elif missing:
        issues.append("guest dependencies missing: " + ", ".join(missing))
    return issues


def inspect_guest():
    """Observe actual domain and guest state; uncertainty always forbids reuse."""
    reasons = []
    state = status()
    if state == "Absent":
        return ["domain absent"]
    if state != "running":
        return [f"domain state is {state!r}"]
    try:
        xml = ET.fromstring(virsh("dumpxml", VM).stdout)
        memory = xml.findtext("memory")
        memory_unit = xml.find("memory").get("unit", "KiB") if xml.find("memory") is not None else None
        if memory != "4194304" or memory_unit != "KiB":
            reasons.append("domain memory differs")
        if xml.findtext("vcpu") != "4":
            reasons.append("domain CPU count differs")
        cpu = xml.find("cpu")
        if cpu is None or cpu.get("mode") != "host-passthrough":
            reasons.append("domain CPU mode differs")
        disks = xml.findall("./devices/disk")

        def matching_disk(path, device):
            return any(
                d.get("device") == device and d.find("source") is not None and d.find("source").get("file") == str(path)
                for d in disks
            )

        if not matching_disk(DISK, "disk") or not matching_disk(SEED, "cdrom"):
            reasons.append("domain storage differs")
        interfaces = xml.findall("./devices/interface")
        if (
            len(interfaces) != 1
            or interfaces[0].get("type") != "user"
            or interfaces[0].find("mac") is None
            or interfaces[0].find("mac").get("address", "").lower() != GUEST_MAC.lower()
        ):
            reasons.append("domain network differs")
        # A passt forwarding change can make an otherwise valid domain unreachable.
        if f"{SSH_PORT}" not in ET.tostring(xml, encoding="unicode"):
            reasons.append("domain SSH forwarding is not verified")
        if not DISK.is_file() or not SEED.is_file():
            reasons.append("guest storage missing")
    except (OSError, ValueError, ET.ParseError, RuntimeError, AttributeError) as exc:
        reasons.append(f"domain inspection failed: {exc}")
    ready = readiness()
    if not ready.startswith("Ready:"):
        reasons.append("guest readiness not verified: " + ready.splitlines()[0])
        return reasons
    reasons.extend(guest_provisioning_issues())
    # A successful acceptance run does not prove a clean baseline. This marker
    # is set before any privileged tests, and cleared only by fresh provisioning.
    try:
        taint = ssh("test", "!", "-e", "/var/tmp/nord-tools-acceptance-used", timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        reasons.append(f"guest baseline check failed: {exc}")
        return reasons
    if taint.returncode:
        reasons.append("guest has run privileged acceptance; baseline is not certified clean")
    return reasons


def rebuild_plan(force=False):
    """Produce a conservative, explainable reuse decision without mutation."""
    if force:
        return (False, ["forced clean rebuild requested"])
    reasons = inspect_guest()
    return (not reasons, reasons)


def provision():
    """Provision with passt userspace networking and no host bridge or firewall changes."""
    if status() != "Absent":
        raise RuntimeError(f"{VM} already exists. Use Rebuild to replace it.")
    check_dependencies()
    key = acceptance_public_key()
    if not port_available():
        raise RuntimeError(f"Loopback SSH port {SSH_PORT} is already in use. Set NORD_TOOLS_ACCEPTANCE_SSH_PORT.")
    cache_image()
    KNOWN_HOSTS.unlink(missing_ok=True)
    source = CACHE / IMAGE
    if not key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-")) or "\n" in key:
        raise RuntimeError("Invalid SSH public key.")
    # The cloud image uses systemd-networkd. Configure it before the first boot,
    # rather than depending on cloud-init to establish its own network transport.
    network_config = f"""version: 2
ethernets:
  acceptance0:
    match:
      macaddress: "{GUEST_MAC}"
    dhcp4: true
    dhcp6: false
"""
    spec = provisioning_spec(key)
    package_list = ", ".join(REQUIRED_PACKAGES)
    user_data = f"""#cloud-config
hostname: {VM}
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
users:
  - name: arch
    groups: [wheel]
    shell: /bin/bash
    lock_passwd: true
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    ssh_authorized_keys:
      - {json.dumps(key)}
package_update: true
packages: [{package_list}]
write_files:
  - path: /etc/nord-tools-acceptance-spec
    owner: root:root
    permissions: '0644'
    content: "{spec}"
  - path: /etc/systemd/network/20-acceptance.network
    owner: root:root
    permissions: '0644'
    content: |
      [Match]
      MACAddress={GUEST_MAC}
      [Network]
      DHCP=ipv4
runcmd:
  - [install, -d, -m, '0755', -o, root, -g, root, /etc/netns]
  - [systemctl, enable, --now, systemd-networkd.service]
  - [systemctl, enable, --now, sshd.service]
  - [systemctl, enable, --now, qemu-guest-agent.service]
"""
    privileged("test", "!", "-e", str(DISK), timeout=15)
    privileged("test", "!", "-e", str(SEED), timeout=15)
    progress("Building the cloud-init seed...")
    with tempfile.TemporaryDirectory(prefix="nord-acceptance-") as folder:
        work = Path(folder)
        (work / "user-data").write_text(user_data, encoding="utf-8")
        (work / "meta-data").write_text(f"instance-id: {VM}-initial\nlocal-hostname: {VM}\n", encoding="utf-8")
        (work / "network-config").write_text(network_config, encoding="utf-8")
        run(
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            "-output",
            str(work / "seed.iso"),
            str(work / "user-data"),
            str(work / "meta-data"),
            str(work / "network-config"),
        )
        progress("Installing and resizing the disposable VM disk...")
        privileged("install", "-m", "0644", str(source), str(DISK), timeout=180)
        try:
            privileged("install", "-m", "0644", str(work / "seed.iso"), str(SEED))
            privileged("qemu-img", "resize", str(DISK), "32G")
            progress("Creating and starting the VM with passt userspace networking...")
            result = run(
                "virt-install",
                "--connect",
                URI,
                "--name",
                VM,
                "--memory",
                "4096",
                "--vcpus",
                "4",
                "--cpu",
                "host-passthrough",
                "--osinfo",
                "archlinux",
                "--import",
                "--disk",
                f"path={DISK},format=qcow2,bus=virtio",
                "--disk",
                f"path={SEED},device=cdrom,readonly=on",
                "--network",
                f"passt,model=virtio,mac={GUEST_MAC},portForward={SSH_HOST}:{SSH_PORT}:22",
                "--channel",
                "unix,target.type=virtio,target.name=org.qemu.guest_agent.0",
                "--graphics",
                "spice,listen=127.0.0.1",
                "--video",
                "virtio",
                "--console",
                "pty,target_type=serial",
                "--noautoconsole",
                timeout=120,
            )
        except Exception:
            # Leave failed artefacts available for an explicit, confirmed rebuild.
            raise
    return result.stdout + "\nVM created. Waiting for guest readiness is a separate operation."


def start():
    if status() == "Absent":
        raise RuntimeError("The guest does not exist. Select Provision, not Start.")
    return virsh("start", VM).stdout


def stop():
    return virsh("shutdown", VM).stdout


def console():
    """Open a guest console, including serial-only guests created by the script."""
    xml = virsh("dumpxml", VM).stdout
    if "<graphics " in xml:
        subprocess.Popen(["virt-viewer", "--connect", URI, VM])
        return "Graphical viewer launched."
    terminal = shutil.which("xterm") or shutil.which("konsole")
    if not terminal:
        raise RuntimeError("This VM has no graphical display. Install xterm or konsole for its serial console.")
    if Path(terminal).name == "konsole":
        subprocess.Popen([terminal, "-e", "virsh", "-c", URI, "console", VM])
    else:
        subprocess.Popen([terminal, "-e", "virsh", "-c", URI, "console", VM])
    return "Serial console launched (Ctrl+] to disconnect)."


def terminal():
    app = shutil.which("xterm") or shutil.which("konsole")
    if not app:
        raise RuntimeError("Install xterm or konsole to open an interactive SSH terminal.")
    subprocess.Popen([app, "-e", *ssh_args()])
    return "SSH terminal launched."


SOURCE_EXCLUDES = {".git", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv"}


def source_manifest(root):
    """Hash the canonical checkout, including mode bits, but not transient caches."""
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SOURCE_EXCLUDES for part in relative.parts):
            continue
        if path.is_symlink():
            raise RuntimeError(f"Source symlinks are not accepted: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError(f"Unsupported source entry: {relative}")
        result[relative.as_posix()] = [
            hashlib.sha256(path.read_bytes()).hexdigest(),
            stat.S_IMODE(path.stat().st_mode) & 0o777,
        ]
    return result


GUEST_MANIFEST_SCRIPT = r"""
from pathlib import Path
import hashlib, json, stat
root = Path('/home/arch/nord-tools')
excluded = {'.git', 'node_modules', '__pycache__', '.pytest_cache', '.ruff_cache', '.venv'}
result = {}
if root.is_dir():
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if any(part in excluded for part in rel.parts):
            continue
        if path.is_symlink():
            raise SystemExit('Guest source contains a symlink')
        if path.is_dir():
            continue
        if not path.is_file():
            raise SystemExit('Guest source contains an unsupported entry')
        result[rel.as_posix()] = [hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode) & 0o777]
print(json.dumps(result, sort_keys=True))
"""


def upload_source():
    """Synchronise changed source bytes and verify the final guest manifest."""
    desired = source_manifest(SOURCE_ROOT)
    current_result = guest_command(GUEST_MANIFEST_SCRIPT, timeout=120)
    if current_result.returncode:
        # Never repair an untrusted or unreadable tree by blindly extracting over it.
        raise RuntimeError("Guest source inspection failed: " + current_result.stderr.strip())
    try:
        current = json.loads(current_result.stdout)
        if not isinstance(current, dict):
            raise ValueError("manifest is not a dictionary")
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Guest source manifest invalid") from exc
    changed = [name for name, entry in desired.items() if current.get(name) != entry]
    removed = sorted(set(current) - set(desired))
    if not changed and not removed:
        progress("Source tree verified unchanged; no transfer required.")
        return
    progress(f"Synchronising source: {len(changed)} changed, {len(removed)} removed.")
    # Extract only regular files from the trusted local checkout. The remote
    # destination is fixed and the final manifest is checked independently.
    if changed:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name in changed:
                archive.add(SOURCE_ROOT / name, arcname=name, recursive=False)
        prepare = ssh("mkdir", "-p", REMOTE_ROOT, timeout=30)
        if prepare.returncode:
            raise RuntimeError("Unable to create guest source tree: " + prepare.stderr.strip())
        receiver = subprocess.run(
            ssh_args("tar", "-C", REMOTE_ROOT, "-xf", "-"),
            input=buffer.getvalue(),
            capture_output=True,
            timeout=180,
            check=False,
        )
        if receiver.returncode:
            raise RuntimeError("Guest source transfer failed: " + receiver.stderr.decode(errors="replace"))
    if removed:
        # Delete only names obtained from the verified guest manifest. The
        # guest script revalidates the relative paths and refuses symlinks.
        encoded = base64.b64encode(json.dumps(removed).encode()).decode()
        deletion = guest_command(f"""from pathlib import Path
import base64, json
root = Path({REMOTE_ROOT!r})
for name in json.loads(base64.b64decode({encoded!r})):
    rel = Path(name)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise SystemExit('Invalid source removal path')
    target = root / rel
    if target.is_symlink() or not target.is_file():
        raise SystemExit('Unexpected source removal target')
    target.unlink()
""")
        if deletion.returncode:
            raise RuntimeError("Unable to remove obsolete guest files: " + deletion.stderr.strip())
    verified = guest_command(GUEST_MANIFEST_SCRIPT, timeout=120)
    if verified.returncode or json.loads(verified.stdout) != desired:
        raise RuntimeError("Guest source verification failed after synchronisation")


# Only this probe currently declares retained diagnostic directories. The guest
# owns the source paths, but never the destination or the set of permitted files.
EVIDENCE_PREFIX = "nt-production-wg-"
EVIDENCE_LIMIT = 4 * 1024 * 1024
EVIDENCE_FILES = 40

# Executed in the guest as root. It exports a deliberately restricted, redacted
# representation, never private key files, arbitrary symlinks or raw archives.
GUEST_EVIDENCE_SCRIPT = r"""
import json
import os
from pathlib import Path
import re
import sys

prefix = 'nt-production-wg-'
root = Path('/tmp')
limit = 4 * 1024 * 1024
secret = re.compile(r'(secret|private|password|credential|token|auth|key)', re.I)

def scrub(value):
    if isinstance(value, dict):
        return {str(k): ('[REDACTED]' if secret.search(str(k)) else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, str) and ('PRIVATE KEY' in value or 'BEGIN ' in value):
        return '[REDACTED]'
    return value

requested = sys.argv[1] if len(sys.argv) > 1 else ''
if requested:
    candidate = Path(requested)
    if candidate.parent != root or not candidate.name.startswith(prefix):
        raise SystemExit('Invalid guest evidence directory')
    candidates = [candidate]
else:
    candidates = sorted((p for p in root.iterdir() if p.name.startswith(prefix) and p.is_dir() and not p.is_symlink()),
                        key=lambda p: p.stat().st_mtime, reverse=True)[:1]
if not candidates:
    raise SystemExit('No retained production WireGuard evidence found')
folder = candidates[0]
if folder.is_symlink() or not folder.is_dir():
    raise SystemExit('Evidence directory is not a real directory')
result = {'guest_directory': str(folder), 'files': {}, 'excluded': []}
size = 0
for entry in sorted(folder.iterdir()):
    if entry.is_symlink() or not entry.is_file() or entry.suffix != '.json' or secret.search(entry.name):
        result['excluded'].append(entry.name)
        continue
    if len(result['files']) >= 40 or entry.stat().st_size > limit or size + entry.stat().st_size > limit:
        result['excluded'].append(entry.name + ' (limit)')
        continue
    try:
        # O_NOFOLLOW prevents a swapped symlink being opened during collection.
        fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            with os.fdopen(fd, 'rb') as stream:
                raw = stream.read(limit + 1)
        except Exception:
            raise
        if len(raw) > limit:
            raise ValueError('File exceeds size limit')
        result['files'][entry.name] = scrub(json.loads(raw.decode('utf-8')))
        size += len(raw)
    except (OSError, UnicodeError, ValueError) as exc:
        result['excluded'].append(entry.name + ' (unreadable or invalid JSON)')
print(json.dumps(result, ensure_ascii=True))
"""


def export_evidence(guest_directory=None):
    """Export redacted JSON evidence into a private parent-side temporary folder."""
    if not readiness().startswith("Ready:"):
        raise RuntimeError("Guest is not ready for evidence collection")
    # Send the script over SSH stdin rather than through remote-shell -c quoting.
    # The remote command uses structured arguments; the optional path is
    # validated before inclusion and passed as a separate Python argument.
    if guest_directory and not re.fullmatch(r"/tmp/nt-production-wg-[A-Za-z0-9_-]+", guest_directory):
        raise RuntimeError("Invalid guest evidence directory")
    remote_command = ["sudo", "-n", "python", "-"]
    if guest_directory:
        remote_command.append(guest_directory)
    result = subprocess.run(
        ssh_args(*remote_command),
        input=GUEST_EVIDENCE_SCRIPT,
        text=True,
        capture_output=True,
        check=False,
        timeout=45,
    )
    if result.returncode:
        raise RuntimeError("Guest evidence collection failed: " + (result.stderr.strip() or "no evidence"))
    if len(result.stdout) > EVIDENCE_LIMIT * 2:
        raise RuntimeError("Guest evidence response exceeds the collection limit")
    payload = json.loads(result.stdout)
    files = payload.get("files")
    if not isinstance(files, dict) or len(files) > EVIDENCE_FILES:
        raise RuntimeError("Guest evidence response is invalid")
    destination = Path(tempfile.mkdtemp(prefix="nord-tools-acceptance-"))
    destination.chmod(0o700)
    for name, contents in files.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+\.json", name) or name.startswith("."):
            raise RuntimeError("Guest evidence contains an invalid filename")
        target = destination / name
        with target.open("x", encoding="utf-8") as output:
            json.dump(contents, output, indent=2, ensure_ascii=False)
            output.write("\n")
        target.chmod(0o600)
    manifest = destination / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "guest_directory": payload.get("guest_directory"),
                "exported": sorted(files),
                "excluded": payload.get("excluded", []),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest.chmod(0o600)
    return f"Redacted guest evidence exported to: {destination}"


def export_failure_evidence(output):
    """Best-effort export without masking the original acceptance failure."""
    matches = re.findall(r"FAILED RUN EVIDENCE RETAINED: (/tmp/nt-production-wg-[A-Za-z0-9_-]+)", output)
    if not matches:
        return "No registered guest evidence directory was reported."
    try:
        return export_evidence(matches[-1])
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        return f"Evidence export failed (original acceptance failure preserved): {exc}"


def start_detached_host_acceptance(*, unit, probe, evidence, result_path):
    """Launch one host-mutating guest stage without waiting through its barrier."""
    started = ssh(
        "sudo",
        "-n",
        "systemd-run",
        "--no-block",
        "--collect",
        "--unit=" + unit.removesuffix(".service"),
        "--property=Type=oneshot",
        "--property=TimeoutStartSec=180",
        "/usr/bin/python",
        f"{REMOTE_ROOT}/tools/{probe}",
        "--run-privileged",
        "--startup-delay",
        "5",
        "--evidence-dir",
        evidence,
        "--result",
        result_path,
        timeout=15,
    )
    if started.returncode:
        raise RuntimeError(f"Could not start {unit}: " + (started.stderr.strip() or started.stdout.strip()))


def wait_for_host_acceptance(
    timeout=180,
    *,
    unit=HOST_ACCEPTANCE_UNIT,
    result_path=HOST_ACCEPTANCE_RESULT,
    expected_scope="D1 host-domain static-egress acceptance",
):
    """Wait for a host stage to restore SSH, then require its durable report."""
    deadline = time.monotonic() + timeout
    last_status = "guest SSH unavailable while the host deny barrier is active"
    while time.monotonic() < deadline:
        try:
            result = ssh("sudo", "-n", "cat", result_path, timeout=10)
        except (OSError, subprocess.SubprocessError):
            time.sleep(1)
            continue
        if result.returncode == 0:
            try:
                report = json.loads(result.stdout)
            except (TypeError, ValueError) as exc:
                raise RuntimeError("D1 host acceptance returned malformed result JSON") from exc
            if report.get("scope") != expected_scope:
                raise RuntimeError("Host acceptance did not report its complete expected scope")
            if report.get("result") == "failed":
                detail = report.get("error", "unknown failure")
                evidence = report.get("evidence_dir", "no evidence directory reported")
                raise RuntimeError(f"{expected_scope} failed: {detail}\nEvidence retained: {evidence}")
            if report.get("result") != "passed":
                raise RuntimeError("Host acceptance returned an unknown result state")
            return report
        try:
            status = ssh(
                "sudo",
                "-n",
                "systemctl",
                "show",
                unit,
                "--property=ActiveState,Result",
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            time.sleep(1)
            continue
        if status.returncode == 0:
            last_status = status.stdout.strip() or last_status
            if "ActiveState=failed" in status.stdout or "Result=failed" in status.stdout:
                journal = ssh(
                    "sudo",
                    "-n",
                    "journalctl",
                    "--unit",
                    unit,
                    "--no-pager",
                    "--lines=80",
                    timeout=15,
                )
                detail = journal.stdout.strip() or journal.stderr.strip() or last_status
                raise RuntimeError(f"{expected_scope} failed before restoring remote access:\n" + detail)
        time.sleep(1)
    raise RuntimeError(
        f"{expected_scope} did not restore remote access within "
        f"{timeout} seconds ({last_status}). Use the serial console to inspect "
        f"{unit}, then rebuild the disposable guest; do not weaken the retained barrier blindly."
    )


def qga_command(*arguments, timeout=180):
    """Execute a bounded root command through the disposable guest serial agent.

    This channel deliberately does not depend on SSH while the host deny
    barrier is installed. It is restricted to the named libvirt guest.
    """
    import base64

    request = json.dumps(
        {
            "execute": "guest-exec",
            "arguments": {
                "path": arguments[0],
                "arg": list(arguments[1:]),
                "capture-output": True,
            },
        }
    )
    started = virsh("qemu-agent-command", VM, request, check=False)
    if started.returncode:
        raise RuntimeError("D3 guest agent unavailable: " + started.stderr.strip())
    payload = json.loads(started.stdout)
    if "return" not in payload or "pid" not in payload["return"]:
        raise RuntimeError("D3 guest agent rejected execution: " + started.stdout[:400])
    pid = payload["return"]["pid"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        query = json.dumps({"execute": "guest-exec-status", "arguments": {"pid": pid}})
        response = virsh("qemu-agent-command", VM, query, check=False)
        if response.returncode:
            raise RuntimeError("D3 guest agent lost command status: " + response.stderr.strip())
        state = json.loads(response.stdout).get("return", {})
        if state.get("exited"):
            output = base64.b64decode(state.get("out-data", ""), validate=True).decode(errors="replace")
            error = base64.b64decode(state.get("err-data", ""), validate=True).decode(errors="replace")
            if state.get("exitcode") != 0:
                raise RuntimeError(f"D3 guest command failed ({state.get('exitcode')}): {error or output}")
            return output
        time.sleep(1)
    raise RuntimeError("D3 guest command timed out; host deny barrier remains in place")


def wait_for_qga_boot(previous_boot, timeout=240):
    """Require an observed new kernel boot, not merely a libvirt reboot reply."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            boot = qga_command("/usr/bin/cat", "/proc/sys/kernel/random/boot_id", timeout=10).strip()
            if boot and boot != previous_boot:
                return boot
        except (RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        time.sleep(3)
    raise RuntimeError("D3 guest did not return with a different kernel boot ID; inspect serial console")


def wait_for_d3_result(timeout=120):
    """Wait for ordinary SSH to return after verified D3 retirement.

    The guest can finish the protected lifecycle before sshd starts.  In the
    Arch cloud image, sshd may wait for the initial system clock
    synchronisation even though the normal interface and forwarding path have
    already been restored.
    """
    deadline = time.monotonic() + timeout
    last_error = "SSH is not reachable"
    while time.monotonic() < deadline:
        try:
            report = ssh("sudo", "-n", "cat", HOST_REBOOT_RESULT, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            last_error = str(exc)
        else:
            if report.returncode == 0:
                return report.stdout
            detail = (report.stderr or report.stdout).strip()
            last_error = detail[:400] or f"SSH exited with status {report.returncode}"
        time.sleep(2)
    raise RuntimeError(
        f"D3 retired its verified barrier, but guest SSH did not return within {timeout} seconds ({last_error})"
    )


def run_host_reboot_acceptance():
    """Exercise the installed boot units across an actual disposable VM reboot."""
    prepared = ssh("sudo", "-n", "/usr/bin/python", HOST_REBOOT_PREPARE, "prepare", timeout=45)
    if prepared.returncode:
        raise RuntimeError("D3 boot fixture preparation failed: " + (prepared.stderr or prepared.stdout))
    previous = qga_command("/usr/bin/cat", "/proc/sys/kernel/random/boot_id").strip()
    progress("Rebooting the disposable guest for D3 startup-order acceptance...")
    rebooted = virsh("reboot", VM, check=False)
    if rebooted.returncode:
        raise RuntimeError("D3 guest reboot request failed: " + rebooted.stderr.strip())
    boot = wait_for_qga_boot(previous)
    progress("Verifying D3 early barrier, network-online activation and dual-stack tunnel through guest agent...")
    deadline = time.monotonic() + 180
    last_error = "D3 boot units have not converged"
    while time.monotonic() < deadline:
        try:
            qga_command("/usr/bin/python", HOST_REBOOT_PROBE, "inspect", timeout=25)
            break
        except RuntimeError as exc:
            last_error = str(exc)
            time.sleep(3)
    else:
        raise RuntimeError("D3 boot did not converge; retain guest for console recovery: " + last_error)
    progress("Testing interrupted D3 retirement and explicit evidence-led recovery...")
    qga_command("/usr/bin/python", HOST_REBOOT_PROBE, "retire", timeout=180)
    document = json.loads(wait_for_d3_result())
    if document.get("result") != "passed" or document.get("boot_id") != boot:
        raise RuntimeError("D3 returned incomplete or mismatched reboot acceptance evidence")
    document["source_manifest_sha256"] = hashlib.sha256(
        json.dumps(source_manifest(SOURCE_ROOT), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return document


def d3_failure_diagnostics():
    """Best-effort read-only boot evidence without weakening guest protection."""
    try:
        return qga_command(
            "/usr/bin/journalctl",
            "-b",
            "--no-pager",
            "--lines=100",
            "-u",
            "nord-tools-d3-fixture.service",
            "-u",
            "nord-tools-host-barrier.service",
            "-u",
            "nord-tools-host-activate.service",
            timeout=20,
        )[-12000:]
    except (RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        return f"Guest agent diagnostics unavailable: {exc}; inspect the libvirt serial console."


def _source_paths(*, suffix=None):
    """Return regular source paths covered by the deployment manifest."""
    paths = []
    for path in sorted(SOURCE_ROOT.rglob("*")):
        relative = path.relative_to(SOURCE_ROOT)
        if any(part in SOURCE_EXCLUDES for part in relative.parts):
            continue
        if path.is_symlink():
            raise RuntimeError(f"Source symlinks are not accepted: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError(f"Unsupported source entry: {relative}")
        name = relative.as_posix()
        if suffix is None or name.endswith(suffix):
            paths.append(name)
    return paths


def _python_module_index(python_paths=None):
    """Map import names and unambiguous short names to local Python files."""
    index = {}
    short_names = {}
    for relative in python_paths or _source_paths(suffix=".py"):
        path = Path(relative)
        parts = list(path.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        if parts:
            index[".".join(parts)] = relative
        short_names.setdefault(path.stem, []).append(relative)
    for name, matches in short_names.items():
        if len(matches) == 1:
            index.setdefault(name, matches[0])
    return index


def _resolve_local_import(module, current, level, index):
    if level:
        package = list(Path(current).with_suffix("").parts[:-1])
        keep = len(package) - level + 1
        package = package[: max(0, keep)]
        module = ".".join([*package, *module.split(".")]) if module else ".".join(package)
    candidates = []
    name = module
    while name:
        if name in index:
            candidates.append(index[name])
            break
        name = name.rpartition(".")[0]
    return candidates


def _load_impact_policy(source_paths):
    """Validate additive impact rules; malformed policies must never permit reuse."""
    path = SOURCE_ROOT / IMPACT_POLICY
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Missing or unsafe test impact policy: {IMPACT_POLICY}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Invalid test impact policy: {exc}") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "rules"}
        or document["schema_version"] != 1
        or not isinstance(document["rules"], list)
    ):
        raise ValueError("Invalid test impact policy schema")
    rules = []
    identifiers = set()
    for rule in document["rules"]:
        if not isinstance(rule, dict) or set(rule) != {"id", "when_changed", "invalidate", "reason"}:
            raise ValueError("Invalid test impact rule fields")
        name, patterns, targets, reason = (rule[key] for key in ("id", "when_changed", "invalidate", "reason"))
        if (
            not isinstance(name, str)
            or not name
            or name in identifiers
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise ValueError("Invalid or duplicate test impact rule")
        if (
            not isinstance(patterns, list)
            or not patterns
            or not all(
                isinstance(x, str) and x and not x.startswith("/") and ".." not in Path(x).parts for x in patterns
            )
        ):
            raise ValueError(f"Invalid paths in impact rule {name}")
        if (
            not isinstance(targets, list)
            or not targets
            or not all(isinstance(x, str) and x.startswith(("pytest:", "scenario:", "quality:")) for x in targets)
        ):
            raise ValueError(f"Invalid targets in impact rule {name}")
        identifiers.add(name)
        rules.append((name, patterns, targets, reason))
    return rules


def _impact_paths(unit_id, source_paths, rules):
    """Return additional inputs and the policy rules explaining their inclusion."""
    paths = {IMPACT_POLICY}
    matched = []
    for name, patterns, targets, reason in rules:
        if any(fnmatch.fnmatchcase(unit_id, target) for target in targets):
            paths.update(
                path for path in source_paths if any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)
            )
            matched.append({"id": name, "reason": reason, "patterns": patterns})
    return paths, matched


def _python_dependency_graph(python_paths, index, source_paths=None):
    """Parse each local Python file once into a direct dependency graph."""
    all_python = set(python_paths)
    all_sources = set(source_paths or python_paths)
    source_names = {}
    for relative in all_sources:
        source_names.setdefault(Path(relative).name, []).append(relative)
    graph = {}
    for relative in python_paths:
        path = SOURCE_ROOT / relative
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeError):
            graph[relative] = set(all_python)
            continue
        dependencies = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                dynamic_import = (isinstance(func, ast.Name) and func.id == "__import__") or (
                    isinstance(func, ast.Attribute) and func.attr == "import_module"
                )
                if dynamic_import and (
                    not node.args
                    or not isinstance(node.args[0], ast.Constant)
                    or not isinstance(node.args[0].value, str)
                ):
                    dependencies.update(all_python)
                # Runtime subprocesses can invoke arbitrary repository tools.
                if isinstance(func, ast.Attribute) and func.attr in {
                    "run",
                    "Popen",
                    "check_call",
                    "check_output",
                    "call",
                }:
                    dependencies.update(
                        path for path in all_sources if path.endswith((".py", ".sh", ".json", ".toml", ".yaml", ".yml"))
                    )

            if isinstance(node, ast.Import):
                for alias in node.names:
                    dependencies.update(_resolve_local_import(alias.name, relative, 0, index))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                dependencies.update(_resolve_local_import(module, relative, node.level, index))
                for alias in node.names:
                    child = ".".join(part for part in (module, alias.name) if part)
                    dependencies.update(_resolve_local_import(child, relative, node.level, index))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if value in index:
                    dependencies.add(index[value])
                if value in all_sources:
                    dependencies.add(value)
                named_sources = source_names.get(Path(value).name, [])
                if len(named_sources) == 1:
                    dependencies.add(named_sources[0])
                if value.endswith(".py") and "\n" not in value:
                    for candidate in (Path(relative).parent / value, Path(value)):
                        normalised = candidate.as_posix()
                        if normalised in all_python:
                            dependencies.add(normalised)
                    short_name = Path(value).stem
                    if Path(value).name == value and short_name in index:
                        dependencies.add(index[short_name])
        graph[relative] = dependencies
    return graph


def local_python_dependencies(entry, *, graph=None, index=None, all_python=None):
    """Find a conservative transitive closure of local Python dependencies."""
    all_python = set(all_python or _source_paths(suffix=".py"))
    if graph is None:
        index = index or _python_module_index(all_python)
        graph = _python_dependency_graph(sorted(all_python), index, _source_paths())
    pending = [entry]
    found = set()
    while pending:
        relative = pending.pop()
        if relative in found:
            continue
        found.add(relative)
        pending.extend(graph.get(relative, set()) - found)
    return sorted(found)


def _path_record(relative):
    path = SOURCE_ROOT / relative
    if not path.is_file() or path.is_symlink():
        return ["missing", relative]
    return [hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode) & 0o777]


def _fingerprint(kind, paths, environment):
    records = {relative: _path_record(relative) for relative in sorted(set(paths))}
    payload = {
        "schema": RESULT_CACHE_SCHEMA,
        "kind": kind,
        "inputs": records,
        "environment": environment,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def guest_environment_identity():
    """Read the tool identities that can change acceptance behaviour."""
    script = (
        "packages = "
        + repr(REQUIRED_PACKAGES)
        + "\n"
        + r"""
import json, platform, subprocess, sys

def version(*command):
    result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=10)
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else f"exit:{result.returncode}"

package_result = subprocess.run(["pacman", "-Q", *packages], text=True, capture_output=True, check=False, timeout=20)
if package_result.returncode:
    raise SystemExit(package_result.stderr or "package identity unavailable")
package_versions = {}
for line in package_result.stdout.splitlines():
    name, _, release = line.partition(" ")
    package_versions[name] = release
if set(package_versions) != set(packages):
    raise SystemExit("package identity incomplete")

print(json.dumps({
    "python": sys.version,
    "platform": platform.platform(),
    "kernel": platform.release(),
    "pytest": version("python", "-m", "pytest", "--version"),
    "ruff": version("ruff", "--version"),
    "node": version("node", "--version"),
    "npm": version("npm", "--version"),
    "ip": version("ip", "-Version"),
    "nft": version("nft", "--version"),
    "wg": version("wg", "--version"),
    "systemd": version("systemctl", "--version"),
    "packages": package_versions,
}, sort_keys=True))
"""
    )
    result = guest_command(script, timeout=45)
    if result.returncode:
        raise RuntimeError("Unable to identify the guest test environment: " + result.stderr.strip())
    try:
        identity = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Guest test environment identity is malformed") from exc
    if not isinstance(identity, dict) or not all(isinstance(key, str) for key in identity):
        raise RuntimeError("Guest test environment identity is incomplete")
    return identity


def _empty_result_cache():
    return {
        "schema": RESULT_CACHE_SCHEMA,
        "workspace": str(SOURCE_ROOT),
        "generation": 0,
        "entries": {},
    }


def load_result_cache():
    """Load only a private cache bound to this exact workspace."""
    if not RESULT_CACHE.exists():
        return _empty_result_cache(), "no prior development result cache"
    try:
        metadata = RESULT_CACHE.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("cache is not a regular file")
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
            raise ValueError("cache ownership or permissions are unsafe")
        document = json.loads(RESULT_CACHE.read_text(encoding="utf-8"))
        if (
            not isinstance(document, dict)
            or document.get("schema") != RESULT_CACHE_SCHEMA
            or document.get("workspace") != str(SOURCE_ROOT)
            or not isinstance(document.get("entries"), dict)
            or not isinstance(document.get("generation"), int)
        ):
            raise ValueError("cache schema or workspace differs")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return _empty_result_cache(), f"prior result cache rejected: {exc}"
    return document, "validated prior development result cache"


def publish_result_cache(units, run_id):
    """Atomically publish validated unit passes under an exclusive lock."""
    if not units:
        return
    RESULT_CACHE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_fd = os.open(RESULT_CACHE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(lock_fd, "r+", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            document, _ = load_result_cache()
            entries = document["entries"]
            completed = datetime.now(timezone.utc).isoformat()
            for unit in units:
                entries[unit["id"]] = {
                    "fingerprint": unit["fingerprint"],
                    "result": "passed",
                    "run_id": run_id,
                    "completed_at": completed,
                }
            document["generation"] += 1
            fd, temporary = tempfile.mkstemp(prefix=".development-results-", dir=RESULT_CACHE.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    json.dump(document, output, indent=2, sort_keys=True)
                    output.write("\n")
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, 0o600)
                os.replace(temporary, RESULT_CACHE)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    except OSError as exc:
        raise RuntimeError(f"Unable to publish the development result cache: {exc}") from exc


def _unit(unit_id, kind, paths, environment, cache, force, invalidated, impact_rules=()):
    fingerprint = _fingerprint(kind, paths, environment)
    prior = cache.get("entries", {}).get(unit_id)
    reusable = (
        not force
        and unit_id not in invalidated
        and isinstance(prior, dict)
        and prior.get("result") == "passed"
        and prior.get("fingerprint") == fingerprint
    )
    if force:
        reason = "complete execution requested"
    elif unit_id in invalidated:
        reason = "explicitly invalidated"
    elif not isinstance(prior, dict):
        reason = "no prior pass"
    elif prior.get("result") != "passed":
        reason = "prior result was not a pass"
    elif prior.get("fingerprint") != fingerprint:
        reason = "inputs or environment changed"
    else:
        reason = "validated inputs and environment are unchanged"
    return {
        "id": unit_id,
        "kind": kind,
        "paths": sorted(set(paths)),
        "fingerprint": fingerprint,
        "execute": not reusable,
        "reason": reason,
        "impact_rules": list(impact_rules),
    }


def _scenario_environment(name, environment):
    """Select only the guest capabilities relevant to one privileged scenario."""
    common_packages = {"nftables", "wireguard-tools", "curl", "iproute2", "iputils", "bind"}
    package_names = set(common_packages)
    if name == "desktop":
        package_names.update({"dbus", "weston", "wayland-utils", "xorg-server-xvfb", "xorg-xauth", "xorg-xdpyinfo"})
    packages = environment.get("packages", {})
    return {key: environment.get(key) for key in ("python", "platform", "kernel", "ip", "nft", "wg", "systemd")} | {
        "packages": {key: packages.get(key) for key in sorted(package_names)}
        if isinstance(packages, dict)
        else packages
    }


def build_execution_plan(*, mode, selected, environment, cache, force=False, invalidated=()):
    """Build a deterministic conservative development or final execution plan."""
    selected = set(SCENARIO_PROBES) | {"quality"} if "all" in selected else set(selected)
    unknown = selected - (set(SCENARIO_PROBES) | {"quality"})
    if unknown:
        raise ValueError("Unknown acceptance scenario: " + ", ".join(sorted(unknown)))
    if mode == "final" and selected != set(SCENARIO_PROBES) | {"quality"}:
        raise ValueError("Final mode requires the complete quality and acceptance scenario set")
    force = force or mode == "final"
    invalidated = set(invalidated)
    units = []
    source_paths = _source_paths()
    python_paths = [path for path in source_paths if path.endswith(".py")]
    module_index = _python_module_index(python_paths)
    dependency_graph = _python_dependency_graph(python_paths, module_index, source_paths)
    rules = _load_impact_policy(source_paths)

    def impact(unit_id, paths):
        additional, matching = _impact_paths(unit_id, source_paths, rules)
        return sorted(set(paths) | additional), matching

    # Non-Python test inputs are not reliably discoverable from static imports.
    # Broadly invalidate pytest on fixture/configuration/script changes rather than
    # risk reusing a stale pass. Documentation is handled by Markdown lint.
    referenced_inputs = set().union(*dependency_graph.values()) if dependency_graph else set()
    pytest_external = [
        path for path in source_paths if not path.endswith((".py", ".md")) and path not in referenced_inputs
    ]
    if "quality" in selected:
        pytest_environment = {key: environment.get(key) for key in ("python", "pytest", "platform")}
        pytest_shared = [path for path in python_paths if Path(path).name == "conftest.py"] + [
            "pytest.ini",
            "pyproject.toml",
            "setup.cfg",
            "tox.ini",
        ]
        for relative in sorted(path for path in _source_paths(suffix=".py") if Path(path).name.startswith("test")):
            unit_id = "pytest:" + relative
            inputs, matched = impact(
                unit_id,
                local_python_dependencies(relative, graph=dependency_graph, all_python=python_paths)
                + pytest_shared
                + pytest_external,
            )
            units.append(_unit(unit_id, "pytest", inputs, pytest_environment, cache, force, invalidated, matched))
        ruff_inputs = python_paths + [name for name in ("pyproject.toml", "ruff.toml", ".ruff.toml")]
        inputs, matched = impact("quality:ruff", ruff_inputs)
        units.append(
            _unit("quality:ruff", "ruff", inputs, {"ruff": environment.get("ruff")}, cache, force, invalidated, matched)
        )
        markdown_paths = _source_paths(suffix=".md")
        markdown_inputs = markdown_paths + [".markdownlint-cli2.jsonc", "package.json", "package-lock.json"]
        inputs, matched = impact("quality:markdown", markdown_inputs)
        units.append(
            _unit(
                "quality:markdown",
                "markdown",
                inputs,
                {key: environment.get(key) for key in ("node", "npm")},
                cache,
                force,
                invalidated,
                matched,
            )
        )
    manager_path = "scripts/acceptance-manager.py"
    for name, probe in SCENARIO_PROBES.items():
        if name not in selected:
            continue
        paths = set(local_python_dependencies(probe, graph=dependency_graph, all_python=python_paths))
        paths.add(manager_path)
        unit_id = "scenario:" + name
        inputs, matched = impact(unit_id, paths)
        # Privileged acceptance depends on mutable guest state that static
        # fingerprints cannot certify. Never substitute a cached pass.
        scenario_unit = _unit(
            unit_id, "scenario", inputs, _scenario_environment(name, environment), cache, True, invalidated, matched
        )
        if not force:
            scenario_unit["reason"] = "privileged scenario requires live execution"
        units.append(scenario_unit)
    unmatched = invalidated - {unit["id"] for unit in units}
    if unmatched:
        raise ValueError("Invalidation did not match the selected plan: " + ", ".join(sorted(unmatched)))
    return units


def _run_guest_script(command):
    """Run a guest script with streamed CLI output and bounded diagnostics."""
    if _CLI_PROGRESS:
        process = subprocess.Popen(
            ssh_args("bash", "-s"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(command)
        process.stdin.close()
        lines = queue.Queue()

        def pump_output():
            for item in process.stdout:
                lines.put(item)
            lines.put(None)

        reader = threading.Thread(target=pump_output, daemon=True)
        reader.start()
        tail = []
        deadline = time.monotonic() + 7200
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise RuntimeError("Acceptance tests exceeded the two-hour timeout.")
            try:
                line = lines.get(timeout=min(1, remaining))
            except queue.Empty:
                continue
            if line is None:
                break
            colour = sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ
            print(
                colourise_acceptance_status(line, enabled=colour, colourblind=_COLOURBLIND),
                end="",
                flush=True,
            )
            tail.append(line.rstrip())
            tail = tail[-30:]
        returncode = process.wait()
        output = "\n".join(tail)
    else:
        result = subprocess.run(
            ssh_args("bash", "-s"), input=command, text=True, capture_output=True, check=False, timeout=7200
        )
        returncode = result.returncode
        output = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
    if returncode:
        evidence = export_failure_evidence(output)
        raise RuntimeError(f"Acceptance tests failed with exit {returncode}. Last output:\n{output}\n{evidence}")
    return output


def _guest_was_used():
    result = ssh("sudo", "-n", "test", "-e", "/var/tmp/nord-tools-acceptance-used", timeout=10)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise RuntimeError("Unable to verify whether the disposable guest has already run privileged acceptance")


def run_tests(
    *,
    mode="development",
    selected=("all",),
    force_complete=False,
    no_result_cache=False,
    explain_selection=False,
    invalidated=(),
):
    """Run only invalidated development units, or the complete final matrix."""
    ready = readiness()
    if not ready.startswith("Ready:"):
        message = "Guest is not ready for testing: " + ready
        if ready == "Guest is not running":
            message += (
                "\nHint: Run 'python scripts/acceptance-manager.py rebuild' "
                "to create and start a fresh disposable guest, then retry 'test'."
            )
        raise RuntimeError(message)
    provisioning_issues = guest_provisioning_issues()
    if provisioning_issues:
        raise RuntimeError(
            "Guest provisioning contract is incomplete: "
            + "; ".join(provisioning_issues)
            + "\nHint: Run 'python scripts/acceptance-manager.py rebuild' before retrying 'test'."
        )
    upload_source()
    environment = guest_environment_identity()
    cache, cache_status = _empty_result_cache(), "result reuse disabled"
    if mode == "development" and not no_result_cache:
        cache, cache_status = load_result_cache()
    plan = build_execution_plan(
        mode=mode,
        selected=selected,
        environment=environment,
        cache=cache,
        force=force_complete or no_result_cache,
        invalidated=invalidated,
    )
    executed = [unit for unit in plan if unit["execute"]]
    reused = [unit for unit in plan if not unit["execute"]]
    if explain_selection:
        progress(f"Selection cache: {cache_status}")
        for unit in plan:
            progress(f"{'RUN' if unit['execute'] else 'REUSED'}: {unit['id']} ({unit['reason']})")
            for rule in unit.get("impact_rules", ()):
                progress(f"  impact policy: {rule['id']} ({rule['reason']})")

    scenario_units = {unit["id"].removeprefix("scenario:"): unit for unit in plan if unit["kind"] == "scenario"}
    executable_scenarios = {name for name, unit in scenario_units.items() if unit["execute"]}
    if executable_scenarios and _guest_was_used():
        names = ", ".join(sorted(executable_scenarios))
        raise RuntimeError(
            f"The selected scenarios require a clean disposable guest ({names}). "
            "Run 'python scripts/acceptance-manager.py rebuild' before retrying."
        )

    pytest_units = [unit for unit in executed if unit["kind"] == "pytest"]
    ruff_unit = next((unit for unit in executed if unit["kind"] == "ruff"), None)
    markdown_unit = next((unit for unit in executed if unit["kind"] == "markdown"), None)
    commands = ["set -euo pipefail", f"cd {shlex.quote(REMOTE_ROOT)}"]
    if pytest_units:
        tests = [unit["id"].removeprefix("pytest:") for unit in pytest_units]
        commands.extend(
            (f'echo "RUN: pytest ({len(tests)} affected files)"', "python -m pytest -q " + shlex.join(tests))
        )
    if ruff_unit:
        commands.extend(
            ('echo "RUN: Ruff lint"', "ruff check .", 'echo "RUN: Ruff format check"', "ruff format --check .")
        )
    if markdown_unit:
        commands.extend(
            (
                'echo "RUN: Markdown lint"',
                "npm_state=\"$(sha256sum package-lock.json | cut -d' ' -f1):$(node --version):$(npm --version)\"",
                'if [ -f node_modules/.nt-install-state ] && [ "$(cat node_modules/.nt-install-state)" = "$npm_state" ] && npm ls --depth=0 --offline >/dev/null 2>&1; then',
                '  echo "Reusing verified Node dependencies"',
                "else",
                "  npm ci --ignore-scripts --no-audit --no-fund",
                "  npm ls --depth=0 --offline >/dev/null",
                "  printf '%s' \"$npm_state\" > node_modules/.nt-install-state",
                "fi",
                "npm run lint:markdown",
            )
        )
    if executable_scenarios:
        commands.append("sudo -n touch /var/tmp/nord-tools-acceptance-used")
    if "network" in executable_scenarios:
        commands.extend(
            (
                'echo "RUN: privileged network isolation acceptance"',
                "sudo -n python tools/probe_network_isolation_adversarial_acceptance.py --run-privileged",
            )
        )
    if "application" in executable_scenarios:
        commands.extend(
            (
                'echo "RUN: privileged application lifecycle acceptance"',
                'sudo -n python tools/probe_application_lifecycle_acceptance.py --run-privileged --uid "$(id -u)" --gid "$(id -g)"',
            )
        )
    if "desktop" in executable_scenarios:
        commands.extend(
            (
                'echo "RUN: registered desktop session integration"',
                'sudo -n python tools/probe_desktop_launch_acceptance.py --run-privileged --uid "$(id -u)" --gid "$(id -g)"',
            )
        )

    run_id = str(uuid.uuid4())
    immediate_units = [
        unit
        for unit in executed
        if unit["kind"] != "scenario" or unit["id"].removeprefix("scenario:") in {"network", "application", "desktop"}
    ]
    output = ""
    if len(commands) > 2:
        progress("Starting selected guest quality and acceptance units...")
        output = _run_guest_script("\n".join(commands) + "\n")
        if not no_result_cache:
            publish_result_cache(immediate_units, run_id)

    completed_scopes = []
    if "d1" in executable_scenarios:
        progress("Starting D1 host-domain acceptance...")
        start_detached_host_acceptance(
            unit=HOST_ACCEPTANCE_UNIT,
            probe="probe_host_domain_acceptance.py",
            evidence=HOST_ACCEPTANCE_EVIDENCE,
            result_path=HOST_ACCEPTANCE_RESULT,
        )
        progress("Waiting for D1 to retire its deny barrier and restore guest SSH...")
        report = wait_for_host_acceptance()
        completed_scopes.append(report["scope"])
        if not no_result_cache:
            publish_result_cache([scenario_units["d1"]], run_id)
    if "d2" in executable_scenarios:
        progress("Starting D2 host failure and recovery acceptance...")
        start_detached_host_acceptance(
            unit=HOST_FAILURE_UNIT,
            probe="probe_host_failure_recovery_acceptance.py",
            evidence=HOST_FAILURE_EVIDENCE,
            result_path=HOST_FAILURE_RESULT,
        )
        progress("Waiting for D2 to complete barrier-last recovery and restore guest SSH...")
        report = wait_for_host_acceptance(
            unit=HOST_FAILURE_UNIT,
            result_path=HOST_FAILURE_RESULT,
            expected_scope="D2 host-domain failure and recovery acceptance",
        )
        completed_scopes.append(report["scope"])
        if not no_result_cache:
            publish_result_cache([scenario_units["d2"]], run_id)
    if "d3" in executable_scenarios:
        try:
            report = run_host_reboot_acceptance()
        except RuntimeError as exc:
            raise RuntimeError(str(exc) + "\nD3 boot diagnostics:\n" + d3_failure_diagnostics()) from exc
        completed_scopes.append(report["scope"])
        if not no_result_cache:
            publish_result_cache([scenario_units["d3"]], run_id)

    summary = (
        f"Acceptance selection completed in {mode} mode: {len(executed)} executed, "
        f"{len(reused)} reused from equivalent development evidence."
    )
    if completed_scopes:
        summary += " Completed " + "; ".join(completed_scopes) + "."
    if output and not _CLI_PROGRESS:
        summary += "\n" + output
    return summary


def remove():
    """Delete the named disposable VM and its known seed, preserving the cache."""
    if status() != "Absent":
        if status() == "running":
            raise RuntimeError("Shut down the VM before deleting it, or use Rebuild.")
        result = virsh("undefine", VM, "--remove-all-storage", check=False)
        # Libvirt may report failure for the unmanaged NoCloud CD-ROM while
        # successfully removing the domain and managed disk.
        if status() != "Absent":
            raise RuntimeError(result.stderr.strip() or "Unable to undefine the guest.")
    # Only remove these exact paths, which are exclusively owned by this tool.
    for path in (SEED, DISK):
        privileged("rm", "-f", "--", str(path))
    return "Disposable guest and its generated storage removed. Image cache retained."


def rebuild(force=False):
    """Reuse only an attested, unused guest; otherwise reprovision from scratch."""
    reuse, reasons = rebuild_plan(force=force)
    if reuse:
        return "Existing guest verified equivalent and unused; no rebuild required.\n" + readiness()
    progress("Clean rebuild required: " + "; ".join(reasons))
    if status() != "Absent":
        if status() == "running":
            progress("Stopping the existing disposable VM...")
            result = virsh("destroy", VM, check=False)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Unable to stop the guest.")
        progress("Removing the existing disposable VM and generated storage...")
        remove()
    else:
        # A failed initial creation may have left only its disk and seed.
        remove()
    progress("Provisioning a fresh disposable VM...")
    output = provision()
    progress("Waiting for cloud-init and authenticated SSH...")
    return output + "\n" + wait_ready()


def gui():
    try:
        from PySide6.QtCore import QThread, Signal
        from PySide6.QtWidgets import (
            QApplication,
            QHBoxLayout,
            QLabel,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QTextEdit,
            QVBoxLayout,
            QWidget,
            QInputDialog,
            QLineEdit,
        )
    except ImportError as exc:
        raise RuntimeError("Install pyside6 to use the graphical manager.") from exc

    class Worker(QThread):
        completed = Signal(str)
        failed = Signal(str)

        def __init__(self, action):
            super().__init__()
            self.action = action

        def run(self):
            try:
                self.completed.emit(str(self.action()))
            except Exception as exc:
                self.failed.emit(str(exc))

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Nord Tools Acceptance Manager")
            self.resize(750, 470)
            container = QWidget()
            layout = QVBoxLayout(container)
            self.state = QLabel("Select Refresh to inspect the guest.")
            self.log = QTextEdit()
            self.log.setReadOnly(True)
            layout.addWidget(self.state)
            layout.addWidget(self.log)
            self.workers = []
            actions = [
                ("Refresh", self.refresh),
                ("Provision", lambda: provision() + "\n" + wait_ready()),
                ("Rebuild", rebuild),
                ("Wait for readiness", wait_ready),
                ("Start", start),
                ("Shut down", stop),
                ("Console", console),
                ("SSH terminal", terminal),
                ("Run acceptance tests", run_tests),
                ("Export failure evidence", export_evidence),
                ("Verify image cache", cache_image),
                ("Delete VM", remove),
            ]
            for offset in range(0, len(actions), 4):
                row = QHBoxLayout()
                for name, action in actions[offset : offset + 4]:
                    button = QPushButton(name)
                    button.clicked.connect(lambda checked=False, n=name, a=action: self.execute(n, a))
                    row.addWidget(button)
                layout.addLayout(row)
            self.setCentralWidget(container)
            self.execute("Refresh", self.refresh)

        def refresh(self):
            state = status()
            ip = address() if state == "running" else None
            return (
                f"VM: {state}\nGuest address: {ip or 'Not available'}\n"
                f"SSH endpoint: {ssh_endpoint()}\n"
                f"Readiness: {readiness() if state == 'running' else 'Not running'}"
            )

        def execute(self, name, action):
            if name in ("Delete VM", "Rebuild"):
                choice = QMessageBox.question(
                    self,
                    "Delete disposable guest",
                    (
                        f"{name} {VM}? Rebuild may erase the disposable disk if equivalence "
                        "cannot be verified. Delete always erases it. The image cache is retained."
                    ),
                )
                if choice != QMessageBox.StandardButton.Yes:
                    return
            global _PRIVILEGE_PASSWORD
            if name in ("Provision", "Rebuild", "Delete VM"):
                password, accepted = QInputDialog.getText(
                    self,
                    "Host authorisation",
                    "Enter your CachyOS sudo password for VM storage operations:",
                    QLineEdit.EchoMode.Password,
                )
                if not accepted:
                    return
                _PRIVILEGE_PASSWORD = password
            self.state.setText(f"{name}: working…")
            worker = Worker(action)
            self.workers.append(worker)
            worker.completed.connect(lambda result: self.finish(name, result))
            worker.failed.connect(lambda error: self.finish(name, f"ERROR: {error}"))
            worker.finished.connect(lambda w=worker: self.workers.remove(w))
            if name in ("Provision", "Rebuild", "Delete VM"):
                worker.finished.connect(self.clear_password)
            worker.start()

        def clear_password(self):
            global _PRIVILEGE_PASSWORD
            _PRIVILEGE_PASSWORD = None

        def finish(self, name, result):
            self.state.setText(f"{name}: finished")
            self.log.append(f"[{name}]\n{result}\n")

    app = QApplication(sys.argv)
    window = Window()
    window.show()
    return app.exec()


def main():
    global _CLI_PROGRESS, _COLOURBLIND
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        nargs="?",
        default="gui",
        choices=[
            "gui",
            "status",
            "ready",
            "address",
            "cache",
            "provision",
            "start",
            "stop",
            "console",
            "ssh",
            "test",
            "evidence",
            "remove",
            "rebuild",
            "wait",
        ],
    )
    parser.add_argument("--force", action="store_true", help="Always recreate the disposable VM with rebuild")
    parser.add_argument("--plan", action="store_true", help="Explain rebuild decisions without making changes")
    parser.add_argument(
        "--colourblind",
        "--colorblind",
        action="store_true",
        help="use blue PASS and orange FAIL markers in colour-capable terminal output",
    )
    parser.add_argument(
        "--mode",
        choices=("development", "final"),
        default=None,
        help="reuse equivalent development results or force complete final execution",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=("all", "quality", *SCENARIO_PROBES),
        help="select a development scenario; repeat to select several (default: all)",
    )
    parser.add_argument(
        "--force-complete-run",
        action="store_true",
        help="execute every unit in the selected test scope without reusing passes",
    )
    parser.add_argument(
        "--no-result-cache",
        action="store_true",
        help="execute the selected test scope without reading or writing reusable results",
    )
    parser.add_argument(
        "--explain-selection",
        action="store_true",
        help="print the reason each selected test unit executes or is reused",
    )
    parser.add_argument(
        "--invalidate",
        action="append",
        default=[],
        metavar="UNIT",
        help="force one selected execution-unit identifier to run",
    )
    args = parser.parse_args()
    if (args.force or args.plan) and args.action != "rebuild":
        parser.error("--force and --plan apply only to rebuild")
    test_options = (
        args.mode is not None
        or args.scenario is not None
        or args.force_complete_run
        or args.no_result_cache
        or args.explain_selection
        or args.invalidate
    )
    if test_options and args.action != "test":
        parser.error("--mode, --scenario and result-selection options apply only to test")
    mode = args.mode or "development"
    selected = tuple(args.scenario or ("all",))
    if "all" in selected and len(selected) != 1:
        parser.error("--scenario all cannot be combined with another scenario")
    if mode == "final" and selected != ("all",):
        parser.error("final mode requires --scenario all")
    actions = {
        "status": status,
        "ready": readiness,
        "address": address,
        "cache": cache_image,
        "provision": provision,
        "start": start,
        "stop": stop,
        "console": console,
        "ssh": terminal,
        "evidence": export_evidence,
        "remove": remove,
        "rebuild": rebuild,
        "wait": wait_ready,
    }
    try:
        if args.action == "gui":
            return gui()
        _CLI_PROGRESS = True
        _COLOURBLIND = args.colourblind
        if args.action == "rebuild" and args.plan:
            reuse, reasons = rebuild_plan(force=args.force)
            print("Decision: " + ("reuse verified unused VM" if reuse else "clean rebuild"))
            for reason in reasons:
                print("Reason: " + reason)
            return 0
        if args.action == "test":
            result = run_tests(
                mode=mode,
                selected=selected,
                force_complete=args.force_complete_run,
                no_result_cache=args.no_result_cache,
                explain_selection=args.explain_selection,
                invalidated=tuple(args.invalidate),
            )
        else:
            result = rebuild(force=args.force) if args.action == "rebuild" else actions[args.action]()
        print(result)
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
