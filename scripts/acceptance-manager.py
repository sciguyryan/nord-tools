#!/usr/bin/env python3
"""Manage a disposable Nord Tools acceptance guest without changing host routing.

All libvirt operations target the system connection and a single named guest.
The GUI delegates blocking operations to workers so that its event loop remains usable.
"""

import argparse
import json
import ipaddress
import time
import hashlib
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.request

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
_PRIVILEGE_PASSWORD = None
_CLI_PROGRESS = False

if not 1024 <= SSH_PORT <= 65535:
    raise ValueError("NORD_TOOLS_ACCEPTANCE_SSH_PORT must be between 1024 and 65535.")


def run(*args, check=True, timeout=30):
    """Execute a command without a shell and preserve useful diagnostic output."""
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=timeout)


def progress(message):
    if _CLI_PROGRESS:
        print(message, flush=True)


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
    KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return (
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
        *args,
    )


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


def readiness():
    """Report actual cloud-init status and treat failures as failures."""
    if status() != "running":
        return "Guest is not running"
    try:
        result = ssh("sudo", "-n", "cloud-init", "status", "--long")
    except (subprocess.SubprocessError, OSError) as exc:
        return f"SSH or cloud-init unavailable: {exc}"
    output = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
    if result.returncode == 255:
        return "SSH or cloud-init unavailable: " + (output or "SSH exited with status 255")
    if "status: error" in output or "status: degraded" in output:
        return "Provisioning failed:\n" + output
    if "status: done" in output:
        return "Ready: cloud-init completed successfully\n" + output
    if result.returncode != 0:
        return "Cloud-init check failed: " + (output or f"exit status {result.returncode}")
    return "Provisioning in progress:\n" + (output or "No status returned")


def wait_ready(timeout=360, interval=5):
    """Wait for a real SSH and cloud-init success, with a bounded deadline."""
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
        if last.startswith(("Provisioning failed:", "Cloud-init check failed:")) or last == "Guest is not running":
            raise RuntimeError(last)
        time.sleep(interval)
    raise RuntimeError(f"Guest was not ready after {timeout} seconds. Last observation: {last}")


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
packages: [git, python, python-pip, python-pytest, ruff, nodejs, npm, openssh, sudo, nftables, wireguard-tools, curl, iproute2, iputils, bind, jq, qemu-guest-agent]
write_files:
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


def upload_source():
    """Copy the current working tree into the guest without Git or cache artefacts."""
    if not SOURCE_ROOT.is_dir():
        raise RuntimeError(f"Source tree is unavailable: {SOURCE_ROOT}")
    progress("Uploading the current working tree to the guest...")
    prepare = ssh("rm", "-rf", "--", REMOTE_ROOT, timeout=30)
    if prepare.returncode:
        raise RuntimeError("Unable to clear the guest test tree: " + prepare.stderr.strip())
    prepare = ssh("mkdir", "-p", "--", REMOTE_ROOT, timeout=30)
    if prepare.returncode:
        raise RuntimeError("Unable to create the guest test tree: " + prepare.stderr.strip())
    archive = subprocess.Popen(
        [
            "tar",
            "--exclude=.git",
            "--exclude=node_modules",
            "--exclude=__pycache__",
            "--exclude=.pytest_cache",
            "--exclude=.ruff_cache",
            "-C",
            str(SOURCE_ROOT),
            "-cf",
            "-",
            ".",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert archive.stdout is not None
    receiver = subprocess.run(
        ssh_args("tar", "-C", REMOTE_ROOT, "-xf", "-"),
        stdin=archive.stdout,
        capture_output=True,
        check=False,
        timeout=180,
    )
    archive.stdout.close()
    archive_stderr = archive.communicate(timeout=30)[1].decode(errors="replace").strip()
    if archive.returncode or receiver.returncode:
        detail = archive_stderr or receiver.stderr.decode(errors="replace").strip()
        raise RuntimeError("Unable to upload the source tree: " + detail)


def run_tests():
    """Upload this checkout, run quality gates, then run privileged acceptance."""
    ready = readiness()
    if not ready.startswith("Ready:"):
        message = "Guest is not ready for testing: " + ready
        if ready == "Guest is not running":
            message += (
                "\nHint: Run 'python scripts/acceptance-manager.py rebuild' "
                "to create and start a fresh disposable guest, then retry 'test'."
            )
        raise RuntimeError(message)
    upload_source()
    command = f"""set -euo pipefail
cd {REMOTE_ROOT}
echo "RUN: pytest"
python -m pytest -q
echo "RUN: Ruff lint"
ruff check .
echo "RUN: Ruff format check"
ruff format --check .
echo "RUN: Markdown lint"
npm ci --ignore-scripts --no-audit --no-fund
npm run lint:markdown
echo "RUN: privileged network isolation acceptance"
sudo -n python tools/probe_network_isolation_adversarial_acceptance.py --run-privileged
echo "RUN: privileged application lifecycle acceptance"
sudo -n python tools/probe_application_lifecycle_acceptance.py --run-privileged --uid "$(id -u)" --gid "$(id -g)"
"""
    progress("Starting guest quality gates and privileged acceptance matrices...")
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
            print(line, end="", flush=True)
            tail.append(line.rstrip())
            tail = tail[-30:]
        returncode = process.wait()
        if returncode:
            raise RuntimeError(f"Acceptance tests failed with exit {returncode}. Last output:\n" + "\n".join(tail))
        return "Acceptance tests passed in the disposable guest."
    result = subprocess.run(
        ssh_args("bash", "-s"), input=command, text=True, capture_output=True, check=False, timeout=7200
    )
    output = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
    if result.returncode:
        raise RuntimeError(f"Acceptance tests failed with exit {result.returncode}:\n{output}")
    return f"Acceptance tests passed in the disposable guest.\n{output}"


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


def rebuild():
    """Replace a failed disposable guest, then wait for verified readiness."""
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
                    f"{name} {VM}? Its disposable disk and guest data will be permanently erased. The verified image cache is retained.",
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
    global _CLI_PROGRESS
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
            "remove",
            "rebuild",
            "wait",
        ],
    )
    args = parser.parse_args()
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
        "test": run_tests,
        "remove": remove,
        "rebuild": rebuild,
        "wait": wait_ready,
    }
    try:
        if args.action == "gui":
            return gui()
        _CLI_PROGRESS = True
        print(actions[args.action]())
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
