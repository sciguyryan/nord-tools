"""Early-barrier and network-online systemd units for host protection."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import tempfile

from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from nord_tools_internal.nordvpn_registry import RegistryError


BARRIER_UNIT = "nord-tools-host-barrier.service"
ACTIVATION_UNIT = "nord-tools-host-activate.service"
_MARKER = "# Managed by Nord Tools host-startup-install; regenerate rather than editing."
_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")


def _path(value: str | Path, label: str) -> str:
    text = str(value)
    if not _PATH.fullmatch(text):
        raise RegistryError(f"host startup {label} must be a simple absolute path")
    return text


def _reject_symlink_components(path: Path) -> None:
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RegistryError(f"refusing symlinked host startup path: {path}")


def render_host_startup_units(
    plan: HostProtectionPlan,
    *,
    plan_path: str | Path,
    store_path: str | Path,
    private_key_path: str | Path,
    python_executable: str | Path = "/usr/bin/python3",
    script_path: str | Path | None = None,
) -> dict[str, str]:
    """Render deterministic units; this function never touches the host."""
    if not isinstance(plan, HostProtectionPlan):
        raise RegistryError("validated host protection plan required")
    plan_file = _path(plan_path, "plan")
    store = _path(store_path, "store")
    private_key = _path(private_key_path, "private key")
    python = _path(python_executable, "Python executable")
    script = _path(
        script_path or Path(__file__).resolve().parent.parent / "nordvpn_manage.py",
        "management script",
    )
    barrier = "\n".join(
        (
            _MARKER,
            "",
            "[Unit]",
            "Description=Nord Tools installs the host VPN deny barrier before networking.",
            "DefaultDependencies=no",
            "Before=network-pre.target",
            "After=local-fs.target",
            f"RequiresMountsFor={plan_file} {Path(store).parent} {python} {script}",
            "OnFailure=emergency.target",
            "OnFailureJobMode=isolate",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            f"ExecStart={python} {script} host-boot-barrier --host-plan {plan_file} --host-store {store}",
            "",
            "[Install]",
            "RequiredBy=network-pre.target",
            "",
        )
    )
    activation = "\n".join(
        (
            _MARKER,
            "",
            "[Unit]",
            "Description=Nord Tools activates the protected host VPN tunnel.",
            f"Requires={BARRIER_UNIT}",
            f"After={BARRIER_UNIT} network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=oneshot",
            "RemainAfterExit=yes",
            f"LoadCredential=ntwg-host:{private_key}",
            f"ExecStart={python} {script} host-activate --execute --host-plan {plan_file} "
            f"--host-store {store} --private-key %d/ntwg-host",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        )
    )
    return {BARRIER_UNIT: barrier, ACTIVATION_UNIT: activation}


def _existing_action(path: Path, content: str) -> str:
    if path.is_symlink():
        raise RegistryError(f"refusing symlinked host startup unit: {path}")
    if not path.exists():
        return "create"
    try:
        existing = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RegistryError(f"cannot read host startup unit: {path}") from exc
    if not existing.startswith(_MARKER):
        raise RegistryError(f"refusing to replace a foreign host startup unit: {path}")
    return "unchanged" if existing == content else "replace"


def plan_host_startup_install(
    plan: HostProtectionPlan,
    *,
    plan_path: str | Path,
    store_path: str | Path,
    private_key_path: str | Path,
    unit_dir: str | Path,
    python_executable: str | Path = "/usr/bin/python3",
    script_path: str | Path | None = None,
) -> dict:
    units = render_host_startup_units(
        plan,
        plan_path=plan_path,
        store_path=store_path,
        private_key_path=private_key_path,
        python_executable=python_executable,
        script_path=script_path,
    )
    directory = Path(_path(unit_dir, "unit directory"))
    _reject_symlink_components(directory)
    directory_info = directory.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or directory_info.st_uid != os.geteuid()
        or directory_info.st_mode & 0o022
    ):
        raise RegistryError("host startup unit directory must be an existing ordinary directory")
    planned = [
        {"unit": name, "path": str(directory / name), "action": _existing_action(directory / name, content)}
        for name, content in units.items()
    ]
    return {
        "version": 1,
        "mode": "host_startup_install_plan",
        "network_changes_applied": False,
        "executed": False,
        "units": planned,
        "rendered": units,
    }


def install_host_startup(
    plan: HostProtectionPlan,
    *,
    plan_path: str | Path,
    store_path: str | Path,
    private_key_path: str | Path,
    unit_dir: str | Path,
    python_executable: str | Path = "/usr/bin/python3",
    script_path: str | Path | None = None,
    execute: bool = False,
) -> dict:
    report = plan_host_startup_install(
        plan,
        plan_path=plan_path,
        store_path=store_path,
        private_key_path=private_key_path,
        unit_dir=unit_dir,
        python_executable=python_executable,
        script_path=script_path,
    )
    if not execute:
        return report
    directory = Path(unit_dir)
    plan_file = Path(plan_path)
    key_file = Path(private_key_path)
    store_parent = Path(store_path).parent
    for path, label in ((plan_file, "plan"), (key_file, "private key")):
        _reject_symlink_components(path)
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise RegistryError(f"host startup {label} must be an owned regular file")
    if key_file.stat(follow_symlinks=False).st_mode & 0o077:
        raise RegistryError("host startup private key must not be accessible by group or other users")
    _reject_symlink_components(store_parent)
    parent_info = store_parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
        raise RegistryError("host startup store directory is unsafe")
    for entry in report["units"]:
        if _existing_action(Path(entry["path"]), report["rendered"][entry["unit"]]) != entry["action"]:
            raise RegistryError("host startup unit changed after installation preflight")
    for entry in report["units"]:
        if entry["action"] == "unchanged":
            continue
        fd, temporary = tempfile.mkstemp(prefix=".nord-tools-host-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                os.fchmod(output.fileno(), 0o644)
                output.write(report["rendered"][entry["unit"]])
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, entry["path"])
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    report["executed"] = True
    report["network_changes_applied"] = False
    return report
