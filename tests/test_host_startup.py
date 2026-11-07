"""Early host barrier systemd integration regression coverage."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from nord_tools_internal.nordvpn_host_startup import (
    ACTIVATION_UNIT,
    BARRIER_UNIT,
    install_host_startup,
    render_host_startup_units,
)
from nord_tools_internal.nordvpn_registry import RegistryError
from test_host_executor import PLAN


def _arguments(tmp_path: Path) -> dict:
    return {
        "plan_path": tmp_path / "plan.json",
        "store_path": tmp_path / "host.json",
        "private_key_path": tmp_path / "private.key",
        "python_executable": "/usr/bin/python3",
        "script_path": "/opt/nord-tools/nordvpn_manage.py",
    }


def test_barrier_unit_runs_before_network_and_activation_waits_online(tmp_path):
    units = render_host_startup_units(HostProtectionPlan.from_mapping(PLAN), **_arguments(tmp_path))
    assert "DefaultDependencies=no" in units[BARRIER_UNIT]
    assert "Before=network-pre.target" in units[BARRIER_UNIT]
    assert "After=local-fs.target" in units[BARRIER_UNIT]
    assert "RequiresMountsFor=" in units[BARRIER_UNIT]
    assert "OnFailure=emergency.target" in units[BARRIER_UNIT]
    assert "OnFailureJobMode=isolate" in units[BARRIER_UNIT]
    assert "RequiredBy=network-pre.target" in units[BARRIER_UNIT]
    assert "host-boot-barrier" in units[BARRIER_UNIT]
    assert f"Requires={BARRIER_UNIT}" in units[ACTIVATION_UNIT]
    assert f"After={BARRIER_UNIT} network-online.target" in units[ACTIVATION_UNIT]
    assert "LoadCredential=ntwg-host:" in units[ACTIVATION_UNIT]
    assert "host-activate --execute" in units[ACTIVATION_UNIT]
    assert "host-deactivate" not in units[ACTIVATION_UNIT]


def test_startup_install_is_preview_by_default_and_idempotent(tmp_path):
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    plan = HostProtectionPlan.from_mapping(PLAN)
    arguments = _arguments(tmp_path)
    arguments["plan_path"].write_text("{}\n", encoding="utf-8")
    arguments["private_key_path"].write_text("private\n", encoding="ascii")
    arguments["private_key_path"].chmod(0o600)
    preview = install_host_startup(plan, unit_dir=unit_dir, **arguments)
    assert preview["executed"] is False
    assert not list(unit_dir.iterdir())
    installed = install_host_startup(plan, unit_dir=unit_dir, execute=True, **arguments)
    assert installed["executed"] is True
    assert {item.name for item in unit_dir.iterdir()} == {BARRIER_UNIT, ACTIVATION_UNIT}
    repeated = install_host_startup(plan, unit_dir=unit_dir, execute=True, **arguments)
    assert {item["action"] for item in repeated["units"]} == {"unchanged"}


def test_startup_install_refuses_foreign_unit(tmp_path):
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    (unit_dir / BARRIER_UNIT).write_text("foreign\n", encoding="utf-8")
    with pytest.raises(RegistryError):
        install_host_startup(
            HostProtectionPlan.from_mapping(PLAN),
            unit_dir=unit_dir,
            **_arguments(tmp_path),
        )


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is unavailable")
def test_rendered_units_pass_systemd_verification(tmp_path):
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    arguments = _arguments(tmp_path)
    arguments["plan_path"].write_text("{}\n", encoding="utf-8")
    arguments["private_key_path"].write_text("private\n", encoding="ascii")
    arguments["private_key_path"].chmod(0o600)
    arguments["python_executable"] = sys.executable
    arguments["script_path"] = Path("nordvpn_manage.py").resolve()
    install_host_startup(
        HostProtectionPlan.from_mapping(PLAN),
        unit_dir=unit_dir,
        execute=True,
        **arguments,
    )
    result = subprocess.run(
        [
            "systemd-analyze",
            "verify",
            str(unit_dir / BARRIER_UNIT),
            str(unit_dir / ACTIVATION_UNIT),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
