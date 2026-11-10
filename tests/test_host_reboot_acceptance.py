"""Deterministic D3 reboot contract tests without privileged host mutation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools import probe_host_reboot_acceptance as probe


def test_reboot_probe_is_root_only_and_opt_in():
    assert probe.STATE.is_absolute()
    assert probe.SETUP_UNIT != probe.BARRIER_UNIT
    assert probe.PEER_UNIT != probe.ACTIVATION_UNIT
    assert probe.RESULT.is_absolute()


def test_boot_fixture_refuses_to_overwrite_unresolved_host_store(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "STATE", tmp_path)
    (tmp_path / "host-store.json").write_text("{}")
    with pytest.raises(RuntimeError, match="unresolved host evidence"):
        probe.setup()


def test_preparation_refuses_foreign_units(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    monkeypatch.setattr(probe, "STATE", tmp_path / "new-state")
    monkeypatch.setattr(probe, "UNIT_DIR", tmp_path)
    (tmp_path / probe.BARRIER_UNIT).write_text("foreign")
    # Platform requirement is checked before unit collisions.
    original_exists = Path.exists
    monkeypatch.setattr(
        Path, "exists", lambda self: True if str(self) == "/etc/arch-release" else original_exists(self)
    )
    with pytest.raises(RuntimeError, match="unit already exists"):
        probe.prepare()


def test_reboot_inspection_requires_changed_boot(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "STATE", tmp_path)
    (tmp_path / "prepared.json").write_text(json.dumps({"boot_id": "same"}))
    (tmp_path / "boot.json").write_text(json.dumps({"boot_id": "same"}))
    original = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **k: "same\n" if str(self) == "/proc/sys/kernel/random/boot_id" else original(self, *a, **k),
    )
    with pytest.raises(RuntimeError, match="required real guest reboot"):
        probe.inspect()


def test_retirement_requires_verified_reboot(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "STATE", tmp_path)
    with pytest.raises(RuntimeError, match="independent verified reboot evidence"):
        probe.retire()


def test_staged_boot_entry_point_imports_in_isolation(tmp_path):
    """Reproduce the deployed root-owned tree, not the checkout's import path."""
    root = probe.ROOT
    for source in root.glob("*.py"):
        shutil.copy2(source, tmp_path / source.name)
    shutil.copytree(root / "nord_tools_internal", tmp_path / "nord_tools_internal")
    probe.stage_boot_probes(root, tmp_path)
    probe.verify_staged_boot_imports(tmp_path)
    assert (tmp_path / "tools" / "probe_two_wireguard.py").is_file()


def test_staged_boot_preflight_rejects_missing_transitive_dependency(tmp_path):
    root = probe.ROOT
    for source in root.glob("*.py"):
        shutil.copy2(source, tmp_path / source.name)
    shutil.copytree(root / "nord_tools_internal", tmp_path / "nord_tools_internal")
    probe.stage_boot_probes(root, tmp_path)
    (tmp_path / "tools" / "probe_two_wireguard.py").unlink()
    with pytest.raises(RuntimeError, match="staged boot entry point failed import preflight"):
        probe.verify_staged_boot_imports(tmp_path)


def test_staging_rejects_symlinked_probe(tmp_path):
    source = tmp_path / "source"
    (source / "tools").mkdir(parents=True)
    for name in probe.BOOT_PROBES:
        (source / "tools" / name).write_text("")
    (source / "tools" / "probe_two_wireguard.py").unlink()
    (source / "tools" / "probe_two_wireguard.py").symlink_to("probe_host_domain_acceptance.py")
    (tmp_path / "installed").mkdir()
    with pytest.raises(RuntimeError, match="missing or symlinked"):
        probe.stage_boot_probes(source, tmp_path / "installed")
