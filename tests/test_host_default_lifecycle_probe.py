"""Dry-run contract for the privileged host-default lifecycle probe."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from test_host_executor import PLAN


def test_host_lifecycle_probe_defaults_to_preview(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(Path("tools/probe_host_default_lifecycle.py")),
            "--plan",
            str(plan),
            "--store",
            str(tmp_path / "host.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["mode"] == "host_default_dry_run"
    assert report["network_changes_applied"] is False
    assert not (tmp_path / "host.json").exists()


def test_host_lifecycle_probe_reports_missing_plan_without_traceback(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(Path("tools/probe_host_default_lifecycle.py")),
            "--plan",
            str(tmp_path / "missing.json"),
            "--store",
            str(tmp_path / "host.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 2
    assert "cannot read a valid host plan" in result.stderr
    assert "Traceback" not in result.stderr


def test_host_domain_acceptance_defaults_to_a_non_mutating_preview():
    result = subprocess.run(
        [sys.executable, str(Path("tools/probe_host_domain_acceptance.py"))],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "DRY RUN: D1 host-domain" in result.stdout
    assert "interrupts remote guest management" in result.stdout
