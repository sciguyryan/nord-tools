"""Acceptance orchestration is tested without invoking privileged operations."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "probe_provisioning_integration.py"
spec = importlib.util.spec_from_file_location("provisioning_integration", SOURCE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_dry_run_lists_every_stage_without_execution(capsys):
    with patch.object(module.subprocess, "run", side_effect=AssertionError("unexpected execution")):
        assert module.main([]) == 0
    output = capsys.readouterr().out
    assert "No privileged probes executed" in output
    for _, filename, _ in module.STAGES:
        assert filename in output
    assert "--after-binding --run-privileged" in output


def test_root_required_before_any_stage():
    with (
        patch.object(module.os, "geteuid", return_value=1000),
        patch.object(module.subprocess, "run", side_effect=AssertionError("unexpected execution")),
    ):
        assert module.main(["--run-privileged"]) == 2


def test_matrix_contains_distinct_authority_and_isolation_checks():
    assert [filename for _, filename, _ in module.STAGES] == [
        "probe_provisioning_authority_acceptance.py",
        "probe_selected_profile_retirement.py",
        "probe_isolated_consumer_retirement.py",
        "probe_recovery.py",
        "probe_wireguard_dns_acceptance.py",
        "probe_production_wireguard_confinement.py",
    ]
    for _, filename, arguments in module.STAGES:
        assert (module.ROOT / "tools" / filename).is_file()
        assert "--run-privileged" in arguments


def test_failure_stops_without_running_later_stages(capsys):
    with patch.object(
        module.subprocess,
        "run",
        side_effect=[SimpleNamespace(returncode=0), SimpleNamespace(returncode=9)],
    ) as runner:
        assert not module.run_acceptance(python="python")
    assert runner.call_count == 2
    assert "later stages not attempted" in capsys.readouterr().err


def test_os_error_stops_without_running_later_stages(capsys):
    with patch.object(module.subprocess, "run", side_effect=OSError("cannot start")) as runner:
        assert not module.run_acceptance(python="python")
    assert runner.call_count == 1
    assert "cannot start" in capsys.readouterr().err


def test_success_requires_all_stages(capsys):
    with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as runner:
        assert module.run_acceptance(python="python")
    assert runner.call_count == len(module.STAGES)
    assert f"all {len(module.STAGES)}" in capsys.readouterr().out


def test_root_confirmation_delegates_to_runner():
    with (
        patch.object(module.os, "geteuid", return_value=0),
        patch.object(module, "run_acceptance", return_value=True) as runner,
    ):
        assert module.main(["--run-privileged"]) == 0
    runner.assert_called_once_with()


def test_real_tunnel_stage_follows_authority_and_recovery():
    """A successful integration run must reach the real tunnel confinement stage."""
    filenames = [filename for _, filename, _ in module.STAGES]
    assert filenames[-2:] == [
        "probe_wireguard_dns_acceptance.py",
        "probe_production_wireguard_confinement.py",
    ]
    assert filenames.index("probe_recovery.py") < filenames.index("probe_wireguard_dns_acceptance.py")


def test_real_tunnel_failure_prevents_success_reporting(capsys):
    """Failure of the final packet stage cannot be hidden by prior successes."""
    results = [SimpleNamespace(returncode=0) for _ in module.STAGES[:-1]]
    results.append(SimpleNamespace(returncode=7))
    with patch.object(module.subprocess, "run", side_effect=results) as runner:
        assert not module.run_acceptance(python="python")
    assert runner.call_count == len(module.STAGES)
    assert "single production-owned WireGuard profile confinement" in capsys.readouterr().err


def test_independent_real_tunnel_failure_prevents_production_stage(capsys):
    """A failed independent tunnel check must prevent production-stage execution."""
    stage = next(
        i for i, (_, filename, _) in enumerate(module.STAGES) if filename == "probe_wireguard_dns_acceptance.py"
    )
    results = [SimpleNamespace(returncode=0) for _ in module.STAGES[:stage]]
    results.append(SimpleNamespace(returncode=7))
    with patch.object(module.subprocess, "run", side_effect=results) as runner:
        assert not module.run_acceptance(python="python")
    assert runner.call_count == stage + 1
    assert "real WireGuard dual-stack DNS and firewall confinement" in capsys.readouterr().err
