"""Fail-fast orchestration tests; never execute privileged network probes."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "probe_provisioning_authority_acceptance.py"
spec = importlib.util.spec_from_file_location("provisioning_authority_acceptance", SOURCE)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_dry_run_never_executes(capsys):
    with patch.object(module.subprocess, "run", side_effect=AssertionError("unexpected execution")):
        assert module.main([]) == 0
    assert "No privileged probes executed" in capsys.readouterr().out


def test_unprivileged_confirmation_refused():
    with (
        patch.object(module.os, "geteuid", return_value=1000),
        patch.object(module.subprocess, "run", side_effect=AssertionError("unexpected execution")),
    ):
        assert module.main(["--run-privileged"]) == 2


def test_stages_are_explicit_and_ordered():
    assert [filename for _, filename in module.STAGES] == [
        "probe_ownership_preflight.py",
        "probe_restore_startup.py",
        "probe_cleanup.py",
        "probe_recovery.py",
        "probe_startup_restoration_lifecycle.py",
    ]


def test_failure_stops_without_running_later_stages(capsys):
    with patch.object(
        module.subprocess, "run", side_effect=[SimpleNamespace(returncode=0), SimpleNamespace(returncode=9)]
    ) as runner:
        assert not module.run_acceptance(python="python")
    assert runner.call_count == 2
    assert "later stages not attempted" in capsys.readouterr().err


def test_success_requires_every_stage(capsys):
    with patch.object(module.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as runner:
        assert module.run_acceptance(python="python")
    assert runner.call_count == 5
    assert "all five" in capsys.readouterr().out


def test_confirmed_root_dispatches_only_through_runner():
    with (
        patch.object(module.os, "geteuid", return_value=0),
        patch.object(module, "run_acceptance", return_value=True) as runner,
    ):
        assert module.main(["--run-privileged"]) == 0
    runner.assert_called_once_with()


def test_cleanup_probe_scopes_namespace_absence_to_its_fixture():
    from tools.probe_cleanup import _namespace_names

    observed = _namespace_names(b"nt-unrelated (id: 2)\nnt-fixture (id: 3)\n")
    assert "nt-fixture" in observed
    assert "nt-missing" not in observed


def test_recovery_probe_scopes_namespace_absence_to_its_fixture():
    from tools.probe_recovery import _namespace_names

    observed = _namespace_names(b"nt-unrelated (id: 2)\n")
    assert observed == {"nt-unrelated"}
