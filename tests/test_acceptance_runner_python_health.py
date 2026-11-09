"""Regression checks for transient Arch guest Python failures during boot."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "acceptance-manager.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("nord_acceptance_runner", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def result(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def test_broken_python_is_not_mistaken_for_cloud_init_failure(monkeypatch):
    runner = load_runner()
    monkeypatch.setattr(runner, "status", lambda: "running")

    def fake_ssh(*args, **_kwargs):
        if args[0] == "/usr/bin/python":
            return result(1, stderr="ModuleNotFoundError: No module named 'operator'")
        return result(1, stderr="cloud-init could not import operator")

    monkeypatch.setattr(runner, "ssh", fake_ssh)
    assert runner.readiness().startswith("Guest Python unhealthy:")


def test_ready_requires_healthy_python_and_successful_cloud_init(monkeypatch):
    runner = load_runner()
    monkeypatch.setattr(runner, "status", lambda: "running")
    monkeypatch.setattr(
        runner,
        "ssh",
        lambda *args, **kwargs: (
            result(stdout="Python healthy") if args[0] == "/usr/bin/python" else result(stdout="status: done")
        ),
    )
    assert runner.readiness().startswith("Ready:")
    monkeypatch.setattr(
        runner,
        "ssh",
        lambda *args, **kwargs: (
            result(stdout="Python healthy") if args[0] == "/usr/bin/python" else result(1, stdout="status: done")
        ),
    )
    assert not runner.readiness().startswith("Ready:")


def test_persistent_python_failure_reports_diagnostics(monkeypatch):
    runner = load_runner()
    clock = iter((0, 0, 0, 0, 0, 91, 91, 91))
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(runner, "readiness", lambda: "Guest Python unhealthy: missing operator")
    monkeypatch.setattr(runner, "guest_boot_diagnostics", lambda: "package logs")
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    import pytest

    with pytest.raises(RuntimeError, match="package logs"):
        runner.wait_ready(timeout=360)
