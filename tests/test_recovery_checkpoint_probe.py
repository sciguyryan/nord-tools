"""The recovery acceptance checkpoint must be before any kernel callback."""

import os
from unittest.mock import patch

import pytest

from tools.probe_recovery import checkpoint_child


def test_checkpoint_child_persists_through_provision_adapter_before_mutation(tmp_path):
    from nord_tools_internal import nordvpn_restore_executor as restore

    read_fd, write_fd = os.pipe()
    called = []

    def fake_adapter(store_path, journal, allocation_id, operation, verify):
        called.append((store_path, journal, allocation_id))
        # The operation is deliberately not invoked: the child must only
        # install a wrapper and must not mutate the kernel during setup.
        return "installed"

    def fake_main(argv):
        assert argv == ["restore-startup", "--config", str(tmp_path / "startup.json")]
        assert restore.execute_recorded_creation("store", {}, "allocation", lambda: None, lambda _: True) == "installed"
        return 0

    with (
        patch.object(restore, "execute_recorded_creation", fake_adapter),
        patch("tools.probe_recovery.nordvpn_manage.main", fake_main),
    ):
        assert checkpoint_child(str(tmp_path / "startup.json"), write_fd) == 0
    os.close(read_fd)
    assert called == [("store", {}, "allocation")]
    with pytest.raises(OSError):
        os.fstat(write_fd)


def test_recovery_probe_success_removes_disposable_evidence():
    """A successful probe must not bypass the cleanup after its try block."""
    import ast
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "tools" / "probe_recovery.py"
    module = ast.parse(source.read_text(encoding="utf-8"))
    function = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "run_probe")
    guarded = next(node for node in function.body if isinstance(node, ast.Try))
    assert not guarded.orelse, "success cleanup must not be unreachable in try/else"
    cleanup = next(
        node
        for node in function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "rmtree"
    )
    assert cleanup.lineno > guarded.end_lineno
    assert any(isinstance(node, ast.Return) for node in function.body if node.lineno > cleanup.lineno)


def test_checkpoint_after_binding_requires_durable_owner_record(tmp_path):
    """The partial-kernel checkpoint fires only after the real binding writer."""
    from nord_tools_internal import nordvpn_restore_executor as restore

    read_fd, write_fd = os.pipe()
    calls = []

    class CheckpointReached(Exception):
        pass

    def fake_binding(store_path, journal, allocation_id, binding, *, configuration=None):
        calls.append((allocation_id, binding))
        return None

    def fake_main(argv):
        assert argv == ["restore-startup", "--config", str(tmp_path / "startup.json")]
        restore.record_binding("store", {}, "interface", {"scope": "host", "ifindex": 4})
        restore.record_binding("store", {}, "namespace", {"device": 5, "inode": 100})
        return 0

    with (
        patch.object(restore, "record_binding", fake_binding),
        patch("tools.probe_recovery.nordvpn_manage.main", fake_main),
        patch("tools.probe_recovery.signal.pause", side_effect=CheckpointReached),
        pytest.raises(CheckpointReached),
    ):
        checkpoint_child(str(tmp_path / "startup.json"), write_fd, after_binding=True)
    assert os.read(read_fd, 1) == b"R"
    assert len(calls) == 2
    os.close(read_fd)
    with pytest.raises(OSError):
        os.fstat(write_fd)
