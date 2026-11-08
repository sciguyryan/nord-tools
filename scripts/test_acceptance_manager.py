from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def manager():
    path = Path(__file__).with_name("acceptance-manager.py")
    spec = spec_from_file_location("acceptance_manager", path)
    module = module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_address_selects_only_expected_mac(manager, monkeypatch):
    output = """ Name   MAC address         Protocol   Address
 other  52:54:00:aa:bb:cc   ipv4       192.0.2.10/24
 eth0   52:54:00:4e:54:08   ipv4       10.0.2.15/24
"""
    monkeypatch.setattr(
        manager,
        "virsh",
        lambda *args, **kwargs: SimpleNamespace(stdout=output, returncode=0),
    )

    assert manager.address() == "10.0.2.15"


def test_status_does_not_treat_libvirt_failure_as_absence(manager, monkeypatch):
    monkeypatch.setattr(
        manager,
        "virsh",
        lambda *args, **kwargs: SimpleNamespace(stdout="", stderr="permission denied", returncode=1),
    )

    with pytest.raises(RuntimeError, match="permission denied"):
        manager.status()


def test_readiness_reports_cloud_init_failure(manager, monkeypatch):
    monkeypatch.setattr(manager, "status", lambda: "running")
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="status: error\ndetail: package installation failed\n",
            stderr="",
            returncode=2,
        ),
    )

    assert manager.readiness().startswith("Provisioning failed:")


def test_readiness_keeps_waiting_for_ssh(manager, monkeypatch):
    monkeypatch.setattr(manager, "status", lambda: "running")
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="",
            stderr="ssh: connect to host 127.0.0.1 port 22222: Connection refused",
            returncode=255,
        ),
    )

    assert manager.readiness().startswith("SSH or cloud-init unavailable:")


def test_ssh_uses_loopback_forward_and_dedicated_identity(manager):
    command = manager.ssh_args("true")

    assert command[0] == "ssh"
    assert command[command.index("-p") + 1] == str(manager.SSH_PORT)
    assert command[command.index("-i") + 1] == str(manager.SSH_PRIVATE_KEY)
    assert f"arch@{manager.SSH_HOST}" in command
    assert "IdentitiesOnly=yes" in command
    assert any(value.startswith("UserKnownHostsFile=") for value in command)


def test_acceptance_key_is_generated_without_using_personal_key(manager, monkeypatch, tmp_path):
    private = tmp_path / "id_ed25519"
    public = tmp_path / "id_ed25519.pub"
    monkeypatch.setattr(manager, "SSH_PRIVATE_KEY", private)
    monkeypatch.setattr(manager, "SSH_PUBLIC_KEY", public)

    value = manager.acceptance_public_key()

    assert value.startswith("ssh-ed25519 ")
    assert private.stat().st_mode & 0o777 == 0o600
    assert public.stat().st_mode & 0o777 == 0o600


def test_cloud_init_prepares_trusted_network_namespace_config_parent():
    source = Path(__file__).with_name("acceptance-manager.py").read_text(encoding="utf-8")

    assert "- [install, -d, -m, '0755', -o, root, -g, root, /etc/netns]" in source


@pytest.mark.parametrize(
    "state",
    ["Guest is not running", "SSH or cloud-init unavailable: connection refused", "Provisioning failed: broken"],
)
def test_test_command_reports_rebuild_hint_only_for_stopped_guest(manager, monkeypatch, state):
    monkeypatch.setattr(manager, "readiness", lambda: state)
    monkeypatch.setattr(manager, "upload_source", lambda: pytest.fail("source uploaded despite failed readiness"))
    with pytest.raises(RuntimeError) as error:
        manager.run_tests()
    message = str(error.value)
    assert state in message
    assert ("acceptance-manager.py rebuild" in message) == (state == "Guest is not running")


def test_failure_evidence_exports_only_registered_path(manager, monkeypatch):
    calls = []
    monkeypatch.setattr(manager, "export_evidence", lambda path: calls.append(path) or "exported")
    assert manager.export_failure_evidence("FAILED RUN EVIDENCE RETAINED: /tmp/nt-production-wg-abc123") == "exported"
    assert calls == ["/tmp/nt-production-wg-abc123"]
    assert "No registered" in manager.export_failure_evidence("FAILED RUN EVIDENCE RETAINED: /etc/shadow")


def test_failure_evidence_export_does_not_mask_original_failure(manager, monkeypatch):
    def fail(_path):
        raise RuntimeError("SSH failed")

    monkeypatch.setattr(manager, "export_evidence", fail)
    assert "SSH failed" in manager.export_failure_evidence("FAILED RUN EVIDENCE RETAINED: /tmp/nt-production-wg-abc123")


def test_evidence_export_rejects_guest_filename_traversal(manager, monkeypatch, tmp_path):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: cloud-init completed successfully")
    monkeypatch.setattr(manager.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path / "export"))
    (tmp_path / "export").mkdir()
    monkeypatch.setattr(
        manager.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout='{"files": {"../escape.json": {"x": 1}}}', stderr=""
        ),
    )
    with pytest.raises(RuntimeError, match="invalid filename"):
        manager.export_evidence()
    assert not (tmp_path / "escape.json").exists()


def test_evidence_export_writes_private_redacted_files(manager, monkeypatch, tmp_path):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: cloud-init completed successfully")
    monkeypatch.setattr(manager.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path / "export"))
    (tmp_path / "export").mkdir()
    monkeypatch.setattr(
        manager.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"guest_directory": "/tmp/nt-production-wg-abc", "files": {"startup.json": {"safe": 1}}, "excluded": ["client.key"]}',
            stderr="",
        ),
    )
    assert "Redacted guest evidence exported" in manager.export_evidence()
    assert (tmp_path / "export" / "startup.json").is_file()
    assert (tmp_path / "export" / "startup.json").stat().st_mode & 0o777 == 0o600


def test_evidence_export_sends_script_on_stdin(manager, monkeypatch):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: cloud-init completed successfully")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=1, stdout="", stderr="deliberate stop")

    monkeypatch.setattr(manager.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="deliberate stop"):
        manager.export_evidence("/tmp/nt-production-wg-test")
    assert captured["args"][-1] == "sudo -n python - /tmp/nt-production-wg-test"
    assert captured["kwargs"]["input"] == manager.GUEST_EVIDENCE_SCRIPT
    assert captured["kwargs"]["text"] is True


def test_evidence_export_rejects_untrusted_guest_path(manager, monkeypatch):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: cloud-init completed successfully")
    with pytest.raises(RuntimeError, match="Invalid guest evidence directory"):
        manager.export_evidence("/tmp/nt-production-wg-safe;touch /tmp/unsafe")


def test_evidence_collector_executes_from_stdin(manager):
    import subprocess

    result = subprocess.run(
        ["sh", "-c", "python -"],
        input="import json\nprint(json.dumps({'ok': True}))\n",
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip() == '{"ok": true}'
