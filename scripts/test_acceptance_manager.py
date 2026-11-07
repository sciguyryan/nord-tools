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
