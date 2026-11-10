import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import subprocess
import sys
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
    monkeypatch.setattr(manager, "python_health", lambda: None)
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


def test_ssh_preserves_remote_command_argument_boundaries(manager):
    command = manager.ssh_args(
        "/usr/bin/python",
        "-c",
        "import operator, argparse, sys; print(sys.version)",
    )

    assert command[-1] == ("/usr/bin/python -c 'import operator, argparse, sys; print(sys.version)'")


def test_ssh_without_remote_command_remains_interactive(manager):
    command = manager.ssh_args()

    assert command[-1] == f"arch@{manager.SSH_HOST}"


def test_acceptance_status_colour_is_terminal_opt_in(manager):
    line = "PASS: tunnel active; FAIL: bypass detected\n"
    assert manager.colourise_acceptance_status(line, enabled=False) == line
    assert manager.colourise_acceptance_status(line, enabled=True) == (
        "\033[32mPASS\033[0m: tunnel active; \033[31mFAIL\033[0m: bypass detected\n"
    )
    assert manager.colourise_acceptance_status(line, enabled=True, colourblind=True) == (
        "\033[38;5;33mPASS\033[0m: tunnel active; \033[38;5;208mFAIL\033[0m: bypass detected\n"
    )


def test_acceptance_manager_exposes_both_colourblind_spellings():
    for flag in ("--colourblind", "--colorblind"):
        result = subprocess.run(
            [sys.executable, "scripts/acceptance-manager.py", flag, "--help"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        assert result.returncode == 0
        assert "blue PASS and orange FAIL" in result.stdout


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
    assert 'package_list = ", ".join(REQUIRED_PACKAGES)' in source
    assert "sudo -n python tools/probe_desktop_launch_acceptance.py" in source
    assert "systemd-run --no-block --collect" in source
    assert "probe_host_domain_acceptance.py --run-privileged --startup-delay 5" in source
    assert 'probe="probe_host_failure_recovery_acceptance.py"' in source


def test_host_acceptance_waits_for_reconnection_and_validates_scope(manager, monkeypatch):
    responses = iter(
        [
            SimpleNamespace(returncode=255, stdout="", stderr="connection refused"),
            SimpleNamespace(returncode=255, stdout="", stderr="connection refused"),
            SimpleNamespace(
                returncode=0,
                stdout='{"result":"passed","scope":"D1 host-domain static-egress acceptance"}',
                stderr="",
            ),
        ]
    )
    monkeypatch.setattr(manager, "ssh", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(manager.time, "sleep", lambda _seconds: None)

    report = manager.wait_for_host_acceptance(timeout=10)

    assert report["result"] == "passed"


def test_host_acceptance_treats_ssh_timeout_as_an_active_barrier(manager, monkeypatch):
    responses = iter(
        [
            subprocess.TimeoutExpired(("ssh",), 10),
            SimpleNamespace(
                returncode=0,
                stdout='{"result":"passed","scope":"D1 host-domain static-egress acceptance"}',
                stderr="",
            ),
        ]
    )

    def ssh(*_args, **_kwargs):
        response = next(responses)
        if isinstance(response, BaseException):
            raise response
        return response

    monkeypatch.setattr(manager, "ssh", ssh)
    monkeypatch.setattr(manager.time, "sleep", lambda _seconds: None)

    assert manager.wait_for_host_acceptance(timeout=10)["result"] == "passed"


def test_host_acceptance_rejects_incomplete_success_report(manager, monkeypatch):
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"result":"passed","scope":"component-only"}',
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match="complete expected scope"):
        manager.wait_for_host_acceptance(timeout=10)


def test_host_acceptance_reports_durable_failure_evidence(manager, monkeypatch):
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "result": "failed",
                    "scope": "D1 host-domain static-egress acceptance",
                    "error": "route inspection failed",
                    "evidence_dir": "/var/tmp/nord-tools-host-d1-evidence",
                }
            ),
            stderr="",
        ),
    )

    with pytest.raises(RuntimeError, match=r"(?s)route inspection failed.*Evidence retained"):
        manager.wait_for_host_acceptance(timeout=10)


def test_detached_host_stage_uses_distinct_unit_probe_and_evidence(manager, monkeypatch):
    calls = []
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *args, **kwargs: calls.append((args, kwargs)) or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    manager.start_detached_host_acceptance(
        unit="nord-tools-host-d2.service",
        probe="probe_host_failure_recovery_acceptance.py",
        evidence="/var/tmp/d2-evidence",
        result_path="/var/tmp/d2-result.json",
    )

    arguments = calls[0][0]
    assert "--unit=nord-tools-host-d2" in arguments
    assert f"{manager.REMOTE_ROOT}/tools/probe_host_failure_recovery_acceptance.py" in arguments
    assert "/var/tmp/d2-evidence" in arguments
    assert "/var/tmp/d2-result.json" in arguments


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


def test_test_command_refuses_incomplete_guest_contract(manager, monkeypatch):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: cloud-init completed successfully")
    monkeypatch.setattr(manager, "guest_provisioning_issues", lambda: ["guest dependencies missing: weston"])
    monkeypatch.setattr(manager, "upload_source", lambda: pytest.fail("source uploaded despite stale guest"))

    with pytest.raises(RuntimeError, match="acceptance-manager.py rebuild"):
        manager.run_tests()


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


def test_rebuild_plan_force_never_inspects_guest(manager, monkeypatch):
    monkeypatch.setattr(manager, "inspect_guest", lambda: (_ for _ in ()).throw(AssertionError("inspected")))
    assert manager.rebuild_plan(force=True) == (False, ["forced clean rebuild requested"])


def test_rebuild_plan_reuses_only_with_positive_inspection(manager, monkeypatch):
    monkeypatch.setattr(manager, "inspect_guest", lambda: [])
    assert manager.rebuild_plan() == (True, [])
    monkeypatch.setattr(manager, "inspect_guest", lambda: ["guest state uncertain"])
    assert manager.rebuild_plan() == (False, ["guest state uncertain"])


def test_source_manifest_detects_content_and_mode(manager, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    script = source / "probe.py"
    script.write_text("print('ok')\n")
    script.chmod(0o755)
    (source / "node_modules").mkdir()
    (source / "node_modules" / "ignored.js").write_text("ignored")
    original = manager.source_manifest(source)
    assert list(original) == ["probe.py"]
    assert original["probe.py"][1] == 0o755
    script.chmod(0o644)
    assert manager.source_manifest(source) != original
    script.write_text("print('changed')\n")
    assert manager.source_manifest(source)["probe.py"][0] != original["probe.py"][0]


def test_source_manifest_refuses_symlinks(manager, tmp_path):
    import pytest

    (tmp_path / "file").write_text("data")
    (tmp_path / "link").symlink_to(tmp_path / "file")
    with pytest.raises(RuntimeError, match="symlinks"):
        manager.source_manifest(tmp_path)


def test_source_upload_skips_only_exact_verified_manifest(manager, monkeypatch, tmp_path):
    import json
    import subprocess

    (tmp_path / "source.py").write_text("print('ok')\n")
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)
    manifest = manager.source_manifest(tmp_path)
    monkeypatch.setattr(
        manager, "guest_command", lambda *a, **kw: subprocess.CompletedProcess([], 0, json.dumps(manifest), "")
    )
    monkeypatch.setattr(manager, "ssh", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("unnecessary transfer")))
    manager.upload_source()
