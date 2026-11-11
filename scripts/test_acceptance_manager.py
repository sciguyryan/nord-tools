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


def test_readiness_labels_cloud_init_boot_relative_update_time(manager, monkeypatch):
    monkeypatch.setattr(manager, "status", lambda: "running")
    monkeypatch.setattr(manager, "python_health", lambda: None)
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=(
                "status: done\n"
                "last_update: Thu, 01 Jan 1970 00:01:00 +0000\n"
                "detail: DataSourceNoCloud [seed=/dev/sr0]\n"
            ),
            stderr="",
            returncode=0,
        ),
    )

    result = manager.readiness()

    assert "completion_offset: 60 seconds after boot" in result
    assert "01 Jan 1970" not in result


def test_cloud_init_wall_clock_update_time_is_preserved(manager):
    output = "last_update: Tue, 10 Nov 2026 15:18:51 +0000"

    assert manager.normalise_cloud_init_status(output) == output


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
    assert "def start_detached_host_acceptance" in source
    assert 'probe="probe_host_domain_acceptance.py"' in source
    assert '"--startup-delay"' in source
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


def test_d3_guest_agent_exec_uses_exact_guest_and_captures_output(manager, monkeypatch):
    import base64

    calls = []

    def fake_virsh(*args, **kwargs):
        calls.append(args)
        request = json.loads(args[2])
        if request["execute"] == "guest-exec":
            assert request["arguments"]["path"] == "/usr/bin/cat"
            assert request["arguments"]["arg"] == ["/proc/sys/kernel/random/boot_id"]
            return SimpleNamespace(returncode=0, stdout=json.dumps({"return": {"pid": 42}}), stderr="")
        assert request["execute"] == "guest-exec-status"
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "return": {
                        "exited": True,
                        "exitcode": 0,
                        "out-data": base64.b64encode(b"boot-two\n").decode(),
                    }
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(manager, "virsh", fake_virsh)
    assert manager.qga_command("/usr/bin/cat", "/proc/sys/kernel/random/boot_id") == "boot-two\n"
    assert all(args[1] == manager.VM for args in calls)


def test_d3_guest_agent_rejects_failed_guest_command(manager, monkeypatch):
    import base64

    def fake_virsh(*args, **kwargs):
        request = json.loads(args[2])
        if request["execute"] == "guest-exec":
            return SimpleNamespace(returncode=0, stdout='{"return":{"pid":9}}', stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "return": {
                        "exited": True,
                        "exitcode": 1,
                        "err-data": base64.b64encode(b"protected state unresolved").decode(),
                    }
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(manager, "virsh", fake_virsh)
    with pytest.raises(RuntimeError, match="protected state unresolved"):
        manager.qga_command("/usr/bin/false")


def test_d3_wait_for_reboot_rejects_same_boot(manager, monkeypatch):
    monkeypatch.setattr(manager, "qga_command", lambda *a, **k: "same\n")
    times = iter([0, 1, 3, 5])
    monkeypatch.setattr(manager.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(manager.time, "sleep", lambda _: None)
    with pytest.raises(RuntimeError, match="different kernel boot ID"):
        manager.wait_for_qga_boot("same", timeout=2)


def test_d3_waits_for_ssh_after_verified_retirement(manager, monkeypatch):
    attempts = iter(
        [
            SimpleNamespace(returncode=255, stdout="", stderr="Connection refused"),
            SimpleNamespace(returncode=0, stdout='{"result":"passed"}\n', stderr=""),
        ]
    )
    monkeypatch.setattr(manager, "ssh", lambda *a, **k: next(attempts))
    monkeypatch.setattr(manager.time, "sleep", lambda _: None)

    assert manager.wait_for_d3_result() == '{"result":"passed"}\n'


def test_d3_ssh_wait_reports_bounded_failure(manager, monkeypatch):
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *a, **k: SimpleNamespace(returncode=255, stdout="", stderr="Connection refused"),
    )
    times = iter([0, 1, 3])
    monkeypatch.setattr(manager.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(manager.time, "sleep", lambda _: None)

    with pytest.raises(RuntimeError, match=r"did not return within 2 seconds \(Connection refused\)"):
        manager.wait_for_d3_result(timeout=2)


def test_local_dependency_closure_follows_imports_and_file_references(manager, monkeypatch, tmp_path):
    (tmp_path / "product.py").write_text("VALUE = 1\n")
    (tmp_path / "helper.py").write_text("from product import VALUE\n")
    (tmp_path / "runner.py").write_text('TARGET = "extra.py"\n')
    (tmp_path / "extra.py").write_text("EXTRA = True\n")
    (tmp_path / "fixture.json").write_text("{}\n")
    (tmp_path / "test_product.py").write_text('import helper\nimport runner\nDATA = "fixture.json"\n')
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)

    assert manager.local_python_dependencies("test_product.py") == [
        "extra.py",
        "fixture.json",
        "helper.py",
        "product.py",
        "runner.py",
        "test_product.py",
    ]


def test_local_dependency_closure_resolves_unique_probe_filename(manager):
    dependencies = manager.local_python_dependencies("tests/test_wireguard_session_probe.py")

    assert "tools/probe_wireguard_session.py" in dependencies


def test_development_plan_reuses_only_equivalent_test_units(manager, monkeypatch, tmp_path):
    (tmp_path / "product.py").write_text("VALUE = 1\n")
    (tmp_path / "other.py").write_text("OTHER = 1\n")
    (tmp_path / "fixture.json").write_text('{"value": 1}\n')
    (tmp_path / "test_product.py").write_text('import product\nDATA = "fixture.json"\n')
    (tmp_path / "test_other.py").write_text("import other\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/impact-rules.json").write_text('{"schema_version":1,"rules":[]}\n')
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)
    environment = {"python": "3.13", "pytest": "9", "platform": "test", "ruff": "1", "node": "2", "npm": "3"}
    first = manager.build_execution_plan(
        mode="development",
        selected=("quality",),
        environment=environment,
        cache=manager._empty_result_cache(),
    )
    cache = manager._empty_result_cache()
    cache["entries"] = {unit["id"]: {"fingerprint": unit["fingerprint"], "result": "passed"} for unit in first}

    equivalent = manager.build_execution_plan(
        mode="development", selected=("quality",), environment=environment, cache=cache
    )
    assert all(not unit["execute"] for unit in equivalent)

    (tmp_path / "fixture.json").write_text('{"value": 2}\n')
    fixture_changed = manager.build_execution_plan(
        mode="development", selected=("quality",), environment=environment, cache=cache
    )
    fixture_decisions = {unit["id"]: unit["execute"] for unit in fixture_changed}
    assert fixture_decisions["pytest:test_product.py"] is True
    assert fixture_decisions["pytest:test_other.py"] is False

    (tmp_path / "fixture.json").write_text('{"value": 1}\n')
    (tmp_path / "product.py").write_text("VALUE = 2\n")
    changed = manager.build_execution_plan(
        mode="development", selected=("quality",), environment=environment, cache=cache
    )
    decisions = {unit["id"]: unit["execute"] for unit in changed}
    assert decisions["pytest:test_product.py"] is True
    assert decisions["pytest:test_other.py"] is False
    assert decisions["quality:ruff"] is True
    assert decisions["quality:markdown"] is False

    (tmp_path / "product.py").write_text("VALUE = 1\n")
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    configured = manager.build_execution_plan(
        mode="development", selected=("quality",), environment=environment, cache=cache
    )
    configured_decisions = {unit["id"]: unit["execute"] for unit in configured}
    assert configured_decisions["pytest:test_product.py"] is True
    assert configured_decisions["pytest:test_other.py"] is True


def test_final_plan_forces_complete_execution_and_rejects_partial_scope(manager):
    environment = {"python": "3.13"}
    plan = manager.build_execution_plan(
        mode="final",
        selected=("all",),
        environment=environment,
        cache=manager._empty_result_cache(),
    )
    assert plan
    assert all(unit["execute"] for unit in plan)

    with pytest.raises(ValueError, match="Final mode requires"):
        manager.build_execution_plan(
            mode="final",
            selected=("d3",),
            environment=environment,
            cache=manager._empty_result_cache(),
        )


def test_host_protection_code_invalidates_each_host_scenario(manager):
    environment = {"python": "3.13", "kernel": "test"}
    plan = manager.build_execution_plan(
        mode="development",
        selected=("d1", "d2", "d3"),
        environment=environment,
        cache=manager._empty_result_cache(),
    )

    assert {unit["id"] for unit in plan} == {"scenario:d1", "scenario:d2", "scenario:d3"}
    for unit in plan:
        assert "nord_tools_internal/nordvpn_host_protection.py" in unit["paths"]


def test_scenario_environment_ignores_unrelated_lint_tool_changes(manager):
    environment = {
        "python": "3.13",
        "kernel": "test",
        "ruff": "old",
        "packages": {"nftables": "1", "wireguard-tools": "1"},
    }
    first = manager.build_execution_plan(
        mode="development",
        selected=("d1",),
        environment=environment,
        cache=manager._empty_result_cache(),
    )
    cache = manager._empty_result_cache()
    cache["entries"] = {first[0]["id"]: {"fingerprint": first[0]["fingerprint"], "result": "passed"}}

    lint_changed = manager.build_execution_plan(
        mode="development",
        selected=("d1",),
        environment={**environment, "ruff": "new"},
        cache=cache,
    )
    assert lint_changed[0]["execute"] is False

    network_changed = manager.build_execution_plan(
        mode="development",
        selected=("d1",),
        environment={**environment, "packages": {"nftables": "2", "wireguard-tools": "1"}},
        cache=cache,
    )
    assert network_changed[0]["execute"] is True


def test_guest_environment_identity_probe_is_valid_python(manager, monkeypatch):
    scripts = []

    def guest_command(script, **_kwargs):
        scripts.append(script)
        return SimpleNamespace(returncode=0, stdout='{"python":"3.13"}\n', stderr="")

    monkeypatch.setattr(manager, "guest_command", guest_command)

    assert manager.guest_environment_identity() == {"python": "3.13"}
    compile(scripts[0], "<guest-environment-identity>", "exec")


def test_result_cache_round_trip_is_private_and_workspace_bound(manager, monkeypatch, tmp_path):
    cache = tmp_path / "results.json"
    lock = tmp_path / "results.lock"
    monkeypatch.setattr(manager, "RESULT_CACHE", cache)
    monkeypatch.setattr(manager, "RESULT_CACHE_LOCK", lock)
    unit = {"id": "pytest:test_one.py", "fingerprint": "abc"}

    manager.publish_result_cache([unit], "run-one")
    document, status = manager.load_result_cache()

    assert status == "validated prior development result cache"
    assert document["entries"][unit["id"]]["result"] == "passed"
    assert cache.stat().st_mode & 0o777 == 0o600


def test_result_cache_rejects_unsafe_permissions(manager, monkeypatch, tmp_path):
    cache = tmp_path / "results.json"
    cache.write_text(json.dumps(manager._empty_result_cache()))
    cache.chmod(0o666)
    monkeypatch.setattr(manager, "RESULT_CACHE", cache)

    document, status = manager.load_result_cache()

    assert document["entries"] == {}
    assert "permissions are unsafe" in status


def test_cli_rejects_partial_final_acceptance_scope():
    result = subprocess.run(
        [
            sys.executable,
            "scripts/acceptance-manager.py",
            "test",
            "--mode",
            "final",
            "--scenario",
            "d3",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 2
    assert "final mode requires --scenario all" in result.stderr


def test_guest_used_probe_fails_closed_on_transport_error(manager, monkeypatch):
    monkeypatch.setattr(
        manager,
        "ssh",
        lambda *a, **k: SimpleNamespace(returncode=255, stdout="", stderr="connection refused"),
    )

    with pytest.raises(RuntimeError, match="Unable to verify whether"):
        manager._guest_was_used()


def test_test_only_mode_option_is_rejected_for_status():
    result = subprocess.run(
        [sys.executable, "scripts/acceptance-manager.py", "status", "--mode", "development"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 2
    assert "apply only to test" in result.stderr


def test_run_tests_does_not_execute_equivalent_reused_units(manager, monkeypatch):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: test")
    monkeypatch.setattr(manager, "guest_provisioning_issues", lambda: [])
    monkeypatch.setattr(manager, "upload_source", lambda: None)
    monkeypatch.setattr(manager, "guest_environment_identity", lambda: {"python": "test"})
    monkeypatch.setattr(manager, "load_result_cache", lambda: (manager._empty_result_cache(), "test cache"))
    monkeypatch.setattr(
        manager,
        "build_execution_plan",
        lambda **kwargs: [
            {
                "id": "pytest:tests/test_one.py",
                "kind": "pytest",
                "fingerprint": "one",
                "execute": False,
                "reason": "unchanged",
            },
            {
                "id": "scenario:d3",
                "kind": "scenario",
                "fingerprint": "two",
                "execute": False,
                "reason": "unchanged",
            },
        ],
    )
    monkeypatch.setattr(
        manager,
        "_run_guest_script",
        lambda command: pytest.fail("guest script ran despite complete result reuse"),
    )
    monkeypatch.setattr(
        manager,
        "_guest_was_used",
        lambda: pytest.fail("guest taint checked despite no executable scenario"),
    )

    result = manager.run_tests()

    assert "0 executed, 2 reused" in result


@pytest.mark.parametrize("mode", ("development", "final"))
def test_run_tests_executes_only_selected_pytest_files(manager, monkeypatch, mode):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: test")
    monkeypatch.setattr(manager, "guest_provisioning_issues", lambda: [])
    monkeypatch.setattr(manager, "upload_source", lambda: None)
    monkeypatch.setattr(manager, "guest_environment_identity", lambda: {"python": "test"})
    monkeypatch.setattr(manager, "load_result_cache", lambda: (manager._empty_result_cache(), "test cache"))
    unit = {
        "id": "pytest:tests/test_one.py",
        "kind": "pytest",
        "fingerprint": "one",
        "execute": True,
        "reason": "changed",
    }
    monkeypatch.setattr(manager, "build_execution_plan", lambda **kwargs: [unit])
    scripts = []
    monkeypatch.setattr(manager, "_run_guest_script", lambda command: scripts.append(command) or "passed")
    published = []
    monkeypatch.setattr(manager, "publish_result_cache", lambda units, run_id: published.extend(units))

    result = manager.run_tests(mode=mode, selected=("quality",))

    assert "python -m pytest -q tests/test_one.py" in scripts[0]
    assert published == [unit]
    assert "1 executed, 0 reused" in result


def test_run_tests_refuses_changed_privileged_scenario_on_used_guest(manager, monkeypatch):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: test")
    monkeypatch.setattr(manager, "guest_provisioning_issues", lambda: [])
    monkeypatch.setattr(manager, "upload_source", lambda: None)
    monkeypatch.setattr(manager, "guest_environment_identity", lambda: {"python": "test"})
    monkeypatch.setattr(manager, "load_result_cache", lambda: (manager._empty_result_cache(), "test cache"))
    monkeypatch.setattr(
        manager,
        "build_execution_plan",
        lambda **kwargs: [
            {
                "id": "scenario:d3",
                "kind": "scenario",
                "fingerprint": "d3",
                "execute": True,
                "reason": "changed",
            }
        ],
    )
    monkeypatch.setattr(manager, "_guest_was_used", lambda: True)

    with pytest.raises(RuntimeError, match=r"require a clean disposable guest \(d3\)"):
        manager.run_tests(selected=("d3",))


def test_combined_network_and_application_run_deduplicates_shared_stages(manager, monkeypatch):
    monkeypatch.setattr(manager, "readiness", lambda: "Ready: test")
    monkeypatch.setattr(manager, "guest_provisioning_issues", lambda: [])
    monkeypatch.setattr(manager, "upload_source", lambda: None)
    monkeypatch.setattr(manager, "guest_environment_identity", lambda: {"python": "test"})
    monkeypatch.setattr(manager, "load_result_cache", lambda: (manager._empty_result_cache(), "test cache"))
    units = [
        {"id": f"scenario:{name}", "kind": "scenario", "fingerprint": name, "execute": True, "reason": "changed"}
        for name in ("network", "application")
    ]
    monkeypatch.setattr(manager, "build_execution_plan", lambda **kwargs: units)
    monkeypatch.setattr(manager, "_guest_was_used", lambda: False)
    commands = []
    monkeypatch.setattr(manager, "_run_guest_script", lambda command: commands.append(command) or "passed")
    monkeypatch.setattr(manager, "publish_result_cache", lambda *_args: None)

    manager.run_tests(selected=("network", "application"))

    assert len(commands) == 1
    assert "probe_network_isolation_adversarial_acceptance.py --run-privileged" in commands[0]
    assert "probe_application_lifecycle_acceptance.py --run-privileged --application-stages-only" in commands[0]


def test_impact_policy_invalidation_is_additive_and_explainable(manager, monkeypatch, tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/impact-rules.json").write_text(
        '{"schema_version":1,"rules":[{"id":"cross-cutting","when_changed":["runtime.json"],'
        '"invalidate":["pytest:test_other.py"],"reason":"Runtime configuration"}]}\n'
    )
    (tmp_path / "runtime.json").write_text('{"enabled":true}\n')
    (tmp_path / "test_other.py").write_text("def test_ok(): assert True\n")
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)
    environment = {"python": "3.13", "pytest": "8", "platform": "test"}
    first = manager.build_execution_plan(
        mode="development", selected=("quality",), environment=environment, cache=manager._empty_result_cache()
    )
    unit = next(unit for unit in first if unit["id"] == "pytest:test_other.py")
    assert "runtime.json" in unit["paths"]
    assert unit["impact_rules"][0]["id"] == "cross-cutting"
    cache = manager._empty_result_cache()
    cache["entries"] = {item["id"]: {"result": "passed", "fingerprint": item["fingerprint"]} for item in first}
    assert not next(
        item
        for item in manager.build_execution_plan(
            mode="development", selected=("quality",), environment=environment, cache=cache
        )
        if item["id"] == unit["id"]
    )["execute"]
    (tmp_path / "runtime.json").write_text('{"enabled":false}\n')
    assert next(
        item
        for item in manager.build_execution_plan(
            mode="development", selected=("quality",), environment=environment, cache=cache
        )
        if item["id"] == unit["id"]
    )["execute"]


def test_impact_policy_malformed_fails_closed(manager, monkeypatch, tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/impact-rules.json").write_text('{"schema_version":1,"rules":[{"id":"bad"}]}')
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)
    with pytest.raises(ValueError, match="Invalid test impact rule"):
        manager.build_execution_plan(
            mode="development", selected=("quality",), environment={}, cache=manager._empty_result_cache()
        )


def test_dynamic_import_falls_back_to_all_local_python(manager, monkeypatch, tmp_path):
    (tmp_path / "test_dynamic.py").write_text('import importlib\nname = "computed"\nimportlib.import_module(name)\n')
    (tmp_path / "unrelated.py").write_text("VALUE = 1\n")
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)
    assert "unrelated.py" in manager.local_python_dependencies("test_dynamic.py")


def test_dynamic_import_from_literal_dispatch_table_stays_bounded(manager, monkeypatch, tmp_path):
    (tmp_path / "selected.py").write_text("VALUE = 1\n")
    (tmp_path / "unrelated.py").write_text("VALUE = 2\n")
    (tmp_path / "dispatcher.py").write_text(
        'import importlib\nCOMMANDS = {"chosen": ("selected",)}\n'
        "def load(name): return importlib.import_module(COMMANDS[name][0])\n"
    )
    (tmp_path / "test_dispatcher.py").write_text("import dispatcher\n")
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)

    dependencies = manager.local_python_dependencies("test_dispatcher.py")

    assert "selected.py" in dependencies
    assert "unrelated.py" not in dependencies


def test_privileged_scenarios_reuse_equivalent_development_evidence(manager):
    first = manager.build_execution_plan(
        mode="development", selected=("d1",), environment={"python": "3.13"}, cache=manager._empty_result_cache()
    )
    cache = manager._empty_result_cache()
    cache["entries"] = {first[0]["id"]: {"result": "passed", "fingerprint": first[0]["fingerprint"]}}
    again = manager.build_execution_plan(
        mode="development", selected=("d1",), environment={"python": "3.13"}, cache=cache
    )
    assert not again[0]["execute"]
    assert "unchanged" in again[0]["reason"]


def test_subprocess_use_does_not_expand_dependency_closure(manager, monkeypatch, tmp_path):
    (tmp_path / "product.py").write_text('import subprocess\nsubprocess.run(["true"], check=False)\n')
    (tmp_path / "unrelated.py").write_text("VALUE = 1\n")
    (tmp_path / "test_product.py").write_text("import product\n")
    monkeypatch.setattr(manager, "SOURCE_ROOT", tmp_path)

    dependencies = manager.local_python_dependencies("test_product.py")

    assert "product.py" in dependencies
    assert "unrelated.py" not in dependencies
