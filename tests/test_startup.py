"""Adversarial tests for startup unit rendering, installation and run records."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import nordvpn_manage
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_startup import (
    initialise_startup_runs,
    install_startup_unit,
    plan_install,
    read_boot_id,
    record_startup_run,
    validate_startup_config,
)


UUID = "12345678-1234-5678-9abc-000000000004"
OTHER_UUID = "12345678-1234-5678-9abc-000000000005"
UUID_MOCK_PATTERN = __import__("re").compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


def config(root: Path) -> dict:
    return {
        "version": 1,
        "policy": str(root / "policy.json"),
        "journal": str(root / "lifecycle.json"),
        "bindings": str(root / "owner-bindings.json"),
        "run_record": str(root / "startup-runs.json"),
        "tunnels": {},
        "credentials": {},
    }


class RunRecordStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "startup-runs.json"
        initialise_startup_runs(self.store)

    def sample_run(self, boot_id=UUID):
        return {
            "boot_id": boot_id,
            "recorded_at": "2026-11-02T12:00:00+00:00",
            "reconciled": True,
            "restored": ["primary"],
            "blocked": [],
            "operator_review_required": False,
        }

    def test_records_are_append_and_validated(self):
        record_startup_run(self.store, self.sample_run())
        record_startup_run(self.store, self.sample_run(OTHER_UUID))
        result = record_startup_run(self.store, self.sample_run())
        self.assertEqual([run["boot_id"] for run in result["runs"]], [UUID, OTHER_UUID, UUID])
        modes = [os.stat(self.store).st_mode & 0o777, os.stat(str(self.store) + ".lock").st_mode & 0o777]
        self.assertEqual(modes, [0o600, 0o600])

    def test_malformed_entries_are_refused(self):
        bad = self.sample_run()
        bad["restored"] = "primary"
        with self.assertRaises(RegistryError):
            record_startup_run(self.store, bad)
        with self.assertRaises(RegistryError):
            record_startup_run(
                self.store, {"boot_id": "not-a-uuid", **{k: v for k, v in self.sample_run().items() if k != "boot_id"}}
            )


class BootIdTests(unittest.TestCase):
    def test_boot_id_representation(self):
        real = read_boot_id()
        self.assertTrue(UUID_MOCK_PATTERN.fullmatch(real), real)

    def test_a_written_boot_identity_is_validated(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "boot_id"
            source.write_text(f"{UUID}\n", encoding="ascii")
            self.assertEqual(read_boot_id(str(source)), UUID)
            source.write_text("not-a-uuid", encoding="ascii")
            with self.assertRaises(RegistryError):
                read_boot_id(str(source))
            source.write_text("", encoding="ascii")
            with self.assertRaises(RegistryError):
                read_boot_id(str(source))


class UnitRenderingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_rendering_is_deterministic_and_complete(self):
        cfg = config(self.root)
        first = nordvpn_manage_render(cfg)
        second = nordvpn_manage_render(cfg)
        wording = [
            "[Unit]",
            "Wants=network-online.target",
            "After=network-online.target",
            "ConditionPathExists=",
            "Type=oneshot",
            "RemainAfterExit=yes",
            "restore-startup",
            "[Install]",
        ]
        self.assertEqual(first, second)
        for line in wording:
            self.assertIn(line, first)
        self.assertNotIn("--transient", first)

    def test_paths_must_be_safe(self):
        base = config(self.root)
        base["policy"] = "relative/policy.json"
        with self.assertRaises(RegistryError):
            validate_startup_config(base)
        dangerous = config(self.root)
        dangerous["journal"] = '/tmp/x"; touch /vulnerable'
        with self.assertRaises(RegistryError):
            validate_startup_config(dangerous)
        spaces = config(self.root)
        spaces["policy"] = str(self.root / "policy two.json")
        with self.assertRaises(RegistryError):
            validate_startup_config(spaces)

    def test_tunnel_plans_and_credentials_must_align(self):
        cfg = config(self.root)
        cfg["tunnels"] = {"primary": {}}
        with self.assertRaises(RegistryError):
            validate_startup_config(cfg)
        cfg["tunnels"]["primary"] = {
            "peer_public_key": "a" * 43 + "=",
            "endpoint_address": "198.51.100.10",
            "endpoint_port": 51820,
            "tunnel_address": "10.213.240.2/32",
            "peer_allowed_ips": ["0.0.0.0/0"],
            "underlay": {"namespace_address": "10.214.0.2/30", "host_address": "10.214.0.1/30"},
        }
        # Credential entries may outnumber the tunnel plans.
        cfg["credentials"] = {"primary": "/etc/nord-tools/primary.key", "other": "/etc/nord-tools/other.key"}
        checked = validate_startup_config(cfg)
        self.assertEqual(checked["credentials"]["other"], "/etc/nord-tools/other.key")


def nordvpn_manage_render(cfg):
    from nord_tools_internal.nordvpn_startup import render_startup_unit

    return render_startup_unit(cfg, "/etc/nord-tools/startup.json", script_path="/opt/nord-tools/nordvpn_manage.py")


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.unit_dir = self.root / "units"
        self.unit_dir.mkdir()

    def test_plan_then_install_is_idempotent_and_refuses_foreign_files(self):
        cfg = config(self.root)
        planned = plan_install(
            cfg, "/etc/nord-tools/startup.json", self.unit_dir, script_path="/opt/nord-tools/nordvpn_manage.py"
        )
        self.assertEqual((planned["action"], planned["executed"]), ("create", False))
        self.assertFalse((self.unit_dir / "nord-tools-restore.service").exists())

        installed = install_startup_unit(
            cfg,
            "/etc/nord-tools/startup.json",
            self.unit_dir,
            execute=True,
            script_path="/opt/nord-tools/nordvpn_manage.py",
        )
        self.assertEqual(installed["executed"], True)
        target = self.unit_dir / "nord-tools-restore.service"
        self.assertTrue(target.exists())
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o644)

        again = install_startup_unit(
            cfg,
            "/etc/nord-tools/startup.json",
            self.unit_dir,
            execute=True,
            script_path="/opt/nord-tools/nordvpn_manage.py",
        )
        self.assertEqual(again["action"], "unchanged")
        planned_update = plan_install(
            cfg, "/etc/nordtools/startup.json", self.unit_dir, script_path="/opt/nord-tools/nordvpn_manage.py"
        )
        self.assertNotEqual(planned_update["unit"], target.read_text(encoding="utf-8"))

        altered = [
            line
            for line in target.read_text(encoding="utf-8").splitlines(keepends=True)
            if not line.startswith("# Managed by Nord Tools")
        ]
        target.write_text("".join(altered))
        with self.assertRaises(RegistryError):
            install_startup_unit(
                cfg,
                "/etc/nord-tools/startup.json",
                self.unit_dir,
                execute=True,
                script_path="/opt/nord-tools/nordvpn_manage.py",
            )
        self.assertFalse("Managed by Nord Tools" in target.read_text(encoding="utf-8"))

    def test_symlinked_unit_target_is_refused(self):
        cfg = config(self.root)
        elsewhere = self.root / "elsewhere.service"
        elsewhere.write_text("[Unit]\n")
        os.symlink(elsewhere, self.unit_dir / "nord-tools-restore.service")
        with self.assertRaises(RegistryError):
            plan_install(
                cfg, "/etc/nord-tools/startup.json", self.unit_dir, script_path="/opt/nord-tools/nordvpn_manage.py"
            )
        self.assertEqual(elsewhere.read_text(encoding="utf-8"), "[Unit]\n")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy_path = self.root / "policy.json"
        self.policy_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {"vpn": "primary"},
                    "vpn_profiles": {
                        "primary": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}
                    },
                    "applications": {},
                }
            ),
            encoding="utf-8",
        )
        self.config_path = self.root / "startup.json"
        self.config_path.write_text(json.dumps(config(self.root)))
        self.unit_dir = self.root / "units"
        self.unit_dir.mkdir()

    def call(self, *args):
        output, stderr = io.StringIO(), io.StringIO()
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(stderr),
        ):
            code = nordvpn_manage.main([*args])
        return code, output.getvalue(), stderr.getvalue()

    def test_invalid_configuration_fails_closed(self):
        self.config_path.write_text(json.dumps({"version": 2}))
        code, output, stderr = self.call("startup-plan", "--config", str(self.config_path))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("startup configuration", stderr)

    def test_startup_install_reports_then_writes_on_execute(self):
        code, output, _ = self.call(
            "startup-install",
            "--config",
            str(self.config_path),
            "--unit-dir",
            str(self.unit_dir),
            "--python",
            "/usr/bin/python3",
        )
        self.assertEqual(code, 0)
        import json as jsonlib

        result = jsonlib.loads(output)
        self.assertFalse(result["executed"])
        self.assertFalse((self.unit_dir / "nord-tools-restore.service").exists())
        code, output, _ = self.call(
            "startup-install",
            "--config",
            str(self.config_path),
            "--unit-dir",
            str(self.unit_dir),
            "--python",
            "/usr/bin/python3",
            "--execute",
        )
        self.assertEqual(code, 0)
        self.assertTrue(
            (self.unit_dir / "nord-tools-restore.service")
            .read_text(encoding="utf-8")
            .startswith("# Managed by Nord Tools")
        )


if __name__ == "__main__":
    unittest.main()
