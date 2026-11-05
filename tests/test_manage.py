"""Regression tests for persistent and transient offline management intent."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import nord_tools
import nordvpn_manage


POLICY = {
    "version": 1,
    "defaults": {"vpn": "main"},
    "vpn_profiles": {"main": {"selection": {"mode": "country", "country": "GB"}}},
    "applications": {},
}


class ManageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(
            os.environ,
            {
                "XDG_RUNTIME_DIR": str(self.root / "runtime"),
                "XDG_CONFIG_HOME": str(self.root / "config"),
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        (self.root / "runtime").mkdir()
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps(POLICY), encoding="utf-8")

    def call(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code = nord_tools.main(["manage", *args])
        return code, json.loads(output.getvalue()) if output.getvalue() else None

    def test_plan_does_not_write(self):
        code, result = self.call("plan", "--policy", str(self.policy))
        self.assertEqual(code, 0)
        self.assertEqual(result["action"], "create")
        self.assertFalse(nordvpn_manage.state_path(True).exists())

    def test_transient_and_persistent_are_independent(self):
        self.assertEqual(self.call("configure", "--policy", str(self.policy))[0], 0)
        self.assertTrue(nordvpn_manage.state_path(True).exists())
        self.assertFalse(nordvpn_manage.state_path(False).exists())
        self.assertFalse(self.call("status", "--transient")[1]["configured"])
        self.assertEqual(self.call("configure", "--transient", "--policy", str(self.policy))[0], 0)
        self.assertTrue(self.call("status", "--transient")[1]["configured"])
        self.assertEqual(self.call("clear")[1]["action"], "remove")
        self.assertTrue(nordvpn_manage.state_path(False).exists())
        self.assertEqual(self.call("clear")[1]["action"], "unchanged")

    def test_reapply_is_idempotent_and_changed_policy_replaces(self):
        self.call("configure", "--policy", str(self.policy))
        self.assertEqual(self.call("plan", "--policy", str(self.policy))[1]["action"], "unchanged")
        changed = json.loads(self.policy.read_text())
        changed["vpn_profiles"]["main"]["selection"]["country"] = "IE"
        self.policy.write_text(json.dumps(changed))
        self.assertEqual(self.call("plan", "--policy", str(self.policy))[1]["action"], "replace")
        self.assertEqual(self.call("configure", "--policy", str(self.policy))[1]["action"], "replace")

    def test_invalid_policy_preserves_previous(self):
        self.call("configure", "--policy", str(self.policy))
        saved = nordvpn_manage.state_path(True).read_bytes()
        self.policy.write_text('{"version": 9}')
        self.assertEqual(self.call("configure", "--policy", str(self.policy))[0], 2)
        self.assertEqual(nordvpn_manage.state_path(True).read_bytes(), saved)

    def test_missing_runtime_directory_is_not_persistent_fallback(self):
        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": ""}):
            self.assertEqual(self.call("status", "--transient")[0], 2)

    def test_default_scope_does_not_require_runtime_directory(self):
        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": ""}):
            code, result = self.call("configure", "--policy", str(self.policy))
            self.assertEqual(code, 0)
            self.assertEqual(result["scope"], "persistent")
            self.assertTrue(nordvpn_manage.state_path(True).exists())

    def test_transient_scope_is_independent_of_persistent_configuration(self):
        self.call("configure", "--policy", str(self.policy))
        self.call("configure", "--transient", "--policy", str(self.policy))
        self.assertEqual(self.call("clear", "--transient")[1]["action"], "remove")
        self.assertTrue(self.call("status")[1]["configured"])
        self.assertFalse(self.call("status", "--transient")[1]["configured"])

    def test_legacy_persist_option_is_not_accepted(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            nord_tools.main(["manage", "status", "--persist"])
        self.assertEqual(raised.exception.code, 2)

    def test_symlinked_intent_file_is_rejected(self):
        path = nordvpn_manage.state_path(True)
        path.parent.mkdir(parents=True)
        path.symlink_to(self.policy)
        self.assertEqual(self.call("configure", "--policy", str(self.policy))[0], 2)
        self.assertEqual(json.loads(self.policy.read_text()), POLICY)


if __name__ == "__main__":
    unittest.main()


class ProductionManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "defaults": {"vpn": "main"},
                    "vpn_profiles": {"main": {"selection": {"mode": "country", "country": "GB"}}},
                    "applications": {"browser": {"executable": "/usr/bin/browser", "vpn": "main"}},
                }
            )
        )
        self.config = self.root / "startup.json"
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "policy": str(self.policy),
                    "journal": str(self.root / "journal.json"),
                    "bindings": str(self.root / "bindings.json"),
                    "intent": str(self.root / "intents.json"),
                    "run_record": str(self.root / "runs.json"),
                    "tunnels": {},
                }
            )
        )

    def invoke(self, *arguments):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = nordvpn_manage.main(list(arguments))
        return status, json.loads(output.getvalue()) if output.getvalue() else None, errors.getvalue()

    def test_provision_preview_does_not_invoke_executor(self):
        with patch.object(nordvpn_manage, "restore_boot_state", side_effect=AssertionError("unexpected execution")):
            status, result, _ = self.invoke("provision", "--config", str(self.config))
        self.assertEqual(status, 0)
        self.assertFalse(result["execute"])
        self.assertTrue(result["intent_only"])
        self.assertFalse((self.root / "journal.json").exists())

    def test_provision_execution_is_explicit(self):
        with patch.object(nordvpn_manage, "restore_boot_state", return_value={"restored": []}) as execute:
            status, result, _ = self.invoke("provision", "--config", str(self.config), "--execute")
        self.assertEqual(status, 0)
        self.assertEqual(result["scope"], "persistent")
        execute.assert_called_once()

    def test_transient_execution_refused(self):
        status, _, error = self.invoke("provision", "--transient", "--config", str(self.config), "--execute")
        self.assertEqual(status, 2)
        self.assertIn("persistent-only", error)

    def test_consumer_retirement_requires_real_reference_evidence(self):
        status, _, error = self.invoke(
            "retire-consumers",
            "--config",
            str(self.config),
            "--consumer",
            "browser",
            "--runtime-consumers",
            str(self.root / "missing.json"),
        )
        self.assertNotEqual(status, 0)
        self.assertFalse((self.root / "journal.json").exists())

    def test_duplicate_consumers_refused(self):
        status, _, error = self.invoke(
            "retire-consumers",
            "--config",
            str(self.config),
            "--consumer",
            "browser",
            "--consumer",
            "browser",
            "--runtime-consumers",
            str(self.root / "leases.json"),
        )
        self.assertEqual(status, 2)
        self.assertIn("repeated", error)

    def test_retirement_routes_selected_profile_and_release_evidence(self):
        with patch.object(nordvpn_manage, "plan_cleanup", return_value={"planned": []}) as cleanup:
            status, result, _ = self.invoke(
                "retire-consumers",
                "--config",
                str(self.config),
                "--consumer",
                "browser",
                "--runtime-consumers",
                str(self.root / "leases.json"),
            )
        self.assertEqual(status, 0)
        self.assertEqual(result["selected_profiles"], ["main"])
        self.assertEqual(cleanup.call_args.kwargs["released_consumers"], ("browser",))
        self.assertEqual(cleanup.call_args.kwargs["selected_profiles"], ("main",))
        self.assertFalse(cleanup.call_args.kwargs["execute"])

    def test_unknown_consumer_refused_before_kernel_access(self):
        with patch.object(nordvpn_manage, "plan_cleanup", side_effect=AssertionError("unexpected cleanup")):
            status, _, error = self.invoke(
                "retire-consumers",
                "--config",
                str(self.config),
                "--consumer",
                "unknown",
                "--runtime-consumers",
                str(self.root / "leases.json"),
            )
        self.assertEqual(status, 2)
        self.assertIn("not registered", error)


class ConsumerLeaseManagementTests(ProductionManagementTests):
    def test_missing_lease_store_fails_closed(self):
        for command in ("consumer-leases", "release-exited-consumer"):
            arguments = [command, "--config", str(self.config), "--runtime-consumers", str(self.root / "missing.json")]
            if command == "release-exited-consumer":
                arguments.extend(("--consumer", "browser", "--execute"))
            with self.subTest(command=command):
                status, _, _ = self.invoke(*arguments)
                self.assertEqual(status, 2)

    def test_read_only_lease_inspection_and_release_preview(self):
        from nord_tools_internal.nordvpn_runtime_consumers import initialise_runtime_consumers

        policy = json.loads(self.policy.read_text())
        store = self.root / "leases.json"
        initialise_runtime_consumers(store, policy)
        status, result, _ = self.invoke(
            "consumer-leases", "--config", str(self.config), "--runtime-consumers", str(store)
        )
        self.assertEqual(status, 0)
        self.assertEqual(result["leases"], [])
        self.assertFalse(result["execute"])
        status, _, _ = self.invoke(
            "release-exited-consumer",
            "--config",
            str(self.config),
            "--runtime-consumers",
            str(store),
            "--consumer",
            "browser",
        )
        self.assertEqual(status, 2)

    def test_transient_lease_management_refused(self):
        status, _, error = self.invoke(
            "consumer-leases",
            "--transient",
            "--config",
            str(self.config),
            "--runtime-consumers",
            str(self.root / "leases.json"),
        )
        self.assertEqual(status, 2)
        self.assertIn("persistent-only", error)


class ConsumerAcquisitionManagementTests(ProductionManagementTests):
    def test_acquisition_preview_does_not_inspect_or_mutate(self):
        with patch.object(nordvpn_manage, "discover", side_effect=AssertionError("unexpected discovery")):
            status, result, _ = self.invoke(
                "acquire-consumer",
                "--config",
                str(self.config),
                "--runtime-consumers",
                str(self.root / "leases.json"),
                "--consumer",
                "browser",
                "--pid",
                "1234",
            )
        self.assertEqual(status, 0)
        self.assertTrue(result["intent_only"])
        self.assertFalse((self.root / "leases.json").exists())

    def test_acquisition_delegates_verified_authority(self):
        from nord_tools_internal import nordvpn_runtime_consumers

        with patch.object(
            nordvpn_runtime_consumers,
            "acquire_provisioned_consumer",
            return_value={"leases": [{"application": "browser"}]},
        ) as acquire:
            status, result, _ = self.invoke(
                "acquire-consumer",
                "--config",
                str(self.config),
                "--runtime-consumers",
                str(self.root / "leases.json"),
                "--consumer",
                "browser",
                "--pid",
                "1234",
                "--execute",
            )
        self.assertEqual(status, 0)
        self.assertEqual(result["lease_count"], 1)
        self.assertEqual(acquire.call_args.kwargs["journal_path"], str(self.root / "journal.json"))
        self.assertIs(acquire.call_args.kwargs["observe"], nordvpn_manage.discover)

    def test_unknown_consumer_and_invalid_pid_fail_before_discovery(self):
        with patch.object(nordvpn_manage, "discover", side_effect=AssertionError("unexpected discovery")):
            for consumer, pid in (("unknown", "123"), ("browser", "0")):
                with self.subTest(consumer=consumer, pid=pid):
                    status, _, _ = self.invoke(
                        "acquire-consumer",
                        "--config",
                        str(self.config),
                        "--runtime-consumers",
                        str(self.root / "leases.json"),
                        "--consumer",
                        consumer,
                        "--pid",
                        pid,
                        "--execute",
                    )
                    self.assertEqual(status, 2)

    def test_transient_acquisition_refused(self):
        status, _, error = self.invoke(
            "acquire-consumer",
            "--transient",
            "--config",
            str(self.config),
            "--runtime-consumers",
            str(self.root / "leases.json"),
            "--consumer",
            "browser",
            "--pid",
            "1234",
            "--execute",
        )
        self.assertEqual(status, 2)
        self.assertIn("persistent-only", error)
