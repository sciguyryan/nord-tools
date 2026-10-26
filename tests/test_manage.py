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
