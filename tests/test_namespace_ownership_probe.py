"""Offline safety checks for the opt-in privileged ownership probe."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_namespace_ownership import OwnershipError

_SPEC = importlib.util.spec_from_file_location(
    "probe_namespace_ownership", Path(__file__).resolve().parents[1] / "tools" / "probe_namespace_ownership.py"
)
probe_module = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(probe_module)


class OwnershipProbeTests(unittest.TestCase):
    def test_default_does_not_create_resources(self):
        with patch.object(probe_module, "disposable_namespace") as create:
            self.assertEqual(probe_module.main([]), 1)
            create.assert_not_called()

    def test_unprivileged_execution_refused(self):
        with (
            patch.object(probe_module.os, "geteuid", return_value=1000),
            patch.object(probe_module, "disposable_namespace") as create,
        ):
            with self.assertRaises(OwnershipError):
                probe_module.probe(confirmed=True)
            create.assert_not_called()

    def test_missing_ip_refused(self):
        with (
            patch.object(probe_module.os, "geteuid", return_value=0),
            patch.object(probe_module.shutil, "which", return_value=None),
            patch.object(probe_module, "disposable_namespace") as create,
        ):
            with self.assertRaises(OwnershipError):
                probe_module.probe(confirmed=True)
            create.assert_not_called()

    def test_success_verifies_and_retires_via_context(self):
        from contextlib import contextmanager

        calls = []

        @contextmanager
        def fake_namespace(name):
            calls.append(("enter", name))

            class Held:
                def verify(self):
                    calls.append(("verify", name))

            yield Held()
            calls.append(("exit", name))

        with (
            patch.object(probe_module.os, "geteuid", return_value=0),
            patch.object(probe_module.shutil, "which", return_value="/usr/bin/ip"),
            patch.object(probe_module, "disposable_namespace", fake_namespace),
        ):
            name = probe_module.probe(confirmed=True)
        self.assertRegex(name, r"^nt-[0-9a-f]{16}$")
        self.assertEqual([c[0] for c in calls], ["enter", "verify", "exit"])

    def test_identity_failure_propagates_without_fallback_delete(self):
        from contextlib import contextmanager

        @contextmanager
        def fail_namespace(name):
            raise OwnershipError("identity changed")
            yield

        with (
            patch.object(probe_module.os, "geteuid", return_value=0),
            patch.object(probe_module.shutil, "which", return_value="/usr/bin/ip"),
            patch.object(probe_module, "disposable_namespace", fail_namespace),
        ):
            self.assertEqual(probe_module.main(["--run-privileged"]), 1)


if __name__ == "__main__":
    unittest.main()
