"""Dispatch behaviour for the unified Nord Tools entry point."""

import contextlib
import io
import unittest
from unittest.mock import patch

import nord_tools


class EntryPointTests(unittest.TestCase):
    def test_version(self):
        output = io.StringIO()
        with (
            patch.object(nord_tools.sys, "argv", ["nord_tools.py"]),
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as raised,
        ):
            nord_tools.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue(), "nord_tools.py 0.9.0\n")

    def test_help_without_subcommand(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(nord_tools.main([]), 0)
        rendered = output.getvalue()
        self.assertIn("doctor", rendered)
        self.assertIn("manage", rendered)
        self.assertIn("explicitly authorised VPN lifecycle operations", rendered)

    def test_unknown_command_is_rejected(self):
        with self.assertRaises(SystemExit) as error:
            nord_tools.main(["unknown"])
        self.assertEqual(error.exception.code, 2)

    def test_dispatch_preserves_arguments_and_return_code(self):
        with patch.object(nord_tools.importlib, "import_module") as imported:
            imported.return_value.main.return_value = 7
            self.assertEqual(nord_tools.main(["benchmark", "--dry-run", "--limit", "3"]), 7)
            imported.assert_called_once_with("nordvpn_benchmark")
            imported.return_value.main.assert_called_once_with(["--dry-run", "--limit", "3"])

    def test_each_command_dispatches_to_its_existing_module(self):
        for name, (module, _) in nord_tools.COMMANDS.items():
            with self.subTest(name=name), patch.object(nord_tools.importlib, "import_module") as imported:
                imported.return_value.main.return_value = 0
                self.assertEqual(nord_tools.main([name, "--help"]), 0)
                imported.assert_called_once_with(module)
                imported.return_value.main.assert_called_once_with(["--help"])


if __name__ == "__main__":
    unittest.main()
