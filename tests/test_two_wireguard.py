"""Offline safety and CLI tests for the disposable WireGuard harness."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from tools import probe_two_wireguard as harness


class TwoWireguardTests(unittest.TestCase):
    def test_names_fit_linux_limits_and_are_unique(self):
        names = [name for group in harness.identifiers("abcdef") for name in group]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(len(name.encode("ascii")) <= 15 for name in names))

    def test_invalid_token_rejected(self):
        for token in ("abc", "ZZZZZZ", "abcdefg"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                harness.identifiers(token)

    def test_default_is_dry_run_without_network_calls(self):
        with patch.object(harness, "run") as command, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(harness.main([]), 0)
        command.assert_not_called()
        self.assertIn("DRY RUN", output.getvalue())

    def test_cleanup_on_failed_first_pair(self):
        calls = []

        def fake_run(*args, **kwargs):
            calls.append(args)
            if args[:3] == ("ip", "link", "add"):
                raise harness.HarnessError("injected failure")

            class Result:
                returncode = 0
                stderr = ""

            return Result()

        with (
            patch.object(harness, "run", side_effect=fake_run),
            self.assertRaisesRegex(harness.HarnessError, "injected failure"),
        ):
            harness.experiment("abcdef")
        self.assertIn(("ip", "netns", "del", "ntabcdefc1"), calls)
        self.assertIn(("ip", "netns", "del", "ntabcdefs1"), calls)
        self.assertFalse(any(call[:3] == ("ip", "link", "del") for call in calls))

    def test_preflight_rejects_missing_tools(self):
        with (
            patch.object(harness.sys, "platform", "linux"),
            patch.object(harness.shutil, "which", return_value=None),
            self.assertRaises(SystemExit),
        ):
            harness.main(["--execute"])


if __name__ == "__main__":
    unittest.main()
