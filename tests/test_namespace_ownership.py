"""Deterministic safety tests for process-bound namespace ownership."""

import unittest
from unittest.mock import patch

from nordvpn_namespace_ownership import OwnedNamespace, OwnershipError, disposable_namespace


class NamespaceOwnershipTests(unittest.TestCase):
    def test_reject_unsafe_names_without_commands(self):
        for name in ("default", "nt-", "nt-../../foo", "nt-ABCDEF12", "nt-abcdefgh;rm"):
            with self.subTest(name=name), patch("nordvpn_namespace_ownership._command") as command:
                with self.assertRaises(OwnershipError), disposable_namespace(name):
                    pass
                command.assert_not_called()

    def test_reject_preexisting_namespace(self):
        with (
            patch("nordvpn_namespace_ownership._namespace_names", return_value={"nt-abcdefgh"}),
            patch("nordvpn_namespace_ownership._command") as command,
        ):
            with self.assertRaises(OwnershipError), disposable_namespace("nt-abcdefgh"):
                pass
            command.assert_not_called()

    def test_closed_descriptor_refuses_verification(self):
        owned = OwnedNamespace("nt-abcdefgh", 42, 1, 2, closed=True)
        with self.assertRaises(OwnershipError):
            owned.verify()

    def test_identity_reuse_refuses_retirement(self):
        owned = OwnedNamespace("nt-abcdefgh", 42, 1, 2)
        with (
            patch("nordvpn_namespace_ownership.os.fstat", return_value=type("S", (), {"st_dev": 1, "st_ino": 2})()),
            patch(
                "nordvpn_namespace_ownership.os.stat",
                return_value=type("S", (), {"st_dev": 1, "st_ino": 3, "st_mode": 0o100600})(),
            ),
            patch("nordvpn_namespace_ownership._command") as command,
        ):
            with self.assertRaises(OwnershipError):
                owned.retire()
            command.assert_not_called()

    def test_processes_block_retirement(self):
        owned = OwnedNamespace("nt-abcdefgh", 42, 1, 2)
        with (
            patch.object(owned, "verify"),
            patch("nordvpn_namespace_ownership._command", return_value="1234\n") as command,
        ):
            with self.assertRaises(OwnershipError):
                owned.retire()
            command.assert_called_once_with("pids", "nt-abcdefgh")

    def test_successful_retirement(self):
        owned = OwnedNamespace("nt-abcdefgh", 42, 1, 2)
        with (
            patch.object(owned, "verify") as verify,
            patch("nordvpn_namespace_ownership._command", side_effect=["", ""]) as command,
            patch("nordvpn_namespace_ownership.os.close") as close,
        ):
            owned.retire()
            self.assertTrue(owned.closed)
            self.assertEqual(verify.call_count, 2)
            self.assertEqual(command.call_args_list[1].args, ("del", "nt-abcdefgh"))
            close.assert_called_once_with(42)


if __name__ == "__main__":
    unittest.main()
