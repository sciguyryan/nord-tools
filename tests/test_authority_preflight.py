"""Adversarial checks for the read-only privileged state boundary."""

import os
from pathlib import Path
import tempfile
import unittest

from nord_tools_internal.nordvpn_authority_preflight import (
    AuthorityPreflightError,
    inspect_authority_directory,
)


class AuthorityPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        os.chmod(self.path, 0o700)
        self.uid = os.getuid()

    def inspect(self):
        # /tmp is intentionally writable: even a private state directory under
        # it must not be mistaken for a trustworthy production authority root.
        return inspect_authority_directory(self.path, trusted_uid=self.uid)

    def test_world_writable_ancestor_is_not_trusted(self):
        report = self.inspect()
        self.assertFalse(report["trusted"])
        self.assertFalse(report["safe_to_execute"])
        self.assertTrue(any("writable component" in item for item in report["findings"]))

    def test_symlinked_directory_is_refused(self):
        alias = self.path.parent / (self.path.name + "-alias")
        alias.symlink_to(self.path, target_is_directory=True)
        self.addCleanup(alias.unlink)
        report = inspect_authority_directory(alias, trusted_uid=self.uid)
        self.assertFalse(report["trusted"])
        self.assertTrue(any("symlink" in item for item in report["findings"]))

    def test_missing_directory_is_refused(self):
        report = inspect_authority_directory(self.path / "missing", trusted_uid=self.uid)
        self.assertFalse(report["trusted"])
        self.assertTrue(any("missing component" in item for item in report["findings"]))

    def test_invalid_trusted_uid_is_rejected(self):
        for uid in (-1, True, "0"):
            with self.subTest(uid=uid), self.assertRaises(AuthorityPreflightError):
                inspect_authority_directory(self.path, trusted_uid=uid)

    def test_report_is_read_only(self):
        before = sorted(p.name for p in self.path.iterdir())
        self.inspect()
        self.assertEqual(before, sorted(p.name for p in self.path.iterdir()))

    def test_unsafe_regular_state_file_is_rejected(self):
        entry = self.path / "state.json"
        entry.write_text("{}")
        os.chmod(entry, 0o644)
        report = self.inspect()
        self.assertTrue(any("unsafe state entry" in item for item in report["findings"]))

    def test_symlinked_state_entry_is_rejected(self):
        (self.path / "state.json").symlink_to("/etc/passwd")
        report = self.inspect()
        self.assertTrue(any("unsafe state entry" in item for item in report["findings"]))

    def test_hardlinked_state_entry_is_rejected(self):
        entry = self.path / "state.json"
        entry.write_text("{}")
        os.chmod(entry, 0o600)
        os.link(entry, self.path / "alias.json")
        report = self.inspect()
        self.assertTrue(any("unsafe state entry" in item for item in report["findings"]))

    def test_nested_symlink_is_rejected_without_following_it(self):
        child = self.path / "child"
        child.symlink_to("/etc", target_is_directory=True)
        report = inspect_authority_directory(child, trusted_uid=self.uid)
        self.assertFalse(report["trusted"])
        self.assertTrue(any("symlink component" in item for item in report["findings"]))
