"""Tests for exclusive, namespace-specific resolver file installation."""

from pathlib import Path
import tempfile
import unittest

from nord_tools_internal.nordvpn_resolver_install import (
    ResolverInstallError,
    install_namespace_resolver,
    remove_namespace_resolver,
)
from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy


class ResolverInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "netns"
        self.root.mkdir(mode=0o700)
        self.policy = NamespaceResolverPolicy(("1.1.1.1", "2606:4700:4700::1111"))

    def test_install_and_remove(self):
        installed = install_namespace_resolver("vpnprobe-test", self.policy, root=self.root)
        self.assertEqual((installed.directory / "resolv.conf").read_text(), self.policy.render_resolv_conf())
        remove_namespace_resolver(installed)
        self.assertFalse(installed.directory.exists())

    def test_existing_directory_is_never_overwritten(self):
        directory = self.root / "existing"
        directory.mkdir()
        (directory / "resolv.conf").write_text("original")
        with self.assertRaises(ResolverInstallError):
            install_namespace_resolver("existing", self.policy, root=self.root)
        self.assertEqual((directory / "resolv.conf").read_text(), "original")

    def test_reject_invalid_namespace(self):
        for name in ("../host", "a/b", "", ".", "..", "x" * 64):
            with self.subTest(name=name), self.assertRaises(ResolverInstallError):
                install_namespace_resolver(name, self.policy, root=self.root)

    def test_reject_symlink_root(self):
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ResolverInstallError):
            install_namespace_resolver("test", self.policy, root=alias)

    def test_refuse_unexpected_cleanup_state(self):
        installed = install_namespace_resolver("test", self.policy, root=self.root)
        (installed.directory / "other").write_text("preserve")
        with self.assertRaises(ResolverInstallError):
            remove_namespace_resolver(installed)
        self.assertTrue((installed.directory / "resolv.conf").exists())
