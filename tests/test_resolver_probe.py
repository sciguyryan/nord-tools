"""Disposable resolver visibility probe contract tests."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import probe_namespace_resolver as probe


class ResolverProbeTests(unittest.TestCase):
    def test_dry_run_does_not_require_privilege(self):
        self.assertEqual(probe.main([]), 0)

    def test_host_digest_tracks_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "resolv.conf"
            path.write_bytes(b"first")
            first = probe.digest(path)
            path.write_bytes(b"second")
            self.assertNotEqual(first, probe.digest(path))

    def test_namespace_visibility_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "netns"
            root.mkdir(mode=0o700)
            host = Path(temp) / "host-resolv.conf"
            host.write_text("nameserver 192.0.2.1\n")
            seen = []

            def fake_run(argv, *, check=True):
                seen.append(argv)
                if argv[:3] == ["ip", "netns", "exec"]:
                    from nord_tools_internal.nordvpn_resolver_policy import NamespaceResolverPolicy

                    value = NamespaceResolverPolicy(("1.1.1.1", "2606:4700:4700::1111")).render_resolv_conf()
                else:
                    value = ""
                from subprocess import CompletedProcess

                return CompletedProcess(argv, 0, value, "")

            with patch.object(probe, "run", side_effect=fake_run):
                probe.probe("vpnres-test", root=root, host_resolver=host)
            self.assertFalse((root / "vpnres-test").exists())
            self.assertEqual(seen[-1], ["ip", "netns", "del", "vpnres-test"])
            self.assertEqual(host.read_text(), "nameserver 192.0.2.1\n")

    def test_mismatched_namespace_view_fails_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "netns"
            root.mkdir(mode=0o700)
            host = Path(temp) / "host-resolv.conf"
            host.write_text("host")
            from subprocess import CompletedProcess

            with (
                patch.object(probe, "run", side_effect=lambda argv, **kwargs: CompletedProcess(argv, 0, "wrong", "")),
                self.assertRaises(probe.ProbeError),
            ):
                probe.probe("vpnres-test", root=root, host_resolver=host)
            self.assertFalse((root / "vpnres-test").exists())


if __name__ == "__main__":
    unittest.main()
