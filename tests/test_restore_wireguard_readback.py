"""Regression tests for byte-oriented wg command output in privileged readback."""

import subprocess
import unittest
from unittest.mock import patch

from nord_tools_internal.nordvpn_restore_executor import _real_kernel


class WireGuardReadbackTests(unittest.TestCase):
    def test_peer_readback_accepts_exact_binary_command_output(self):
        kernel = _real_kernel()
        with patch(
            "nord_tools_internal.nordvpn_restore_executor.subprocess.run",
            side_effect=[
                subprocess.CompletedProcess([], 0, b"local-public-key\n", b""),
                subprocess.CompletedProcess([], 0, b"remote-public-key\n", b""),
            ],
        ):
            self.assertTrue(kernel.verify_wireguard("ns", "wg0", "local-public-key", "remote-public-key"))

    def test_peer_readback_rejects_wrong_peer(self):
        kernel = _real_kernel()
        with patch(
            "nord_tools_internal.nordvpn_restore_executor.subprocess.run",
            side_effect=[
                subprocess.CompletedProcess([], 0, b"local-public-key\n", b""),
                subprocess.CompletedProcess([], 0, b"unexpected-peer\n", b""),
            ],
        ):
            self.assertFalse(kernel.verify_wireguard("ns", "wg0", "local-public-key", "remote-public-key"))
