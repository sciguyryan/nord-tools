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


class CompletePeerReadbackTests(unittest.TestCase):
    def setUp(self):
        from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification
        import base64

        self.spec = TunnelSpecification(
            "nt-0123456789",
            "ntwg1234",
            base64.b64encode(bytes(range(32))).decode(),
            "198.51.100.2",
            51820,
            "10.42.0.2/32",
            ("10.42.0.1/32",),
            25,
        )

    def results(self, *, endpoint=b"198.51.100.2:51820", allowed=b"10.42.0.1/32", keepalive=b"25"):
        peer = self.spec.peer_public_key.encode("ascii")
        return [
            subprocess.CompletedProcess([], 0, b"local\n", b""),
            subprocess.CompletedProcess([], 0, peer + b"\n", b""),
            subprocess.CompletedProcess([], 0, peer + b"\t" + endpoint + b"\n", b""),
            subprocess.CompletedProcess([], 0, peer + b"\t" + allowed + b"\n", b""),
            subprocess.CompletedProcess([], 0, peer + b"\t" + keepalive + b"\n", b""),
        ]

    def verify(self, results):
        with patch("nord_tools_internal.nordvpn_restore_executor.subprocess.run", side_effect=results) as run:
            verified = _real_kernel().verify_wireguard(
                self.spec.namespace, self.spec.interface, "local", self.spec.peer_public_key, self.spec
            )
            self.assertTrue(all("dump" not in call.args[0] for call in run.call_args_list))
            return verified

    def test_exact_non_secret_readback_is_accepted(self):
        self.assertTrue(self.verify(self.results()))

    def test_endpoint_mismatch_is_refused(self):
        self.assertFalse(self.verify(self.results(endpoint=b"198.51.100.3:51820")))

    def test_allowed_ips_mismatch_is_refused(self):
        self.assertFalse(self.verify(self.results(allowed=b"0.0.0.0/0")))

    def test_multiple_allowed_ips_use_script_friendly_space_separation(self):
        from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification

        self.spec = TunnelSpecification(
            self.spec.namespace,
            self.spec.interface,
            self.spec.peer_public_key,
            self.spec.endpoint_address,
            self.spec.endpoint_port,
            self.spec.tunnel_address,
            ("0.0.0.0/0", "::/0"),
            self.spec.persistent_keepalive_seconds,
        )
        self.assertTrue(self.verify(self.results(allowed=b"0.0.0.0/0 ::/0")))

    def test_keepalive_mismatch_is_refused(self):
        self.assertFalse(self.verify(self.results(keepalive=b"off")))

    def test_failed_readback_is_refused(self):
        results = self.results()
        results[2] = subprocess.CompletedProcess([], 1, b"", b"private material")
        self.assertFalse(self.verify(results))
