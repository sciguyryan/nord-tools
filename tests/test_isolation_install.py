"""Offline tests of the experimental namespace firewall installation boundary."""

import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from nord_tools_internal.nordvpn_failclosed_policy import NamespaceIsolationPolicy
from nord_tools_internal.nordvpn_isolation_install import IsolationInstallError, install_disposable_isolation
from nord_tools_internal.nordvpn_namespace_ownership import OwnedNamespace, OwnershipError


class IsolationInstallTests(unittest.TestCase):
    @staticmethod
    def readback(*, output_policy="drop"):
        return json.dumps(
            {
                "nftables": [
                    {
                        "chain": {
                            "family": "inet",
                            "table": "nord_tools_isolation",
                            "name": name,
                            "hook": name,
                            "type": "filter",
                            "policy": output_policy if name == "output" else "drop",
                        }
                    }
                    for name in ("input", "output", "forward")
                ]
            }
        )

    def setUp(self):
        self.owned = OwnedNamespace("nt-12345678", 3, 1, 2)
        self.policy = NamespaceIsolationPolicy("ntwg0", "veth0", "198.51.100.20", 51820)

    @patch.object(OwnedNamespace, "verify")
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_check_before_apply_with_same_rules(self, run, verify):
        run.side_effect = [Mock(returncode=0), Mock(returncode=0), Mock(returncode=0, stdout=self.readback())]
        result = install_disposable_isolation(self.owned, self.policy)
        self.assertEqual(run.call_count, 3)
        first, second = (call.args[0] for call in run.call_args_list[:2])
        self.assertEqual(first, ["ip", "netns", "exec", "nt-12345678", "nft", "-c", "-f", "-"])
        self.assertEqual(second, ["ip", "netns", "exec", "nt-12345678", "nft", "-f", "-"])
        self.assertEqual(run.call_args_list[0].kwargs["input"], run.call_args_list[1].kwargs["input"])
        self.assertEqual(verify.call_count, 4)
        self.assertTrue(result.base_chains_verified)
        self.assertTrue(result.policy_applied)
        self.assertFalse(result.dns_confined)
        self.assertFalse(result.tunnel_loss_verified)

    @patch.object(OwnedNamespace, "verify")
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_check_failure_prevents_apply(self, run, verify):
        run.return_value = Mock(returncode=1)
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, self.policy)
        self.assertEqual(run.call_count, 1)

    @patch.object(OwnedNamespace, "verify")
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_apply_failure_not_reported_as_success(self, run, verify):
        run.side_effect = [Mock(returncode=0), Mock(returncode=1)]
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, self.policy)

    @patch.object(OwnedNamespace, "verify")
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_readback_failure_blocks_success(self, run, verify):
        run.side_effect = [Mock(returncode=0), Mock(returncode=0), Mock(returncode=1)]
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, self.policy)
        self.assertEqual(run.call_count, 3)

    @patch.object(OwnedNamespace, "verify")
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_readback_rejects_accept_output_chain(self, run, verify):
        run.side_effect = [
            Mock(returncode=0),
            Mock(returncode=0),
            Mock(returncode=0, stdout=self.readback(output_policy="accept")),
        ]
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, self.policy)

    @patch.object(OwnedNamespace, "verify")
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_readback_rejects_malformed_json(self, run, verify):
        run.side_effect = [Mock(returncode=0), Mock(returncode=0), Mock(returncode=0, stdout="not json")]
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, self.policy)

    @patch.object(OwnedNamespace, "verify")
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_timeout_is_uncertain(self, run, verify):
        run.side_effect = subprocess.TimeoutExpired("nft", 15)
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, self.policy)

    @patch.object(OwnedNamespace, "verify", side_effect=OwnershipError("changed"))
    @patch("nord_tools_internal.nordvpn_isolation_install.subprocess.run")
    def test_ownership_failure_prevents_commands(self, run, verify):
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, self.policy)
        run.assert_not_called()

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation("nt-12345678", self.policy)
        with self.assertRaises(IsolationInstallError):
            install_disposable_isolation(self.owned, "ruleset")


if __name__ == "__main__":
    unittest.main()
