"""Default optimisation must be an offline, narrowly scoped decision."""

import copy
import unittest

from nordvpn_policy import PolicyError, plan_default


POLICY = {
    "version": 1,
    "defaults": {"vpn": "primary"},
    "vpn_profiles": {
        "primary": {
            "selection": {
                "mode": "fastest",
                "filter": "country:ad&protocol:udp",
                "minimum_improvement_ms": 10,
                "minimum_improvement_percent": 15,
            }
        },
        "discord": {"selection": {"mode": "pinned", "server": "gb123.nordvpn.com"}},
    },
    "applications": {"discord": {"executable": "/usr/bin/discord", "vpn": "discord"}},
}


def record(server, latency, *, protocol="udp", received=3, loss=0):
    return {
        "server": server,
        "protocol": protocol,
        "port": 1194,
        "received": received,
        "median_ms": latency,
        "loss_pct": loss,
    }


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "schema_version": 1,
            "ranking": [record("ad1.nordvpn.com", 20), record("ad2.nordvpn.com", 40), record("gb1.nordvpn.com", 1)],
        }

    def test_switch_only_default(self):
        original = copy.deepcopy(POLICY)
        result = plan_default(POLICY, self.report, current_server="ad2")
        self.assertEqual(result["decision"], "switch_candidate")
        self.assertEqual(result["candidate"], "ad1.nordvpn.com")
        self.assertFalse(result["executed"])
        self.assertEqual(POLICY, original)

    def test_thresholds_prevent_churn(self):
        report = {"schema_version": 1, "ranking": [record("ad1.nordvpn.com", 38), record("ad2.nordvpn.com", 40)]}
        self.assertEqual(plan_default(POLICY, report, current_server="ad2")["decision"], "keep_current")

    def test_unknown_current_not_automatically_switched(self):
        self.assertEqual(plan_default(POLICY, self.report, current_server="ad9")["decision"], "current_not_measured")

    def test_no_responsive_candidate(self):
        report = {"schema_version": 1, "ranking": [record("ad1.nordvpn.com", None, received=0)]}
        self.assertEqual(plan_default(POLICY, report)["decision"], "no_eligible_server")

    def test_rejects_invalid_policy_and_report(self):
        for policy, report in [
            ({**POLICY, "defaults": {"vpn": "missing"}}, self.report),
            (POLICY, {"schema_version": 2, "ranking": []}),
            (POLICY, {"schema_version": 1, "ranking": [record("evil.invalid", 1)]}),
        ]:
            with self.subTest(policy=policy, report=report), self.assertRaises(PolicyError):
                plan_default(policy, report)


if __name__ == "__main__":
    unittest.main()
