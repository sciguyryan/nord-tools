"""Offline regression checks for the disposable host-integrity probe."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from tools import probe_wireguard_host_integrity as integrity


class HostIntegrityProbeTests(unittest.TestCase):
    def test_nft_counter_values_are_volatile_but_counter_statement_remains(self):
        import json

        original = {
            "nftables": [
                {
                    "rule": {
                        "family": "ip",
                        "table": "filter",
                        "chain": "INPUT",
                        "handle": 4,
                        "expr": [{"counter": {"packets": 1, "bytes": 30}}, {"accept": None}],
                    }
                }
            ]
        }
        updated = json.loads(json.dumps(original))
        updated["nftables"][0]["rule"]["expr"][0]["counter"] = {"packets": 999, "bytes": 45000}
        fingerprint = integrity._nft_configuration_fingerprint
        self.assertEqual(fingerprint(json.dumps(original)), fingerprint(json.dumps(updated)))
        updated["nftables"][0]["rule"]["expr"].pop(0)
        self.assertNotEqual(fingerprint(json.dumps(original)), fingerprint(json.dumps(updated)))

    def test_nft_security_relevant_mutations_fail(self):
        import copy
        import json

        original = {
            "nftables": [
                {
                    "chain": {
                        "family": "ip",
                        "table": "filter",
                        "name": "INPUT",
                        "hook": "input",
                        "prio": 0,
                        "policy": "drop",
                    }
                },
                {"rule": {"expr": [{"counter": {"packets": 1, "bytes": 2}}, {"drop": None}], "handle": 7}},
            ]
        }
        fingerprint = integrity._nft_configuration_fingerprint
        baseline = fingerprint(json.dumps(original))
        for mutate in ("policy", "verdict", "handle", "extra-rule", "counter-extra"):
            changed = copy.deepcopy(original)
            if mutate == "policy":
                changed["nftables"][0]["chain"]["policy"] = "accept"
            elif mutate == "verdict":
                changed["nftables"][1]["rule"]["expr"][1] = {"accept": None}
            elif mutate == "handle":
                changed["nftables"][1]["rule"]["handle"] = 8
            elif mutate == "extra-rule":
                changed["nftables"].append({"rule": {"expr": [{"accept": None}]}})
            else:
                changed["nftables"][1]["rule"]["expr"][0]["counter"]["name"] = "other"
            with self.subTest(mutate=mutate):
                self.assertNotEqual(baseline, fingerprint(json.dumps(changed)))

    def test_malformed_nft_readback_fails_closed(self):
        for output in ("not json", "{}", "[]", '{"nftables": {}}'):
            with self.subTest(output=output), self.assertRaises(integrity.IntegrityError):
                integrity._nft_configuration_fingerprint(output)

    def test_route_expiry_value_is_volatile_but_field_and_route_remain(self):
        import json

        original = [{"dst": "default", "gateway": "fe80::1", "dev": "eth0", "expires": 65000}]
        fingerprint = integrity._route_configuration_fingerprint
        self.assertEqual(
            fingerprint(json.dumps(original)), fingerprint(json.dumps([{**original[0], "expires": 64999}]))
        )
        self.assertNotEqual(
            fingerprint(json.dumps(original)),
            fingerprint(json.dumps([{key: value for key, value in original[0].items() if key != "expires"}])),
        )
        self.assertNotEqual(
            fingerprint(json.dumps(original)), fingerprint(json.dumps([{**original[0], "gateway": "fe80::2"}]))
        )

    def test_malformed_route_readback_fails_closed(self):
        for output in ("not json", "{}", '["not-a-route"]'):
            with self.subTest(output=output), self.assertRaises(integrity.IntegrityError):
                integrity._route_configuration_fingerprint(output)

    def test_dry_run_never_executes(self):
        with patch.object(integrity, "experiment") as experiment, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(integrity.main([]), 0)
        experiment.assert_not_called()
        self.assertIn("DRY RUN", output.getvalue())

    def test_matching_observations_pass(self):
        with redirect_stdout(io.StringIO()) as output:
            integrity.verify({"routes": "a"}, {"routes": "a"})
        self.assertIn("PASS", output.getvalue())

    def test_changed_host_state_fails(self):
        with self.assertRaisesRegex(integrity.IntegrityError, "routes"):
            integrity.verify({"routes": "a"}, {"routes": "b"})

    def test_missing_observation_fails(self):
        with self.assertRaisesRegex(integrity.IntegrityError, "set changed"):
            integrity.verify({"routes": "a"}, {})

    def test_experiment_failure_still_observes_afterwards(self):
        with (
            patch.object(integrity, "observe", side_effect=[{"routes": "a"}, {"routes": "a"}]) as observation,
            patch.object(integrity, "experiment", side_effect=integrity.HarnessError("injected")),
            redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(integrity.IntegrityError, "injected"),
        ):
            integrity.probe("abcdef")
        self.assertEqual(observation.call_count, 2)

    def test_experiment_and_observations_pass(self):
        with (
            patch.object(integrity, "observe", side_effect=[{"routes": "a"}, {"routes": "a"}]),
            patch.object(integrity, "experiment") as experiment,
            redirect_stdout(io.StringIO()),
        ):
            integrity.probe("abcdef")
        experiment.assert_called_once_with("abcdef")


if __name__ == "__main__":
    unittest.main()
