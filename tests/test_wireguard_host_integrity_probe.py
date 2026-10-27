"""Offline regression checks for the disposable host-integrity probe."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from tools import probe_wireguard_host_integrity as integrity


class HostIntegrityProbeTests(unittest.TestCase):
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


class NftStructuralEvidenceTests(unittest.TestCase):
    def test_volatile_counters_and_handles_do_not_change_policy(self):
        before = '{"nftables":[{"table":{"family":"ip","name":"filter","handle":1}},{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":4,"expr":[{"counter":{"packets":10,"bytes":100}},{"accept":null}]}}]}'
        after = '{"nftables":[{"table":{"family":"ip","name":"filter","handle":55}},{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":99,"expr":[{"counter":{"packets":20,"bytes":200}},{"accept":null}]}}]}'
        self.assertEqual(integrity.nft_policy(before), integrity.nft_policy(after))

    def test_policy_changes_are_detected(self):
        original = '{"nftables":[{"chain":{"name":"INPUT","policy":"drop"}},{"rule":{"expr":[{"counter":{"packets":1,"bytes":2}},{"accept":null}]}}]}'
        for changed in (
            original.replace('"drop"', '"accept"'),
            original.replace('"accept":null', '"drop":null'),
            original.replace('},{"rule"', '},{"set":{"name":"allow"}},{"rule"'),
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(integrity.IntegrityError, "nftables"),
            ):
                integrity.verify(
                    {"host nftables ruleset": integrity.nft_policy(original)},
                    {"host nftables ruleset": integrity.nft_policy(changed)},
                )

    def test_rule_order_is_preserved(self):
        first = '{"nftables":[{"rule":{"expr":[{"accept":null}]}},{"rule":{"expr":[{"drop":null}]}}]}'
        second = '{"nftables":[{"rule":{"expr":[{"drop":null}]}},{"rule":{"expr":[{"accept":null}]}}]}'
        self.assertNotEqual(integrity.nft_policy(first), integrity.nft_policy(second))

    def test_invalid_json_fails_closed(self):
        for invalid in ("not-json", "{}", "[]"):
            with self.subTest(invalid=invalid), self.assertRaises(integrity.IntegrityError):
                integrity.nft_policy(invalid)
