"""Adversarial offline recovery checkpoint contract tests."""

import unittest

from nord_tools_internal.nordvpn_recovery_coordinator import RecoveryContractError, assess_checkpoint
from nord_tools_internal.nordvpn_transaction_plan import STAGES


class RecoveryCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.operation = {"profile": "primary", "action": "replace"}

    def checkpoint(self, completed=None, outcome="interrupted", **overrides):
        record = {
            "version": 1,
            "profile": "primary",
            "action": "replace",
            "completed": [] if completed is None else completed,
            "outcome": outcome,
        }
        record.update(overrides)
        return record

    def test_every_interruption_boundary_is_fail_closed(self):
        stages = list(STAGES["replace"])
        for count in range(len(stages)):
            with self.subTest(count=count):
                result = assess_checkpoint(self.operation, self.checkpoint(stages[:count]))
                self.assertEqual(result["next_unverified_stage"], stages[count])
                self.assertFalse(result["safe_to_resume"])
                self.assertFalse(result["safe_to_rollback"])
                self.assertFalse(result["safe_to_delete"])
                self.assertTrue(result["requires_independent_ownership_proof"])

    def test_complete_history_is_not_authority(self):
        stages = list(STAGES["replace"])
        result = assess_checkpoint(self.operation, self.checkpoint(stages, "recorded_complete"))
        self.assertIsNone(result["next_unverified_stage"])
        self.assertFalse(result["safe_to_resume"])

    def test_invalid_history_rejected(self):
        stages = list(STAGES["replace"])
        invalid = (
            self.checkpoint([stages[1]]),
            self.checkpoint([stages[0], stages[0]]),
            self.checkpoint(["unrecognised"]),
            self.checkpoint(stages, "failed"),
            self.checkpoint([], "recorded_complete"),
            self.checkpoint(version=True),
            self.checkpoint(profile="other"),
            self.checkpoint(action="create"),
            self.checkpoint(completed="not a list"),
            {**self.checkpoint(), "extra": True},
        )
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(RecoveryContractError):
                assess_checkpoint(self.operation, record)

    def test_all_actions_and_immutability(self):
        for action, stages in STAGES.items():
            with self.subTest(action=action):
                operation = {"profile": "primary", "action": action}
                record = self.checkpoint(action=action, completed=list(stages), outcome="recorded_complete")
                before = repr(record)
                self.assertEqual(assess_checkpoint(operation, record), assess_checkpoint(operation, record))
                self.assertEqual(repr(record), before)


if __name__ == "__main__":
    unittest.main()
