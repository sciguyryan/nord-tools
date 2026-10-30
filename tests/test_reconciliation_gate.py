"""Adversarial tests for the offline reconciliation decision gate."""

import unittest

from nord_tools_internal.nordvpn_reconciliation_gate import ReconciliationGateError, assess_reconciliation


POLICY = {
    "version": 1,
    "defaults": {"vpn": "main"},
    "vpn_profiles": {"main": {"selection": {"mode": "country", "country": "GB"}}},
    "applications": {},
}


def evidence(**profiles):
    return {"version": 1, "profiles": profiles}


def proof(ownership="independently_observed", observation="current"):
    return {"ownership": ownership, "observation": observation}


class GateTests(unittest.TestCase):
    def assess(self, records=None, claims=None):
        return assess_reconciliation(POLICY, {"version": 1, "profiles": records or {}}, claims or evidence())

    def test_missing_evidence_blocks_creation(self):
        result = self.assess()
        self.assertTrue(result["blocked"])
        self.assertEqual(result["decisions"][0]["status"], "blocked")
        self.assertFalse(result["safe_to_execute"])

    def test_independent_observation_still_does_not_authorise(self):
        result = self.assess(claims=evidence(main=proof()))
        self.assertEqual(result["decisions"][0]["status"], "requires_privileged_reverification")
        self.assertFalse(result["safe_to_execute"])

    def test_stale_and_conflicting_evidence_block(self):
        for claim in (
            proof(observation="stale"),
            proof(ownership="conflicting"),
            proof(ownership="unverified"),
            proof(observation="missing"),
        ):
            with self.subTest(claim=claim):
                self.assertTrue(self.assess(claims=evidence(main=claim))["blocked"])

    def test_invalid_and_unexpected_evidence_rejected(self):
        for claim in (
            None,
            [],
            {"version": True, "profiles": {}},
            evidence(other=proof()),
            evidence(main={"ownership": "yes", "observation": "current"}),
            evidence(main={"ownership": "independently_observed", "observation": "current", "extra": 1}),
        ):
            with self.subTest(claim=claim), self.assertRaises(ReconciliationGateError):
                assess_reconciliation(POLICY, {"version": 1, "profiles": {}}, claim)

    def test_repeatable_and_does_not_mutate(self):
        claims = evidence(main=proof())
        before = repr(claims)
        self.assertEqual(self.assess(claims=claims), self.assess(claims=claims))
        self.assertEqual(repr(claims), before)


if __name__ == "__main__":
    unittest.main()
