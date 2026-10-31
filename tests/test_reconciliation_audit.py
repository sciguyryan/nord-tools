"""Adversarial composition tests for the non-authorising Part 6 audit."""

import copy

import pytest

from nord_tools_internal.nordvpn_reconciliation_audit import (
    ReconciliationAuditError,
    audit_reconciliation_contracts,
)


def reports():
    gate = {
        "schema_version": 1,
        "mode": "offline_reconciliation_gate",
        "network_changes_applied": False,
        "safe_to_execute": False,
        "decisions": [{"profile": "alpha"}, {"profile": "beta"}],
    }
    drift = {
        "schema_version": 1,
        "mode": "offline_drift_assessment",
        "network_changes_applied": False,
        "safe_to_execute": False,
        "decisions": [
            {"profile": "alpha", "safe_to_mutate": False, "safe_to_delete": False},
            {"profile": "beta", "safe_to_mutate": False, "safe_to_delete": False},
        ],
    }
    return gate, drift


def test_consistent_reports_are_still_non_authorising():
    gate, drift = reports()
    before = copy.deepcopy((gate, drift))
    result = audit_reconciliation_contracts(gate=gate, drift=drift)
    assert result["consistent_scope"] is True
    assert result["findings"] == []
    assert all(
        result[key] is False
        for key in (
            "safe_to_execute",
            "safe_to_resume",
            "safe_to_rollback",
            "safe_to_delete",
            "network_changes_applied",
        )
    )
    assert (gate, drift) == before


def test_missing_profile_is_reported_deterministically():
    gate, drift = reports()
    drift["decisions"].pop()
    result = audit_reconciliation_contracts(gate=gate, drift=drift)
    assert result["findings"] == [{"profile": "beta", "issue": "missing_from_drift"}]


def test_optional_recovery_outside_scope_is_reported():
    gate, drift = reports()
    recovery = {
        "schema_version": 1,
        "mode": "offline_recovery_assessment",
        "network_changes_applied": False,
        "profile": "gamma",
        "safe_to_resume": False,
        "safe_to_rollback": False,
        "safe_to_delete": False,
    }
    result = audit_reconciliation_contracts(gate=gate, drift=drift, recovery=recovery)
    assert result["findings"] == [{"profile": "gamma", "issue": "recovery_outside_common_scope"}]


@pytest.mark.parametrize(
    "change",
    [
        lambda g, d: g.update(safe_to_execute=True),
        lambda g, d: d.update(network_changes_applied=True),
        lambda g, d: d["decisions"].append(copy.deepcopy(d["decisions"][0])),
        lambda g, d: d["decisions"][0].update(safe_to_delete=True),
        lambda g, d: g.update(schema_version=True),
    ],
)
def test_reject_malformed_or_authorising_reports(change):
    gate, drift = reports()
    change(gate, drift)
    with pytest.raises(ReconciliationAuditError):
        audit_reconciliation_contracts(gate=gate, drift=drift)
