"""Cross-contract Part 6 diagnostic audit, with no privileged execution path.

All inputs are untrusted reports. A consistent report is not ownership proof,
verification of kernel state or authority to perform a recovery operation.
"""

from __future__ import annotations

from collections.abc import Mapping


class ReconciliationAuditError(ValueError):
    """A supplied offline diagnostic report is malformed or contradictory."""


_REPORTS = {
    "gate": ("offline_reconciliation_gate", "decisions"),
    "drift": ("offline_drift_assessment", "decisions"),
    "recovery": ("offline_recovery_assessment", "profile"),
    "replacement": ("offline_staged_replacement", "profile"),
}


def _validate_report(name: str, report: object) -> Mapping:
    if not isinstance(report, Mapping):
        raise ReconciliationAuditError(f"{name} must be a report mapping")
    mode, required = _REPORTS[name]
    if (
        type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
        or report.get("mode") != mode
        or report.get("network_changes_applied") is not False
    ):
        raise ReconciliationAuditError(f"{name} is not a version 1 non-mutating report")
    if required not in report:
        raise ReconciliationAuditError(f"{name} lacks {required}")
    if name == "gate" and report.get("safe_to_execute") is not False:
        raise ReconciliationAuditError("gate must explicitly deny execution")
    if name == "drift" and report.get("safe_to_execute") is not False:
        raise ReconciliationAuditError("drift must explicitly deny execution")
    if name == "recovery" and any(
        report.get(k) is not False for k in ("safe_to_resume", "safe_to_rollback", "safe_to_delete")
    ):
        raise ReconciliationAuditError("recovery must explicitly deny privileged actions")
    if name == "replacement" and any(report.get(k) is not False for k in ("safe_to_cut_over", "safe_to_retire_old")):
        raise ReconciliationAuditError("replacement must explicitly deny privileged actions")
    return report


def _profiles(name: str, report: Mapping) -> set[str]:
    if name in ("recovery", "replacement"):
        profile = report["profile"]
        if not isinstance(profile, str) or not profile.strip():
            raise ReconciliationAuditError(f"{name} has invalid profile")
        return {profile}
    decisions = report["decisions"]
    if not isinstance(decisions, list):
        raise ReconciliationAuditError(f"{name} decisions must be a list")
    profiles = set()
    for item in decisions:
        if not isinstance(item, Mapping) or not isinstance(item.get("profile"), str) or not item["profile"].strip():
            raise ReconciliationAuditError(f"{name} has invalid decision profile")
        profile = item["profile"]
        if profile in profiles:
            raise ReconciliationAuditError(f"{name} has duplicate profile")
        profiles.add(profile)
        if name == "drift" and (item.get("safe_to_mutate") is not False or item.get("safe_to_delete") is not False):
            raise ReconciliationAuditError("drift decision must deny mutation and deletion")
    return profiles


def audit_reconciliation_contracts(
    *, gate: object, drift: object, recovery: object = None, replacement: object = None
) -> dict:
    """Compare diagnostic scope and report cross-contract mismatches without action.

    Recovery and replacement are optional single-profile reports. Their profiles
    must appear in both broad reports. Missing profiles in either broad report
    are recorded as contradictions rather than silently treated as safe.
    """
    reports = {"gate": gate, "drift": drift}
    if recovery is not None:
        reports["recovery"] = recovery
    if replacement is not None:
        reports["replacement"] = replacement
    scopes = {name: _profiles(name, _validate_report(name, value)) for name, value in reports.items()}
    gate_names, drift_names = scopes["gate"], scopes["drift"]
    findings = []
    for profile in sorted(gate_names ^ drift_names):
        findings.append(
            {"profile": profile, "issue": "missing_from_drift" if profile in gate_names else "missing_from_gate"}
        )
    for name in ("recovery", "replacement"):
        if name in scopes:
            profile = next(iter(scopes[name]))
            if profile not in gate_names or profile not in drift_names:
                findings.append({"profile": profile, "issue": f"{name}_outside_common_scope"})
    return {
        "schema_version": 1,
        "mode": "offline_reconciliation_contract_audit",
        "profiles": sorted(gate_names | drift_names),
        "findings": sorted(findings, key=lambda x: (x["profile"], x["issue"])),
        "consistent_scope": not findings,
        "requires_fresh_privileged_observation": True,
        "requires_independent_creation_time_ownership": True,
        "safe_to_execute": False,
        "safe_to_resume": False,
        "safe_to_rollback": False,
        "safe_to_delete": False,
        "network_changes_applied": False,
    }
