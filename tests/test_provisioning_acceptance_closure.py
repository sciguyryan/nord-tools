"""Guard the accepted provisioning acceptance coverage against accidental drift."""

from pathlib import Path

from tools import probe_later_recovery, probe_provisioning_integration, probe_recovery


def test_accepted_provisioning_matrix_covers_all_lifecycle_scenarios():
    expected = (
        "probe_part8_authority_acceptance.py",
        "probe_selected_profile_retirement.py",
        "probe_isolated_consumer_retirement.py",
        "probe_recovery.py",
    )
    assert tuple(filename for _, filename, _ in probe_provisioning_integration.STAGES) == expected
    for _, filename, arguments in probe_provisioning_integration.STAGES:
        assert (probe_provisioning_integration.ROOT / "tools" / filename).is_file()
        assert "--run-privileged" in arguments
    assert probe_provisioning_integration.STAGES[-1][2] == ("--after-binding", "--run-privileged")


def test_accepted_later_interruption_matrix_covers_each_kernel_boundary():
    assert probe_later_recovery.CHECKPOINTS == ("underlay", "wireguard", "routing")
    assert (probe_later_recovery.ROOT / "tools" / "probe_recovery.py").is_file()
    assert callable(probe_recovery.checkpoint_child)


def test_accepted_coverage_does_not_claim_unimplemented_network_safeguards():
    roadmap = (Path(__file__).resolve().parents[1] / "TODO.md").read_text(encoding="utf-8")
    assert "- [x] 8.2.7 Privileged provisioning integration" in roadmap
    assert "- [ ] Verify real-tunnel IPv4/IPv6 DNS packet confinement" in roadmap
    assert "- [ ] Route assigned applications through their profiles" in roadmap
