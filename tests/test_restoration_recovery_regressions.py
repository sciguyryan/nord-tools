"""Regression checks for privileged Part 7 probe preconditions and diagnostics."""

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from nord_tools_internal.nordvpn_underlay_install import UnderlayError, _run
from tools.probe_recovery import interrupted_evidence


def test_killed_child_before_first_durable_write_is_not_uncertain(tmp_path: Path):
    assert interrupted_evidence(tmp_path) == []


def test_intent_only_interruption_remains_visible(tmp_path: Path):
    (tmp_path / "operation-intents.json").write_text(
        json.dumps({"operations": [{"operation_id": "a", "outcome": "pending"}]}), encoding="utf-8"
    )
    assert interrupted_evidence(tmp_path) == ["operation a: pending"]


def test_underlay_failure_identifies_step_without_echoing_command_output():
    argv = ["ip", "link", "add", "private-interface", "type", "veth"]
    result = subprocess.CompletedProcess(argv, 2, b"", b"private diagnostics")
    with (
        mock.patch("subprocess.run", return_value=result),
        pytest.raises(UnderlayError, match="underlay step.*link.*add.*exit 2") as error,
    ):
        _run(argv)
    assert "private diagnostics" not in str(error.value)


def test_restoration_fixture_uses_valid_pinned_server():
    source = (Path(__file__).resolve().parents[1] / "tools" / "probe_restore_startup.py").read_text()
    assert '"server": "uk715"' in source
    assert '"server": "probe"' not in source


def test_restoration_probe_uses_independent_retirement_descriptor():
    source = (Path(__file__).resolve().parents[1] / "tools" / "probe_restore_startup.py").read_text()
    assert "os.dup(descriptor.fileno())" in source
    assert "owned.release()" in source


def test_part7_gate_exempts_only_identity_bound_kernel_underlay_route():
    from tools.probe_startup_restoration_lifecycle import ProbeError, _assert_no_host_drift

    underlay = {
        "dst": "10.214.0.0/30",
        "dev": "nthlverified",
        "prefsrc": "10.214.0.1",
        "protocol": "kernel",
        "scope": "link",
    }
    baseline = {"ipv4_routes": b'[{"dst":"default","gateway":"192.0.2.1"}]', "resolver": "unchanged"}
    after = {
        "ipv4_routes": json.dumps([{"dst": "default", "gateway": "192.0.2.1"}, underlay]).encode(),
        "resolver": "unchanged",
    }
    allowed = {("nthlverified", "10.214.0.0/30", "10.214.0.1"): True}
    _assert_no_host_drift("before", "after", baseline, after, allowed)
    _assert_no_host_drift("before", "after", after, baseline, allowed)
    with pytest.raises(ProbeError, match="ipv4_routes"):
        _assert_no_host_drift("before", "after", baseline, after, {})
    for field, replacement in (
        ("protocol", "static"),
        ("scope", "global"),
        ("gateway", "192.0.2.9"),
        ("dst", "0.0.0.0/0"),
    ):
        altered = {**underlay, field: replacement}
        changed = {**after, "ipv4_routes": json.dumps([{"dst": "default", "gateway": "192.0.2.1"}, altered]).encode()}
        with pytest.raises(ProbeError, match="ipv4_routes"):
            _assert_no_host_drift("before", "after", baseline, changed, allowed)
    with pytest.raises(ProbeError, match="resolver"):
        _assert_no_host_drift("before", "after", baseline, {**after, "resolver": "changed"}, allowed)


def test_part7_nftables_gate_ignores_only_counter_readings():
    from tools.probe_startup_restoration_lifecycle import ProbeError, _assert_no_host_drift

    fixture = {
        "nftables": [
            {"table": {"family": "ip", "name": "filter", "handle": 1}},
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "policy": "drop"}},
            {
                "rule": {
                    "family": "ip",
                    "table": "filter",
                    "chain": "INPUT",
                    "handle": 7,
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
                        {"counter": {"packets": 1, "bytes": 64}},
                        {"accept": None},
                    ],
                }
            },
        ]
    }
    baseline = {"nftables": json.dumps(fixture).encode()}
    changed = json.loads(json.dumps(fixture))
    changed["nftables"][2]["rule"]["expr"][1]["counter"].update(packets=900, bytes=65535)
    _assert_no_host_drift("persistence", "recovery", baseline, {"nftables": json.dumps(changed).encode()}, {})

    import copy

    for mutate in (
        lambda d: d["nftables"][1]["chain"].update(policy="accept"),
        lambda d: d["nftables"][2]["rule"]["expr"][0]["match"].update(right="eth0"),
        lambda d: d["nftables"][2]["rule"]["expr"][2].update(drop=None),
        lambda d: d["nftables"][2]["rule"]["expr"].reverse(),
        lambda d: d["nftables"][2]["rule"]["expr"][1]["counter"].update(extra="changed"),
        lambda d: d["nftables"].append({"table": {"family": "ip6", "name": "filter"}}),
    ):
        altered = copy.deepcopy(changed)
        mutate(altered)
        with pytest.raises(ProbeError, match="nftables"):
            _assert_no_host_drift("persistence", "recovery", baseline, {"nftables": json.dumps(altered).encode()}, {})


@pytest.mark.parametrize("invalid", [b"{}", b"[]", b"not-json"])
def test_part7_nftables_gate_rejects_invalid_snapshot(invalid: bytes):
    from tools.probe_startup_restoration_lifecycle import _assert_no_host_drift

    valid = {"nftables": b'{"nftables":[]}'}
    with pytest.raises((ValueError, RuntimeError)):
        _assert_no_host_drift("before", "after", valid, {"nftables": invalid}, {})


def test_part7_recovery_creates_missing_generation_before_checkpoint(tmp_path: Path):
    from tools.probe_startup_restoration_lifecycle import stage_recovery

    policy = {
        "version": 1,
        "defaults": {"vpn": "primary"},
        "vpn_profiles": {"primary": {"sharing": "shared"}, "other": {"sharing": "shared"}},
        "applications": {"app-b": {"vpn": "primary"}},
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    calls = []

    class FakeMatrix:
        policy = path

        def cleanup_args(self, execute=False):
            assert execute
            return ["cleanup", "--execute"]

        def recovery_args(self, execute=False):
            assert execute
            return ["recovery", "--execute"]

        def call(self, *args):
            calls.append(args[0])
            assert list(json.loads(path.read_text())["vpn_profiles"]) == ["primary"]
            return {}

        def reconcile(self):
            calls.append("reconcile")
            return {"reconciled": True}

        def interrupt_at_durable_intent(self):
            calls.append("checkpoint")
            assert json.loads(path.read_text()) == policy

        def restore(self):
            calls.append("restore")
            return {}

    stage_recovery(FakeMatrix())
    assert calls == ["cleanup", "reconcile", "checkpoint", "restore", "reconcile"]
    assert json.loads(path.read_text()) == policy


def test_part7_cleanup_namespace_scope_ignores_retired_history(tmp_path: Path):
    from tools.probe_startup_restoration_lifecycle import _active_namespaces_by_profile

    resources = [
        {"allocation_id": "old", "kind": "namespace", "identifier": "nt-old", "profile": "other"},
        {"allocation_id": "primary", "kind": "namespace", "identifier": "nt-primary", "profile": "primary"},
        {"allocation_id": "other", "kind": "namespace", "identifier": "nt-other", "profile": "other"},
        {"allocation_id": "interface", "kind": "interface", "identifier": "nthl-primary", "profile": "primary"},
    ]
    journal = {
        "allocations": {"resources": resources},
        "events": [
            {"allocation_id": "old", "state": "active"},
            {"allocation_id": "old", "state": "retired"},
            {"allocation_id": "primary", "state": "active"},
            {"allocation_id": "other", "state": "active"},
            {"allocation_id": "interface", "state": "active"},
        ],
    }
    path = tmp_path / "lifecycle.json"
    path.write_text(json.dumps(journal))

    assert _active_namespaces_by_profile(path) == {"primary": "nt-primary", "other": "nt-other"}


def test_part7_cleanup_reduces_startup_provider_data(tmp_path: Path):
    from tools.probe_startup_restoration_lifecycle import _retain_startup_profiles

    path = tmp_path / "startup.json"
    path.write_text(
        json.dumps(
            {
                "tunnels": {"primary": {"endpoint": "one"}, "other": {"endpoint": "two"}},
                "credentials": {"primary": "/key/one", "other": "/key/two"},
                "journal": "/state/lifecycle.json",
            }
        )
    )

    _retain_startup_profiles(path, {"primary"})

    assert json.loads(path.read_text()) == {
        "tunnels": {"primary": {"endpoint": "one"}},
        "credentials": {"primary": "/key/one"},
        "journal": "/state/lifecycle.json",
    }


def test_matrix_policy_writer_supports_final_teardown_profile(tmp_path: Path):
    from tools.probe_startup_restoration_lifecycle import Matrix

    matrix = object.__new__(Matrix)
    matrix.policy = tmp_path / "desired-policy.json"
    matrix.write_policy(
        {"teardown": {"selection": {"mode": "pinned", "server": "uk715"}, "sharing": "shared"}},
        default="teardown",
    )

    policy = json.loads(matrix.policy.read_text())
    assert policy["defaults"] == {"vpn": "teardown"}
    assert set(policy["vpn_profiles"]) == {"teardown"}
