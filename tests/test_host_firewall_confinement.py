"""Regression checks for the host-default nftables confinement contract."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_host_executor import HostProtectionError
from nord_tools_internal.nordvpn_host_linux import (
    _expected_nft_expressions,
    _install_barrier,
    _install_endpoint,
    _nft_markers,
    _remove_endpoint,
)
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from test_host_executor import PLAN


def test_underlay_endpoint_requires_wireguard_mark():
    plan = HostProtectionPlan.from_mapping(PLAN)
    expressions = _expected_nft_expressions(plan)[f"nt:{plan.generation}:endpoint"]
    assert {"match": {"op": "==", "left": {"meta": {"key": "mark"}}, "right": plan.fwmark}} in expressions
    with patch("nord_tools_internal.nordvpn_host_linux._run") as run:
        _install_endpoint(plan)
    assert f"meta mark {plan.fwmark}" in run.call_args.kwargs["input_text"]


def test_input_established_is_tunnel_scoped_and_handshake_is_endpoint_scoped():
    plan = HostProtectionPlan.from_mapping(PLAN)
    expressions = _expected_nft_expressions(plan)
    established = expressions[f"nt:{plan.generation}:barrier:input-established"]
    assert established[0]["match"]["right"] == plan.interface
    inbound = expressions[f"nt:{plan.generation}:barrier:input-endpoint"]
    assert inbound[0]["match"]["right"] == plan.egress_interface
    assert any(item.get("match", {}).get("right") == plan.endpoint_port for item in inbound)


def test_barrier_installs_scoped_inbound_rules():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
        patch("nord_tools_internal.nordvpn_host_linux._resource_state", return_value="present"),
    ):
        _install_barrier(plan)
    rules = run.call_args_list[0].kwargs["input_text"]
    assert f'iifname "{plan.interface}" ct state established,related accept' in rules
    assert f'iifname "{plan.egress_interface}" ip saddr {plan.endpoint_address}' in rules
    assert f"udp sport {plan.endpoint_port}" in rules
    assert "  ct state established,related accept" not in rules


def test_endpoint_retirement_refuses_ambiguous_firewall():
    plan = HostProtectionPlan.from_mapping(PLAN)
    with (
        patch("nord_tools_internal.nordvpn_host_linux._nft_markers", return_value=(set(), True)),
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
        pytest.raises(HostProtectionError, match="structure is absent or ambiguous"),
    ):
        _remove_endpoint(plan, {})
    run.assert_not_called()


def test_duplicate_rule_markers_are_ambiguous():
    plan = HostProtectionPlan.from_mapping(PLAN)
    expressions = _expected_nft_expressions(plan)
    comment = f"nt:{plan.generation}:endpoint"
    rule = {
        "rule": {
            "comment": comment,
            "family": "inet",
            "table": plan.firewall_table,
            "chain": "output",
            "expr": expressions[comment],
        }
    }
    chains = [
        {
            "chain": {
                "name": name,
                "family": "inet",
                "table": plan.firewall_table,
                "type": "filter",
                "hook": name,
                "prio": plan.firewall_priority,
                "policy": "drop",
            }
        }
        for name in ("input", "output", "forward")
    ]
    with patch("nord_tools_internal.nordvpn_host_linux._nft", return_value={"nftables": [*chains, rule, rule]}):
        markers, ambiguous = _nft_markers(plan)
    assert comment in markers
    assert ambiguous
