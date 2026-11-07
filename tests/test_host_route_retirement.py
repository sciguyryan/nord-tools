"""Host routing retirement must never delete unrelated kernel resources."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from nord_tools_internal.nordvpn_host_executor import HostProtectionError
from nord_tools_internal.nordvpn_host_linux import _remove_routes
from nord_tools_internal.nordvpn_host_protection import HostProtectionPlan
from test_host_executor import PLAN


def _readback(plan, completed):
    endpoint_family = 4
    rules = {}
    routes = {}
    for family in (4, 6):
        rules[family] = []
        if family == endpoint_family and completed == 0:
            rules[family].append(
                {
                    "priority": plan.endpoint_rule_priority,
                    "table": "main",
                    "src": "all",
                    "dst": plan.endpoint_address,
                }
            )
        if completed <= (1 if family == 4 else 2):
            rules[family].append(
                {
                    "priority": plan.tunnel_rule_priority,
                    "table": plan.route_table,
                    "src": "all",
                }
            )
        routes[family] = (
            [{"dst": "default", "dev": plan.interface, "protocol": "static"}]
            if completed <= (3 if family == 4 else 4)
            else []
        )
    return rules, routes


def test_route_retirement_uses_full_selectors_and_checks_each_mutation():
    plan = HostProtectionPlan.from_mapping(PLAN)
    state = {"completed": 0}
    commands = []

    def rules(family):
        return _readback(plan, state["completed"])[0][family]

    def routes(family, table):
        assert table == plan.route_table
        return _readback(plan, state["completed"])[1][family]

    def run(argv):
        commands.append(argv)
        state["completed"] += 1

    with (
        patch("nord_tools_internal.nordvpn_host_linux._rule_rows", side_effect=rules),
        patch("nord_tools_internal.nordvpn_host_linux._route_rows", side_effect=routes),
        patch("nord_tools_internal.nordvpn_host_linux._run", side_effect=run),
    ):
        assert _remove_routes(plan, {}) == {"removed_table": plan.route_table}
    assert len(commands) == 5
    assert commands[0][-4:] == ["to", f"{plan.endpoint_address}/32", "lookup", "main"]
    assert commands[1][-2:] == ["lookup", str(plan.route_table)]
    assert commands[3][4:] == ["default", "dev", plan.interface, "table", str(plan.route_table), "proto", "static"]


@pytest.mark.parametrize("kind", ["foreign-rule", "foreign-route", "duplicate-rule"])
def test_route_retirement_refuses_ambiguous_live_resources(kind):
    plan = HostProtectionPlan.from_mapping(PLAN)
    rules, routes = _readback(plan, 0)
    if kind == "foreign-rule":
        rules[4][0]["dst"] = "198.51.100.77"
    elif kind == "foreign-route":
        routes[6][0]["dev"] = "unrelated0"
    else:
        rules[4].append(dict(rules[4][0]))
    with (
        patch("nord_tools_internal.nordvpn_host_linux._rule_rows", side_effect=lambda family: rules[family]),
        patch("nord_tools_internal.nordvpn_host_linux._route_rows", side_effect=lambda family, table: routes[family]),
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
        pytest.raises(HostProtectionError, match="identity changed"),
    ):
        _remove_routes(plan, {})
    run.assert_not_called()


def test_route_retirement_stops_after_concurrent_replacement():
    plan = HostProtectionPlan.from_mapping(PLAN)
    state = {"completed": 0}

    def rules(family):
        rows = _readback(plan, state["completed"])[0][family]
        if state["completed"] == 1 and family == 4:
            rows[0]["table"] = 99999
        return rows

    def routes(family, table):
        assert table == plan.route_table
        return _readback(plan, state["completed"])[1][family]

    def run(argv):
        state["completed"] += 1

    with (
        patch("nord_tools_internal.nordvpn_host_linux._rule_rows", side_effect=rules),
        patch("nord_tools_internal.nordvpn_host_linux._route_rows", side_effect=routes),
        patch("nord_tools_internal.nordvpn_host_linux._run", side_effect=run) as run_mock,
        pytest.raises(HostProtectionError, match="identity changed"),
    ):
        _remove_routes(plan, {})
    assert run_mock.call_count == 1


def test_resolver_retirement_requires_original_link_identity():
    from nord_tools_internal.nordvpn_host_linux import _remove_resolver

    plan = HostProtectionPlan.from_mapping(PLAN)
    link = [{"name": plan.interface, "kind": "wireguard", "index": 9}]
    with (
        patch("nord_tools_internal.nordvpn_host_linux._links", return_value=link),
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
        pytest.raises(HostProtectionError, match="identity changed"),
    ):
        _remove_resolver(plan, {"ifindex": 8})
    run.assert_not_called()


def test_resolver_retirement_refuses_changed_assignment():
    from nord_tools_internal.nordvpn_host_linux import _remove_resolver

    plan = HostProtectionPlan.from_mapping(PLAN)
    link = [{"name": plan.interface, "kind": "wireguard", "index": 9}]
    with (
        patch("nord_tools_internal.nordvpn_host_linux._links", return_value=link),
        patch("nord_tools_internal.nordvpn_host_linux._resolver_state", return_value="ambiguous"),
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
        pytest.raises(HostProtectionError, match="assignment changed"),
    ):
        _remove_resolver(plan, {"ifindex": 9})
    run.assert_not_called()


def test_resolver_install_requires_verified_readback_and_records_link_identity():
    from nord_tools_internal.nordvpn_host_linux import _install_resolver

    plan = HostProtectionPlan.from_mapping(PLAN)
    link = [{"name": plan.interface, "kind": "wireguard", "index": 42}]
    with (
        patch("nord_tools_internal.nordvpn_host_linux._links", return_value=link),
        patch("nord_tools_internal.nordvpn_host_linux._resolver_state", return_value="present"),
        patch("nord_tools_internal.nordvpn_host_linux._run") as run,
    ):
        evidence = _install_resolver(plan)
    assert evidence["ifindex"] == 42
    assert run.call_count == 3


def test_resolver_install_rejects_unverifiable_readback():
    from nord_tools_internal.nordvpn_host_linux import _install_resolver

    plan = HostProtectionPlan.from_mapping(PLAN)
    link = [{"name": plan.interface, "kind": "wireguard", "index": 42}]
    with (
        patch("nord_tools_internal.nordvpn_host_linux._links", return_value=link),
        patch("nord_tools_internal.nordvpn_host_linux._resolver_state", return_value="ambiguous"),
        patch("nord_tools_internal.nordvpn_host_linux._run"),
        pytest.raises(HostProtectionError, match="could not be verified"),
    ):
        _install_resolver(plan)
