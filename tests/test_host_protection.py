"""Read-only host default safety assessment regression coverage."""

import copy

import pytest

from nord_tools_internal.nordvpn_host_protection import assess_host_default_protection
from nord_tools_internal.nordvpn_registry import RegistryError


BASE = {
    "endpoint_address": "198.51.100.2",
    "endpoint_port": 51820,
    "tunnel_address": "10.7.0.2/32",
    "peer_allowed_ips": ["0.0.0.0/0", "::/0"],
    "dns_servers": ["10.7.0.1", "2001:db8::53"],
}


def test_assessment_never_authorises_host_mutation():
    plan = assess_host_default_protection(BASE)
    assert plan["network_changes_applied"] is False
    assert plan["mutation_authorised"] is False
    assert plan["executable"] is False
    assert len(plan["required_guards"]) == 6


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("endpoint_address", "vpn.example"),
        ("endpoint_address", "127.0.0.1"),
        ("endpoint_address", "fe80::1"),
        ("endpoint_port", True),
        ("endpoint_port", 65536),
        ("tunnel_address", "not-an-address"),
        ("peer_allowed_ips", ["0.0.0.0/0"]),
        ("peer_allowed_ips", ["0.0.0.0/0", "::/0", "10.0.0.0/8"]),
        ("peer_allowed_ips", ["::/0", "::/0"]),
        ("dns_servers", []),
        ("dns_servers", ["dns.example"]),
        ("dns_servers", ["127.0.0.1"]),
        ("dns_servers", ["10.7.0.1", "10.7.0.1"]),
    ],
)
def test_unsafe_host_protection_plans_are_rejected(field, value):
    plan = copy.deepcopy(BASE)
    plan[field] = value
    with pytest.raises(RegistryError):
        assess_host_default_protection(plan)


def test_missing_dns_is_not_silently_accepted():
    plan = copy.deepcopy(BASE)
    del plan["dns_servers"]
    with pytest.raises(RegistryError):
        assess_host_default_protection(plan)
