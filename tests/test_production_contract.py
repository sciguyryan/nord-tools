"""Production provisioning contract refuses incomplete or conflicting offline claims."""

import base64
from copy import deepcopy

import pytest

from nord_tools_internal.nordvpn_production_contract import validate_provisioning_contract
from nord_tools_internal.nordvpn_registry import RegistryError
from nord_tools_internal.nordvpn_wireguard_provision import TunnelSpecification


def fixture():
    policy = {
        "version": 1,
        "defaults": {"vpn": "primary"},
        "vpn_profiles": {
            "primary": {"selection": {"mode": "pinned", "server": "uk1234.nordvpn.com"}, "sharing": "shared"},
        },
        "applications": {},
    }
    spec = TunnelSpecification(
        namespace="nt-abcdef12",
        interface="ntwgabcdef",
        peer_public_key=base64.b64encode(bytes(range(32))).decode(),
        endpoint_address="198.51.100.1",
        endpoint_port=51820,
        tunnel_address="10.0.0.2/32",
        peer_allowed_ips=("0.0.0.0/0",),
    )
    allocations = {
        "version": 2,
        "resources": [
            {
                "kind": kind,
                "identifier": identifier,
                "profile": "primary",
                "owner": "nord-tools",
                "allocation_id": token * 32,
            }
            for kind, identifier, token in (("namespace", spec.namespace, "a"), ("interface", spec.interface, "b"))
        ],
    }
    return policy, {"primary": spec}, allocations


def test_contract_is_read_only_and_credential_free():
    result = validate_provisioning_contract(*fixture())
    assert result["default_profile"] == "primary"
    assert result["profiles"]["primary"]["tunnel"]["namespace"] == "nt-abcdef12"
    assert result["ownership_verified"] is False
    assert result["mutation_authorised"] is False
    assert result["network_changes_applied"] is False
    assert "private_key_value" not in repr(result)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "extra",
        "wrong_namespace",
        "wrong_interface",
        "missing_allocation",
        "duplicate_kind",
        "unknown_profile",
        "reused_token",
        "invalid_plan",
    ],
)
def test_rejects_ambiguous_claims(change):
    policy, tunnels, allocations = fixture()
    allocations = deepcopy(allocations)
    if change == "missing":
        tunnels.clear()
    elif change == "extra":
        tunnels["other"] = tunnels["primary"]
    elif change == "wrong_namespace":
        allocations["resources"][0]["identifier"] = "nt-deadbeef"
    elif change == "wrong_interface":
        allocations["resources"][1]["identifier"] = "ntwgdeadbeef"
    elif change == "missing_allocation":
        allocations["resources"].pop()
    elif change == "duplicate_kind":
        allocations["resources"][1]["kind"] = "namespace"
        allocations["resources"][1]["identifier"] = "nt-deadbeef"
    elif change == "unknown_profile":
        allocations["resources"][0]["profile"] = "other"
    elif change == "reused_token":
        allocations["resources"][1]["allocation_id"] = "a" * 32
    elif change == "invalid_plan":
        tunnels["primary"] = {"namespace": "nt-abcdef12"}
    with pytest.raises(RegistryError):
        validate_provisioning_contract(policy, tunnels, allocations)
