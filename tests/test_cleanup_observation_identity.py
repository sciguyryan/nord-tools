"""Cleanup must refuse ambiguous kernel interface observations."""

import pytest

from nord_tools_internal.nordvpn_cleanup_executor import _observed_links
from nord_tools_internal.nordvpn_provision_execution import ProvisioningUncertainError


def test_unambiguous_links_are_preserved():
    assert _observed_links(
        {
            "host_interfaces": [{"name": "h0", "index": 4}],
            "namespace_details": [{"name": "nt-abc", "interfaces": [{"name": "wg0", "index": 4}]}],
        }
    ) == {("host", "h0"): 4, ("nt-abc", "wg0"): 4}


@pytest.mark.parametrize(
    "observation",
    [
        {},
        {"host_interfaces": [], "namespace_details": None},
        {"host_interfaces": [{"name": "h0", "index": True}], "namespace_details": []},
        {"host_interfaces": [{"name": "h0", "index": 0}], "namespace_details": []},
        {"host_interfaces": [{"name": "h0", "index": 4}, {"name": "h0", "index": 5}], "namespace_details": []},
        {"host_interfaces": [{"name": "h0", "index": 4}, {"name": "h1", "index": 4}], "namespace_details": []},
        {
            "host_interfaces": [],
            "namespace_details": [{"name": "nt-a", "interfaces": []}, {"name": "nt-a", "interfaces": []}],
        },
        {
            "host_interfaces": [],
            "namespace_details": [
                {"name": "nt-a", "interfaces": [{"name": "wg0", "index": 2}, {"name": "wg1", "index": 2}]}
            ],
        },
    ],
)
def test_ambiguous_observations_refuse_retirement(observation):
    with pytest.raises(ProvisioningUncertainError):
        _observed_links(observation)
