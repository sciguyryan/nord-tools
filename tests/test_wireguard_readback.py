"""Strict semantic WireGuard allowed-IP readback tests."""

import pytest

from nord_tools_internal.nordvpn_wireguard_readback import allowed_ips_match


@pytest.mark.parametrize(
    "observed",
    [
        "peer\t0.0.0.0/0, ::/0\n",
        "peer\t::/0 0.0.0.0/0\n",
        "peer\t0.0.0.0/0,::/0\n",
    ],
)
def test_equivalent_allowed_ips(observed):
    assert allowed_ips_match(observed, "peer", ("0.0.0.0/0", "::/0"))


@pytest.mark.parametrize(
    "observed",
    [
        "peer\t0.0.0.0/0\n",
        "peer\t0.0.0.0/0 ::/0 10.0.0.0/8\n",
        "peer\t0.0.0.0/0 ::/0 ::/0\n",
        "other\t0.0.0.0/0 ::/0\n",
        "peer\t0.0.0.0/0 ::/0\nother\t10.0.0.0/8\n",
        "peer\t0.0.0.0/0,\n",
        "peer\t0.0.0.0/0 not-a-network\n",
        "peer\t0.0.0.1/0 ::/0\n",
        "peer 0.0.0.0/0 ::/0\n",
        "",
    ],
)
def test_mismatched_allowed_ips(observed):
    assert not allowed_ips_match(observed, "peer", ("0.0.0.0/0", "::/0"))
