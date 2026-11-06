"""Production route readback must refuse ambiguous or unprotected defaults."""

import json
from types import SimpleNamespace

import pytest

from nord_tools_internal.nordvpn_underlay_install import UnderlayError, verify_tunnel_route_readback


NS = "nt-1a2b3c4d5e6f7a8b"
WG = "ntwg0123abcd"
UL = "ntul0123ab"


def runner_with(ipv4, ipv6):
    def run(argv, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(ipv4 if "-4" in argv else ipv6).encode())

    return run


def check(ipv4, ipv6, endpoint="198.51.100.10"):
    verify_tunnel_route_readback(NS, WG, UL, endpoint, runner=runner_with(ipv4, ipv6))


V4 = [{"dst": "default", "dev": WG}, {"dst": "198.51.100.10", "dev": UL, "gateway": "10.214.0.1"}]
V6 = [{"dst": "default", "dev": WG}]


def test_valid_dual_stack_defaults_and_endpoint():
    check(V4, V6)


@pytest.mark.parametrize(
    "v4,v6",
    [
        ([], V6),
        (V4, []),
        ([{"dst": "default", "dev": UL}, V4[1]], V6),
        (V4, [{"dst": "default", "dev": UL}]),
        (V4 + [{"dst": "default", "dev": UL}], V6),
        ([V4[0]], V6),
        ([V4[0], {"dst": "198.51.100.10", "dev": WG}], V6),
        (V4, [{"dst": "default", "dev": WG, "gateway": "fd00::1"}]),
    ],
)
def test_unprotected_or_ambiguous_routes_refused(v4, v6):
    with pytest.raises(UnderlayError):
        check(v4, v6)


def test_malformed_readback_refused():
    with pytest.raises(UnderlayError):
        check({"not": "routes"}, V6)
