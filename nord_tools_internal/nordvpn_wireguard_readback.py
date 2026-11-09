"""Parse non-secret WireGuard peer allowed-IP observations strictly.

The `wg show ... allowed-ips` presentation is not a stable serialisation:
spacing and comma separators are presentation details, not peer policy.
"""

from __future__ import annotations

import ipaddress
import re


def allowed_ips_match(observation: str, peer_public_key: str, expected: tuple[str, ...]) -> bool:
    """Accept exactly one expected peer with exactly the expected IP networks.

    Reject malformed, duplicated or additional networks and any extra peer rows.
    Network comparisons ignore textual spelling and ordering, but not policy.
    """
    lines = observation.splitlines()
    if len(lines) != 1:
        return False
    columns = lines[0].split("\t")
    if len(columns) != 2 or columns[0] != peer_public_key:
        return False
    tokens = re.split(r"\s*,\s*|\s+", columns[1].strip())
    if not tokens or any(not token for token in tokens):
        return False
    try:
        observed = [ipaddress.ip_network(token, strict=True) for token in tokens]
        required = [ipaddress.ip_network(token, strict=True) for token in expected]
    except ValueError:
        return False
    return len(observed) == len(required) and len(set(observed)) == len(observed) and set(observed) == set(required)
