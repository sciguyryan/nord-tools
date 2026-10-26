"""Compile VPN profile intent into an inspectable, non-executable topology.

This module does not create namespaces, routes, firewall rules or tunnels. It
records the isolation boundaries that a future privileged manager must enforce.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from nordvpn_profiles import ProfileError, validate_policy


class TopologyError(ValueError):
    """The requested topology is ambiguous or cannot be represented."""


def compile_topology(policy):
    """Describe the host and override domains without assigning live endpoints.

    A profile is a connection-sharing boundary. An isolated profile is still
    one domain for all applications assigned to that named profile. Separate
    isolated connections require separate named profiles.
    """
    checked = validate_policy(policy)
    default = checked["defaults"]["vpn"]
    domains = []
    for name, profile in sorted(checked["vpn_profiles"].items()):
        host = name == default
        domains.append(
            {
                "profile": name,
                "kind": "host" if host else "namespace",
                "connection": "persistent" if host else "on_demand",
                "selection": profile["selection"],
                "sharing": profile["sharing"],
                "requirements": {
                    "fail_closed": True,
                    "dns_confined": True,
                    "ipv4_confined": True,
                    "ipv6_confined": True,
                    "underlay_only_for_tunnel_transport": True,
                },
                "applications": sorted(
                    app_name for app_name, app in checked["applications"].items() if app["vpn"] == name
                ),
            }
        )
    return {
        "schema_version": 1,
        "status": "design_only",
        "default_profile": default,
        "domains": domains,
        "unlisted_applications": {"profile": default, "kind": "host"},
        "default_optimisation_scope": [default],
        "runtime_enforcement": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect proposed VPN routing domains (no network changes)")
    parser.add_argument("--policy", required=True, type=Path, help="Version 1 VPN policy JSON")
    args = parser.parse_args(argv)
    try:
        with args.policy.open(encoding="utf-8") as stream:
            policy = json.load(stream)
        result = compile_topology(policy)
    except (OSError, json.JSONDecodeError, ProfileError, TopologyError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
